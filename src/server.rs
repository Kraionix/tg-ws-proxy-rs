//! Process-level proxy server: bind, banner, accept loop.
//!
//! Extracted from the binary so embedders (the Android app, tests) can start
//! and stop the same accept loop the CLI runs, without spawning a process or
//! duplicating the fallback / pool / FD-budget setup.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::check;
use crate::config::{Config, UpstreamTier};
use crate::default_domains;
use crate::limits::{auto_max_connections, open_fds, soft_nofile_limit};
use crate::log::schema::{Category, DcIp, ErrorCode, Level};
use crate::log::{self, LogHandle};
use crate::log_event;
use crate::pool::WsPool;
use crate::proxy;
use crate::runtime::Runtime;

/// How often the descriptor budget is recorded, when the sink is on.
const FD_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(60);

/// Past this, `--log-retention` stops being a retention policy and becomes a
/// wish — the sweep is by file name and simply finds nothing to delete. Warned
/// about at startup rather than refused.
const RETENTION_WARN_DAYS: u32 = 3650;

/// Why [`run`] / [`run_with_listen`] stopped before serving, or failed to start.
#[derive(Debug)]
pub enum RunError {
    /// `--outbound-proxy` / `NO_PROXY` could not be parsed.
    InvalidOutbound(String),
    /// A pinned upstream tier (`--pinned-upstream` / `--pinned-media-upstream`)
    /// names a tier nothing configures.
    InvalidPin(String),
    /// `{host}:{port}` is not a valid socket address.
    InvalidListenAddress(String),
    /// `--log-dir` is on a filesystem that cannot carry a segment.
    InvalidLogFs(String),
    /// `--log-dir` could not be created, opened, or claimed for writing.
    InvalidLogDir(String),
    /// The listen socket could not be bound.
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    /// `--check` ran and at least one probe failed.
    CheckFailed,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOutbound(e) => write!(f, "invalid outbound proxy config: {e}"),
            Self::InvalidPin(e) => write!(f, "invalid pinned upstream config: {e}"),
            Self::InvalidListenAddress(addr) => write!(f, "invalid listen address: {addr}"),
            Self::InvalidLogFs(reason) => f.write_str(reason),
            Self::InvalidLogDir(reason) => write!(f, "invalid --log-dir: {reason}"),
            Self::Bind { addr, source } => write!(f, "cannot bind {addr}: {source}"),
            Self::CheckFailed => write!(f, "connectivity check failed"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Bound address and `tg://` link, handed to [`run_with_listen`] once the
/// listener is up and the startup banner has been logged.
#[derive(Clone, Debug)]
pub struct ListenInfo {
    pub addr: SocketAddr,
    pub tg_link: String,
}

/// Install the rustls `ring` provider if nothing else has yet.
///
/// Safe to call more than once — later calls are ignored, including when a
/// test harness already installed a provider.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Run the proxy until `shutdown` completes.
///
/// Same path as the binary: fetch `--default-domains`, honour `--check`, bind,
/// print the banner, warm the pool, then accept clients.  Completing `shutdown`
/// breaks the accept loop and returns; in-flight connections are dropped with
/// the Tokio runtime that called this.
pub async fn run(
    config: Config,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), RunError> {
    run_with_listen(config, shutdown, |_| {}).await
}

/// Awaits a check's verdict when one is running, and never completes otherwise,
/// so the accept loop can keep a single `select!` shape whether or not
/// `--check-listener` asked for one.
async fn check_verdict(rx: &mut Option<tokio::sync::oneshot::Receiver<bool>>) -> bool {
    match rx {
        Some(rx) => rx.await.unwrap_or(false),
        None => std::future::pending().await,
    }
}

/// [`run`] plus a one-shot callback after the listen socket is bound.
///
/// `on_listen` is how an embedder learns the real port (when `--port 0`) and
/// the `tg://proxy` link without scraping log lines.
///
/// The structured sink is started here rather than in the binary's `main`
/// because this is the function that owns `config`: a handle created outside
/// would have to be threaded through `run`, every embedder and the Android shim
/// to be usable inside — or worse, the shim would run without logging at all.
/// Starting it here also makes "a clean stop loses nothing" a property of the
/// return path: every way out of [`serve`] comes back through the shutdown,
/// including the early returns for `--check` and a failed bind.
pub async fn run_with_listen(
    config: Config,
    shutdown: impl Future<Output = ()> + Send,
    on_listen: impl FnOnce(ListenInfo) + Send,
) -> Result<(), RunError> {
    let log = match &config.log_dir {
        Some(dir) => Some(
            log::init(dir, config.log_settings(), config.log_options())
                .map_err(|error| log_start_error(error, dir))?,
        ),
        None => None,
    };

    let result = serve(config, shutdown, on_listen, log.as_ref()).await;

    if let Some(handle) = &log {
        handle.shutdown().await;
    }

    result
}

/// `--log-dir` is the one startup setting whose failure has no fallback: a
/// directory this process cannot write to is a configuration mistake the
/// operator has to see, not a reason to run on quietly without logs.
fn log_start_error(error: log::LogError, dir: &Path) -> RunError {
    match error {
        log::LogError::FsUnsupported(reason) => RunError::InvalidLogFs(reason),
        // The io error alone ("Permission denied") does not say which directory
        // it was about; the operator named one, so quote it back.
        log::LogError::Io(error) => RunError::InvalidLogDir(format!("{}: {error}", dir.display())),
        error => RunError::InvalidLogDir(error.to_string()),
    }
}

/// The upstream ladder this configuration can route through, in the order the
/// fallback tries it: `ws` and `tcp` are always there, the Cloudflare and
/// upstream-proxy rungs only when something configures them.
///
/// Names come from [`UpstreamTier`] rather than being spelled out again, so a
/// record says exactly what the flag help does.
fn configured_tiers(config: &Config, cf_worker_domains: &[String]) -> Vec<String> {
    let mut tiers = vec![UpstreamTier::Ws];
    if !cf_worker_domains.is_empty() {
        tiers.push(UpstreamTier::Cfworker);
    }
    if !config.cf_domains.is_empty() {
        tiers.push(UpstreamTier::Cfproxy);
    }
    if !config.mtproto_proxies.is_empty() {
        tiers.push(UpstreamTier::Mtproto);
    }
    tiers.push(UpstreamTier::Tcp);
    tiers.iter().map(ToString::to_string).collect()
}

/// The server itself: everything [`run_with_listen`] does once the sink is up.
async fn serve(
    mut config: Config,
    shutdown: impl Future<Output = ()> + Send,
    on_listen: impl FnOnce(ListenInfo) + Send,
    log: Option<&Arc<LogHandle>>,
) -> Result<(), RunError> {
    install_crypto_provider();

    let outbound = config
        .outbound_connector()
        .map_err(RunError::InvalidOutbound)?;
    let runtime = Arc::new(
        Runtime::new(outbound)
            .with_cf_ips(config.cf_ips.clone())
            .with_cf_fail_cooldown(Duration::from_secs(config.cf_fail_cooldown))
            .with_fronting(config.fronting_domain.clone()),
    );

    tokio::pin!(shutdown);

    // ── Default CF domain list (--default-domains) ────────────────────────
    // Fetch the obfuscated domain list from GitHub, deobfuscate it, and
    // append the resulting domains to any that were supplied with --cf-domain.
    // Done once here so both --check mode and the normal server path share
    // the same fetched list.  The fetch selects on `shutdown` so an embedder
    // can cancel a slow fetch instead of blocking a stop for the full timeout.
    if config.default_domains {
        info!("Fetching default CF proxy domain list from GitHub…");
        let fetched = tokio::select! {
            _ = &mut shutdown => {
                info!("proxy stopped");
                return Ok(());
            }
            fetched = default_domains::fetch_default_domains_with_outbound(runtime.outbound()) => fetched,
        };
        info!("  Got {} default CF domain(s)", fetched.len());
        config.cf_domains.extend(fetched);
    }

    // ── Pinned upstream sanity ───────────────────────────────────────────
    // After the domain fetch (so a cfproxy pin plus --default-domains is
    // judged on the fetched list) and before anything binds: a class pinned
    // to an unconfigured tier would drop every connection at runtime.
    config
        .validate_pinned_upstreams()
        .map_err(RunError::InvalidPin)?;
    for (flag, tiers) in [
        ("--pinned-upstream", &config.pinned_upstreams),
        ("--pinned-media-upstream", &config.pinned_media_upstreams),
    ] {
        if let Some(pos) = tiers.iter().position(|t| *t == UpstreamTier::Tcp)
            && pos + 1 != tiers.len()
        {
            warn!(
                "{flag}: tcp is a terminal tier — everything listed after it \
                 ({}) is never reached",
                tiers[pos + 1..]
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
    }

    // ── Connectivity check mode (--check) ────────────────────────────────
    // Run probes for every configured CF domain and MTProto proxy, print the
    // results, then return.  This lets the user verify their configuration
    // before starting the proxy server.
    //
    // With `--check-listener` there is a socket of our own to probe, so the
    // check runs after the bind below instead, against the listener this
    // process serves on.
    if config.check && !config.check_listener {
        let all_ok = tokio::select! {
            _ = &mut shutdown => return Ok(()),
            all_ok = check::run_check_with_outbound(&config, runtime.outbound(), None) => all_ok,
        };
        return if all_ok {
            Ok(())
        } else {
            Err(RunError::CheckFailed)
        };
    }

    // ── Bind the server socket ────────────────────────────────────────────
    let bind_host = config.bind_host();
    let addr: SocketAddr = format!("{}:{}", bind_host, config.port)
        .parse()
        .map_err(|_| RunError::InvalidListenAddress(format!("{bind_host}:{}", config.port)))?;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| RunError::Bind { addr, source })?;
    let bound_addr = listener.local_addr().unwrap_or(addr);
    let listen_port = bound_addr.port();

    // ── FD budget & effective max_connections ────────────────────────────
    // Each active connection uses 2 FDs: the accepted client socket and the
    // outbound connection to Telegram (WS or TCP fallback).  The pool adds
    // pool_size × dc_buckets × 2 FDs (idle + one in-flight refill per bucket).
    // Auto-compute a safe default when the user has not set --max-connections,
    // so the proxy stays within the process's soft file-descriptor limit.
    let fd_limit = soft_nofile_limit();
    let dc_redirects = config.dc_redirects();
    let dc_buckets = dc_redirects.len() * 2; // non-media + media per DC
    let max_connections = match config.max_connections {
        Some(n) => {
            let safe = auto_max_connections(fd_limit, config.pool_size, dc_buckets);
            if n > safe {
                warn!(
                    "max-connections={} may exceed the safe limit for this system's \
                     FD budget (fd-limit={}, recommended ≤{}). \
                     Consider raising `ulimit -n` or reducing --max-connections.",
                    n, fd_limit, safe
                );
            }
            n
        }
        None => auto_max_connections(fd_limit, config.pool_size, dc_buckets),
    };

    // ── Print startup banner ──────────────────────────────────────────────
    let secret = config.primary_secret();

    let link_host = config.link_host();
    let tg_link = format!(
        "tg://proxy?server={}&port={}&secret={}",
        link_host,
        listen_port,
        config.link_secret()
    );

    info!("{}", "=".repeat(60));
    info!(
        "  Telegram MTProto WS Bridge Proxy  (tg-ws-proxy-rs v{})",
        env!("CARGO_PKG_VERSION")
    );
    info!("  Listening on   {}:{}", bind_host, listen_port);
    info!("  Secret:        {}", secret);
    if let Some(domain) = config.listen_faketls_domain() {
        info!("  Inbound mode:   FakeTLS ee (SNI: {})", domain);
    } else {
        info!("  Inbound mode:   padded MTProto dd");
    }
    info!("  Target DC IPs:");
    let mut dcs: Vec<_> = dc_redirects.iter().collect();
    dcs.sort_by_key(|(k, _)| *k);
    for (dc, ip) in &dcs {
        info!("    DC{}: {}", dc, ip);
    }

    if config.skip_tls_verify {
        info!("  ⚠  TLS certificate verification DISABLED");
    }

    if !config.cf_domains.is_empty() {
        info!("  Cloudflare proxy domain(s):");
        for d in &config.cf_domains {
            info!("    {} (kws{{N}}.{} subdomains)", d, d);
        }
        if config.cf_balance && config.cf_domains.len() > 1 {
            info!("    ⚖  CF balance mode: connections are round-robin'd across domains");
        }
    }

    let cf_worker_domains = config.cf_worker_domains();
    if !cf_worker_domains.is_empty() {
        info!("  Cloudflare Worker domain(s):");
        for domain in cf_worker_domains {
            info!("    {}", domain);
        }
    }

    if config.cf_disable_tls && (!config.cf_domains.is_empty() || !cf_worker_domains.is_empty()) {
        warn!(
            "  ⚠  CF transport: plaintext ws:// on port 80 — the obfuscated MTProto stream is \
             on the wire in the clear: every frame's auth_key_id is readable and the \
             obfuscation is recoverable from captured bytes (#123), so connections are \
             identifiable. Route media through these tiers, not text."
        );
    }
    if !config.pinned_upstreams.is_empty() || !config.pinned_media_upstreams.is_empty() {
        info!("  Pinned upstream order (default ladder is used for the rest):");
        let names = |tiers: &[UpstreamTier]| {
            tiers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        if !config.pinned_upstreams.is_empty() {
            info!("    non-media: {}", names(&config.pinned_upstreams));
        }
        if !config.pinned_media_upstreams.is_empty() {
            info!("    media: {}", names(&config.pinned_media_upstreams));
        } else if !config.pinned_upstreams.is_empty() {
            info!("    media: inherits non-media pin above");
        }
    }

    if !config.cf_ips.is_empty() {
        info!(
            "  Cloudflare preferred IP(s): {}",
            config
                .cf_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        if config.cf_domains.is_empty() && cf_worker_domains.is_empty() {
            warn!(
                "  ⚠  --cf-ip has no effect: no --cf-domain, --default-domains, \
                 or --cf-worker-domain route is configured"
            );
        }
    }

    if !config.mtproto_proxies.is_empty() {
        info!("  Upstream MTProto proxies (WS fallback):");
        for p in &config.mtproto_proxies {
            info!("    {}:{}", p.host, p.port);
        }
    }

    if let Some(summary) = runtime.outbound().summary() {
        info!("  Outbound proxy: {}", summary);
    }

    if let Some(domain) = runtime.fronting_domain() {
        if dc_redirects.is_empty() {
            warn!(
                "  ⚠  --fronting-domain {} has no effect: no --dc-ip is configured. \
                 Fronting only applies to a direct connection to a DC's real IP \
                 (matching upstream tg-ws-proxy) — it is never used for CF proxy, \
                 CF Worker, or upstream MTProto proxy connections.",
                domain
            );
        } else {
            info!("  Domain fronting: always (SNI {})", domain);
        }
    }

    info!(
        "  Max connections: {} (fd-limit: {})",
        max_connections, fd_limit
    );
    if let Some(dir) = &config.log_dir {
        let options = config.log_options();
        let retention = match options.retention_days {
            0 => "keep all".to_string(),
            days => format!("{days} days"),
        };
        info!(
            "  Log sink:      {} ({}, compression {}, durability {})",
            dir.display(),
            retention,
            config.log_compress,
            config.log_durability
        );
        // Retention is a sweep by file name, so an absurd value deletes nothing
        // rather than failing — worth saying out loud, not worth refusing.
        if options.retention_days > RETENTION_WARN_DAYS {
            warn!(
                "  ⚠  --log-retention {} days keeps every segment in practice",
                options.retention_days
            );
        }
    }
    info!("{}", "=".repeat(60));
    info!("  Telegram proxy link (use this on all devices):");
    info!("    {}", tg_link);
    if config.secrets.len() > 1 {
        info!("  Additional per-user proxy links:");
        for secret in &config.secrets[1..] {
            let link_secret = config.link_secret_for(secret);
            info!(
                "    tg://proxy?server={}&port={}&secret={}",
                link_host, listen_port, link_secret
            );
        }
    }

    if link_host != bind_host {
        info!(
            "  ℹ  Link uses auto-detected IP {}. \
             Use --link-ip <IP> to override.",
            link_host
        );
    } else if matches!(bind_host.as_str(), "127.0.0.1" | "::1") {
        warn!(
            "  ⚠  Link shows {} — only the local machine can use this link. \
             Run with --host 0.0.0.0 (or --link-ip <router-LAN-IP>) \
             so other devices on the network can connect.",
            bind_host
        );
    }
    info!("{}", "=".repeat(60));

    // ── The banner as one record ──────────────────────────────────────────
    // Written once, and only when the sink is on: it is how a segment says
    // which configuration produced the sessions in it, months later, on a
    // device whose console output nobody kept.
    if let Some(handle) = &log {
        let mut dc_ips: Vec<DcIp> = dc_redirects
            .iter()
            .map(|(dc, ip)| DcIp {
                dc: *dc,
                ip: ip.clone(),
            })
            .collect();
        dc_ips.sort_by_key(|entry| entry.dc);

        let levels = config.log_settings().levels;
        let categories: Vec<String> = Category::ALL
            .iter()
            .map(|category| format!("{}={}", category.name(), levels[*category as usize].name()))
            .collect();

        let version = env!("CARGO_PKG_VERSION").to_string();
        let listen = format!("{bind_host}:{listen_port}");
        let tiers = configured_tiers(&config, cf_worker_domains);

        log::scope_global(Arc::clone(handle), async {
            log_event!(
                Category::Config,
                Level::Info,
                Event::StartupSummary {
                    version,
                    listen,
                    dc_ips,
                    tiers,
                    categories,
                }
            );
        })
        .await;
    }

    on_listen(ListenInfo {
        addr: bound_addr,
        tg_link,
    });

    // ── Connection pool warm-up ───────────────────────────────────────────
    let pool = Arc::new(
        WsPool::with_runtime(
            config.pool_size,
            Duration::from_secs(config.pool_max_age),
            Arc::clone(&runtime),
        )
        .with_log(log.cloned()),
    );
    // Shared for the rest of the process: every connection reads the same
    // settings, so they are behind one `Arc` instead of a per-connection clone.
    let config = Arc::new(config);
    {
        let pool_clone = pool.clone();
        let config_clone = Arc::clone(&config);
        tokio::spawn(async move {
            pool_clone.warmup(&config_clone).await;
        });
    }

    // ── Own-listener check (--check --check-listener) ─────────────────────
    // The probes run as a task, not before the bind: the listener probe has to
    // be accepted by the loop below, so the two run together, and the loop
    // stops on the verdict.  The socket handed over is the one just bound, so
    // the secret, address and inbound mode are the ones being served rather
    // than copies the user has to repeat.
    let (check_tx, check_rx) = tokio::sync::oneshot::channel::<bool>();
    let mut check_rx = Some(check_rx);
    let _check_keep = if config.check {
        let config = Arc::clone(&config);
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            let all_ok =
                check::run_check_with_outbound(&config, runtime.outbound(), Some(bound_addr)).await;
            let _ = check_tx.send(all_ok);
        });
        None
    } else {
        // Held for the life of the loop, so the receiver never resolves and the
        // selects below keep one shape.
        Some(check_tx)
    };
    let mut check_ok = None;

    // ── Accept loop ───────────────────────────────────────────────────────
    // Acquire a permit before each accept() to cap concurrent connections.
    // This prevents EMFILE (too many open files) by keeping file-descriptor
    // usage bounded: at most `max_connections` client sockets plus the pool
    // connections can be open simultaneously.
    const EMFILE: i32 = 24; // too many open files (per-process fd limit)
    const ENFILE: i32 = 23; // file table overflow (system-wide fd limit)
    let semaphore = Arc::new(Semaphore::new(max_connections));
    // One clone for the loop: each accepted connection needs its own handle to
    // plant in its task, and the option itself is borrowed from the caller.
    let log = log.cloned();

    // ── Descriptor snapshot (EVT:fd_snapshot) ─────────────────────────────
    // A task of its own rather than a branch in the selects below: the first
    // select blocks when the process is at its connection limit, which is the
    // one moment a descriptor count is interesting. Aborted with the loop, so
    // an embedder that starts and stops servers does not accumulate timers.
    let snapshot = log.as_ref().map(|handle| {
        let handle = Arc::clone(handle);
        let semaphore = Arc::clone(&semaphore);
        let soft_limit = fd_limit.min(u32::MAX as usize) as u32;
        tokio::spawn(log::scope_global(handle, async move {
            let mut ticker = tokio::time::interval(FD_SNAPSHOT_INTERVAL);
            // The first tick of an interval is immediate; this record is about
            // a steady state, not a startup.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                log_event!(
                    Category::Accept,
                    Level::Debug,
                    Event::FdSnapshot {
                        open: open_fds(),
                        soft_limit,
                        sem_avail: semaphore.available_permits().min(u32::MAX as usize) as u32,
                    }
                );
            }
        }))
    });

    loop {
        // Block here when we are already at the connection limit.  Pending
        // TCP connections queue in the kernel backlog until capacity frees up.
        let permit = tokio::select! {
            _ = &mut shutdown => break,
            all_ok = check_verdict(&mut check_rx) => {
                check_ok = Some(all_ok);
                break;
            }
            permit = Arc::clone(&semaphore).acquire_owned() => {
                permit.expect("semaphore closed unexpectedly")
            }
        };

        tokio::select! {
            _ = &mut shutdown => break,
            all_ok = check_verdict(&mut check_rx) => {
                check_ok = Some(all_ok);
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer_addr)) => {
                        let cfg = Arc::clone(&config);
                        let pool = pool.clone();
                        let runtime = Arc::clone(&runtime);
                        let log = log.clone();
                        tokio::spawn(async move {
                            // Hold the permit for the lifetime of this connection so
                            // it is released (and the slot freed) when the task ends.
                            let _permit = permit;
                            let client =
                                proxy::handle_client_with_runtime(stream, peer_addr, cfg, pool, runtime);
                            // The session's events are attributed by the task-local
                            // rather than by a parameter, which is what keeps `conn_id`
                            // off the ~110 call sites below this one.  Scoping the
                            // whole future — including the tasks it spawns — is the
                            // only place it has to be set up.
                            match &log {
                                Some(handle) => {
                                    log::scope(handle.next_conn_id(), Arc::clone(handle), client).await
                                }
                                None => client.await,
                            }
                        });
                    }
                    Err(e) => {
                        // EMFILE / ENFILE: the process has run out of file descriptors
                        // (e.g. from pool connections).  Back off longer to let
                        // existing connections close, and log at warn-level to avoid
                        // flooding the log with repeated identical messages.
                        let (backoff_ms, code) = if matches!(e.raw_os_error(), Some(EMFILE) | Some(ENFILE)) {
                            (500, ErrorCode::Resource)
                        } else {
                            // Not a class of its own: the errno is the answer, and
                            // `Resource` would claim a budget problem that is not there.
                            (50, ErrorCode::Unspecified)
                        };
                        if let Some(handle) = &log {
                            let errno = e.raw_os_error().unwrap_or(0);
                            log::scope_global(Arc::clone(handle), async {
                                log_event!(Category::Accept, Level::Warn, Event::AcceptError {
                                    errno,
                                    backoff_ms,
                                    err: code as i32,
                                });
                            })
                            .await;
                        }
                        if matches!(e.raw_os_error(), Some(EMFILE) | Some(ENFILE)) {
                            warn!("accept error: {} — backing off to allow FDs to free", e);
                            tokio::time::sleep(Duration::from_millis(u64::from(backoff_ms))).await;
                        } else {
                            error!("accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(u64::from(backoff_ms))).await;
                        }
                    }
                }
            }
        }
    }

    if let Some(task) = snapshot {
        task.abort();
    }

    if let Some(all_ok) = check_ok {
        return if all_ok {
            Ok(())
        } else {
            Err(RunError::CheckFailed)
        };
    }

    info!("proxy stopped");
    Ok(())
}
