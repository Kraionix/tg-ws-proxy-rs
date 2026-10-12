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

use crate::check;
use crate::config::{Config, UpstreamTier};
use crate::default_domains::{self, Fetched};
use crate::limits::{auto_max_connections, open_fds, soft_nofile_limit};
use crate::log::schema::{
    Category, DcIp, DomainListFetched, DomainSource, ErrorCode, Event, Level, Shutdown,
    ShutdownPhase, ShutdownSignal,
};
use crate::log::{self, LogHandle};
use crate::log_event;
use crate::outbound::OutboundConnector;
use crate::pool::WsPool;
use crate::proxy;
use crate::runtime::Runtime;

/// How often the descriptor budget is recorded.
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
    /// `--text-log` names something that cannot be written to.
    InvalidTextLog(String),
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
            Self::InvalidTextLog(reason) => write!(f, "invalid --text-log: {reason}"),
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
    shutdown: impl Future<Output = ShutdownSignal> + Send,
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
/// The pipeline is started here rather than in the binary's `main` because this
/// is the function that owns `config`: a handle created outside would have to be
/// threaded through `run`, every embedder and the Android shim to be usable
/// inside — or worse, the shim would run without logging at all. With a
/// `--log-dir` the sink is a segment on disk; without one it keeps nothing, and
/// the text log is the whole of what the records are for. Starting it here also
/// makes "a clean stop loses nothing" a property of the return path: every way
/// out of [`serve`] comes back through the shutdown, including the early returns
/// for `--check` and a failed bind.
pub async fn run_with_listen(
    config: Config,
    shutdown: impl Future<Output = ShutdownSignal> + Send,
    on_listen: impl FnOnce(ListenInfo) + Send,
) -> Result<(), RunError> {
    let log = log::init(
        config.log_dir.as_deref(),
        config.log_settings(),
        config.log_options(),
    )
    .map_err(|error| log_start_error(error, config.log_dir.as_deref()))?;

    let result = serve(config, shutdown, on_listen, &log).await;

    log.shutdown().await;

    result
}

/// A destination that could not be opened is the one startup failure with no
/// fallback: a log the operator asked for and did not get is a configuration
/// mistake to see, not a reason to run on quietly without it.
fn log_start_error(error: log::LogError, dir: Option<&Path>) -> RunError {
    match error {
        log::LogError::FsUnsupported(reason) => RunError::InvalidLogFs(reason),
        // The io error alone ("Permission denied") does not say which directory
        // it was about; the operator named one, so quote it back.
        log::LogError::Io(error) => RunError::InvalidLogDir(match dir {
            Some(dir) => format!("{}: {error}", dir.display()),
            None => error.to_string(),
        }),
        log::LogError::TextSink(reason) => RunError::InvalidTextLog(reason),
        error => RunError::InvalidLogDir(error.to_string()),
    }
}

#[cfg(test)]
mod tests;

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

/// The server itself: everything [`run_with_listen`] does once the pipeline is
/// up. Runs the probes with the pool's attribution: `conn_id = 0`.
///
/// A probe is not a session — nothing about it belongs to a client connection —
/// so it reports as the process does rather than under a scope built for it.
async fn run_check_logged(
    config: &Config,
    outbound: &OutboundConnector,
    listener: Option<SocketAddr>,
    log: &Arc<LogHandle>,
) -> bool {
    log::scope_global(
        Arc::clone(log),
        check::run_check_with_outbound(config, outbound, listener),
    )
    .await
}

/// Prints the startup banner to stdout and returns the primary `tg://` link.
///
/// stdout rather than the log, and unconditionally: the banner carries the
/// secret and the `tg://` links, which are the one thing a user needs before
/// anything else works, and it is printed before the pipeline exists. It is
/// also the reason nothing here is a record — "this is the whole
/// configuration" is not a level, and a record has a session or a process to
/// belong to, not a screen to appear on.
///
/// The ⚠ lines are part of it rather than warnings written elsewhere: they are
/// facts about the configuration being printed, and splitting them off would
/// leave a reader of the console log with half of it.
///
/// What it takes is only what the caller had to compute: the *bound* port (a
/// `--port 0` is not the configured one), the descriptor budget, and the
/// runtime whose outbound summary is part of the picture.
fn print_banner(
    config: &Config,
    runtime: &Runtime,
    listen_port: u16,
    max_connections: usize,
    fd_limit: usize,
) -> String {
    let secret = config.primary_secret();
    let bind_host = config.bind_host();
    let link_host = config.link_host();
    let dc_redirects = config.dc_redirects();
    let tg_link = format!(
        "tg://proxy?server={}&port={}&secret={}",
        link_host,
        listen_port,
        config.link_secret()
    );

    println!("{}", "=".repeat(60));
    println!(
        "  Telegram MTProto WS Bridge Proxy  (tg-ws-proxy-rs v{})",
        env!("CARGO_PKG_VERSION")
    );
    println!("  Listening on   {}:{}", bind_host, listen_port);
    println!("  Secret:        {}", secret);
    if let Some(domain) = config.listen_faketls_domain() {
        println!("  Inbound mode:   FakeTLS ee (SNI: {})", domain);
    } else {
        println!("  Inbound mode:   padded MTProto dd");
    }
    println!("  Target DC IPs:");
    let mut dcs: Vec<_> = dc_redirects.iter().collect();
    dcs.sort_by_key(|(k, _)| *k);
    for (dc, ip) in &dcs {
        println!("    DC{}: {}", dc, ip);
    }

    if config.skip_tls_verify {
        println!("  ⚠  TLS certificate verification DISABLED");
    }

    if !config.cf_domains.is_empty() {
        println!("  Cloudflare proxy domain(s):");
        for d in &config.cf_domains {
            println!("    {} (kws{{N}}.{} subdomains)", d, d);
        }
        if config.cf_balance && config.cf_domains.len() > 1 {
            println!("    ⚖  CF balance mode: connections are round-robin'd across domains");
        }
    }

    let cf_worker_domains = config.cf_worker_domains();
    if !cf_worker_domains.is_empty() {
        println!("  Cloudflare Worker domain(s):");
        for domain in cf_worker_domains {
            println!("    {}", domain);
        }
    }

    if config.cf_disable_tls && (!config.cf_domains.is_empty() || !cf_worker_domains.is_empty()) {
        println!(
            "  ⚠  CF transport: plaintext ws:// on port 80 — the obfuscated MTProto stream is \
             on the wire in the clear: every frame's auth_key_id is readable and the \
             obfuscation is recoverable from captured bytes (#123), so connections are \
             identifiable. Route media through these tiers, not text."
        );
    }
    if !config.pinned_upstreams.is_empty() || !config.pinned_media_upstreams.is_empty() {
        println!("  Pinned upstream order (default ladder is used for the rest):");
        let names = |tiers: &[UpstreamTier]| {
            tiers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        if !config.pinned_upstreams.is_empty() {
            println!("    non-media: {}", names(&config.pinned_upstreams));
        }
        if !config.pinned_media_upstreams.is_empty() {
            println!("    media: {}", names(&config.pinned_media_upstreams));
        } else if !config.pinned_upstreams.is_empty() {
            println!("    media: inherits non-media pin above");
        }
    }

    if !config.cf_ips.is_empty() {
        println!(
            "  Cloudflare preferred IP(s): {}",
            config
                .cf_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        if config.cf_domains.is_empty() && cf_worker_domains.is_empty() {
            println!(
                "  ⚠  --cf-ip has no effect: no --cf-domain, --default-domains, \
                 or --cf-worker-domain route is configured"
            );
        }
    }

    if !config.mtproto_proxies.is_empty() {
        println!("  Upstream MTProto proxies (WS fallback):");
        for p in &config.mtproto_proxies {
            println!("    {}:{}", p.host, p.port);
        }
    }

    if let Some(summary) = runtime.outbound().summary() {
        println!("  Outbound proxy: {}", summary);
    }

    if let Some(domain) = runtime.fronting_domain() {
        if dc_redirects.is_empty() {
            println!(
                "  ⚠  --fronting-domain {} has no effect: no --dc-ip is configured. \
                 Fronting only applies to a direct connection to a DC's real IP \
                 (matching upstream tg-ws-proxy) — it is never used for CF proxy, \
                 CF Worker, or upstream MTProto proxy connections.",
                domain
            );
        } else {
            println!("  Domain fronting: always (SNI {})", domain);
        }
    }

    println!(
        "  Max connections: {} (fd-limit: {})",
        max_connections, fd_limit
    );
    // The text view: where it goes, and the two floors that decide what
    // reaches it. Printed even when it is off, because "the console is silent"
    // is the answer to a question an operator asks by starting the proxy.
    let settings = config.log_settings();
    println!(
        "  Text log:      {} (text {}, ring {} ×{})",
        settings.text_log.name(),
        settings.text.name(),
        settings.ring.name(),
        settings.ring_capacity,
    );

    match &config.log_dir {
        None => println!(
            "  Log sink:      none — records are not written to disk (--log-dir keeps them)"
        ),
        Some(dir) => {
            let options = config.log_options();
            let retention = match options.retention_days {
                0 => "keep all".to_string(),
                days => format!("{days} days"),
            };
            // The filesystem, not just the path: which one the directory landed
            // on is the difference between a stick that works and one that has
            // to be re-formatted, and between a log file and a slice of RAM.
            let filesystem = log::storage::filesystem_name(dir);
            println!(
                "  Log sink:      {} ({}, compression {}, durability {}{})",
                dir.display(),
                retention,
                config.log_compress,
                config.log_durability,
                filesystem
                    .as_deref()
                    .map(|name| format!(", {name}"))
                    .unwrap_or_default()
            );
            // What it costs, from the measurement in the implementation plan's
            // §5.1: a record is ~44 B, a client connection writes about one of
            // them at the default level and about four with `--log-level
            // debug`, and an idle process writes the descriptor snapshot once
            // a minute.
            println!(
                "  Log volume:    ~44 B/record · ~1 record per client connection (~4 at debug)"
            );
            println!(
                "                 1 000 connections/day ≈ 0.3 MB/week (debug 1.2 MB) · \
             idle ≈ 1 MB/week · zstd-l1 ≈ 2× smaller"
            );
            if filesystem.as_deref() == Some("tmpfs") {
                println!(
                    "  ⚠  --log-dir is on tmpfs: the log lives in RAM, and --log-retention is \
                 the only thing bounding it"
                );
            }
            // Retention is a sweep by file name, so an absurd value deletes
            // nothing rather than failing — worth saying out loud, not worth
            // refusing.
            if options.retention_days > RETENTION_WARN_DAYS {
                println!(
                    "  ⚠  --log-retention {} days keeps every segment in practice",
                    options.retention_days
                );
            }
        }
    }
    println!("{}", "=".repeat(60));
    println!("  Telegram proxy link (use this on all devices):");
    println!("    {}", tg_link);
    if config.secrets.len() > 1 {
        println!("  Additional per-user proxy links:");
        for secret in &config.secrets[1..] {
            let link_secret = config.link_secret_for(secret);
            println!(
                "    tg://proxy?server={}&port={}&secret={}",
                link_host, listen_port, link_secret
            );
        }
    }

    if link_host != bind_host.as_str() {
        println!(
            "  ℹ  Link uses auto-detected IP {}. \
             Use --link-ip <IP> to override.",
            link_host
        );
    } else if matches!(bind_host.as_str(), "127.0.0.1" | "::1") {
        println!(
            "  ⚠  Link shows {} — only the local machine can use this link. \
             Run with --host 0.0.0.0 (or --link-ip <router-LAN-IP>) \
             so other devices on the network can connect.",
            bind_host
        );
    }

    tg_link
}

async fn serve(
    mut config: Config,
    shutdown: impl Future<Output = ShutdownSignal> + Send,
    on_listen: impl FnOnce(ListenInfo) + Send,
    log: &Arc<LogHandle>,
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
        let fetched = tokio::select! {
            signal = &mut shutdown => {
                // A stop during the fetch is a stop before anything was served,
                // so there is no "proxy stopped" to record — the run never got
                // that far.
                log::emit_global(
                    Some(log),
                    Category::Config,
                    Level::Info,
                    Event::Shutdown(Shutdown {
                        phase: ShutdownPhase::Requested as i32,
                        signal: signal as i32,
                    }),
                );

                return Ok(());
            }
            fetched = default_domains::fetch_domains_with_source(runtime.outbound()) => fetched,
        };

        log_domain_list(log, &fetched);
        config.cf_domains.extend(fetched.domains);
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
            // Not a record and not part of the banner either: this is a
            // configuration mistake, and it is the same line whether or not a
            // log was asked for.
            crate::direct!(
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
            all_ok = run_check_logged(&config, runtime.outbound(), None, log) => all_ok,
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
                crate::direct!(
                    "max-connections={} may exceed the safe limit for this system's \
                     FD budget (fd-limit={}, recommended ≤{}). \
                     Consider raising `ulimit -n` or reducing --max-connections.",
                    n,
                    fd_limit,
                    safe
                );
            }
            n
        }
        None => auto_max_connections(fd_limit, config.pool_size, dc_buckets),
    };

    // ── Print startup banner ──────────────────────────────────────────────
    let tg_link = print_banner(&config, &runtime, listen_port, max_connections, fd_limit);

    // ── The same banner as one record ─────────────────────────────────────
    // The printed banner above is for whoever is watching; this is for the
    // segment, which is how a log says months later which configuration
    // produced the sessions in it when nobody kept the console output.
    {
        let mut dc_ips: Vec<DcIp> = dc_redirects
            .iter()
            .map(|(dc, ip)| DcIp {
                dc: *dc,
                ip: ip.clone(),
            })
            .collect();
        dc_ips.sort_by_key(|entry| entry.dc);

        let disks = config.log_settings().disk;
        let categories: Vec<String> = Category::ALL
            .iter()
            .map(|category| format!("{}={}", category.name(), disks[*category as usize].name()))
            .collect();

        let version = env!("CARGO_PKG_VERSION").to_string();
        let listen = format!("{bind_host}:{listen_port}");
        let tiers = configured_tiers(&config, config.cf_worker_domains());

        log::emit_global(
            Some(log),
            Category::Config,
            Level::Info,
            Event::StartupSummary(crate::log::schema::StartupSummary {
                version,
                listen,
                dc_ips,
                tiers,
                categories,
            }),
        );
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
        .with_log(Some(Arc::clone(log))),
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
        let log = Arc::clone(log);
        tokio::spawn(async move {
            let all_ok =
                run_check_logged(&config, runtime.outbound(), Some(bound_addr), &log).await;
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
    // plant in its task, and the caller's reference is only borrowed.
    let log = Arc::clone(log);

    // ── Descriptor snapshot (EVT:fd_snapshot) ─────────────────────────────
    // A task of its own rather than a branch in the selects below: the first
    // select blocks when the process is at its connection limit, which is the
    // one moment a descriptor count is interesting. Aborted with the loop, so
    // an embedder that starts and stops servers does not accumulate timers.
    let snapshot = {
        let handle = Arc::clone(&log);
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
    };

    // Which signal ended the run, when one did: the record of the stop is
    // written after the loop, because a stop is two facts — it was asked for,
    // and it finished — and only the second one can be recorded from inside.
    let mut stop_signal = None;

    loop {
        // Block here when we are already at the connection limit.  Pending
        // TCP connections queue in the kernel backlog until capacity frees up.
        let permit = tokio::select! {
            signal = &mut shutdown => {
                stop_signal = Some(signal);
                break;
            }
            all_ok = check_verdict(&mut check_rx) => {
                check_ok = Some(all_ok);
                break;
            }
            permit = Arc::clone(&semaphore).acquire_owned() => {
                permit.expect("semaphore closed unexpectedly")
            }
        };

        tokio::select! {
            signal = &mut shutdown => {
                stop_signal = Some(signal);
                break;
            }
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
                            log::scope(log.next_conn_id(), log, client).await
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
                        let errno = e.raw_os_error().unwrap_or(0);
                        log::scope_global(Arc::clone(&log), async {
                            log_event!(Category::Accept, Level::Warn, Event::AcceptError {
                                errno,
                                backoff_ms,
                                err: code as i32,
                            });
                        })
                        .await;

                        tokio::time::sleep(Duration::from_millis(u64::from(backoff_ms))).await;
                    }
                }
            }
        }
    }

    snapshot.abort();

    if let Some(all_ok) = check_ok {
        return if all_ok {
            Ok(())
        } else {
            Err(RunError::CheckFailed)
        };
    }

    if let Some(signal) = stop_signal {
        log::emit_global(
            Some(&log),
            Category::Config,
            Level::Info,
            Event::Shutdown(Shutdown {
                phase: ShutdownPhase::Requested as i32,
                signal: signal as i32,
            }),
        );
    }

    log::emit_global(
        Some(&log),
        Category::Config,
        Level::Info,
        Event::Shutdown(Shutdown {
            phase: ShutdownPhase::Complete as i32,
            signal: ShutdownSignal::Unspecified as i32,
        }),
    );

    Ok(())
}

/// `EVT:domain_list_fetched` — where the process-wide route list came from.
///
/// A warning when the built-in list is what runs: `--default-domains` asks for
/// the community list, and a fallback quietly in use is how a proxy ends up
/// dialling domains nobody maintains. The failure class says which it was —
/// GitHub unreachable, or a list that parsed to nothing.
fn log_domain_list(log: &Arc<LogHandle>, fetched: &Fetched) {
    let (err, err_code) = match &fetched.failure {
        Some(failure) => (failure.err as i32, failure.err_code),
        None => (ErrorCode::Unspecified as i32, 0),
    };

    let level = if fetched.source == DomainSource::Builtin {
        Level::Warn
    } else {
        Level::Info
    };

    log::emit_global(
        Some(log),
        Category::Config,
        level,
        Event::DomainListFetched(DomainListFetched {
            source: fetched.source as i32,
            count: fetched.domains.len().min(u32::MAX as usize) as u32,
            err,
            err_code,
        }),
    );
}
