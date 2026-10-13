//! tg-ws-proxy-rs — Telegram MTProto WebSocket Bridge Proxy
//!
//! Listens for Telegram Desktop MTProto connections and forwards them through
//! WebSocket tunnels to Telegram's DC servers, bypassing networks that block
//! direct Telegram TCP traffic.
//!
//! # Architecture
//!
//! ```
//! Telegram Desktop → MTProto (TCP 1443) → tg-ws-proxy-rs → WS (TLS 443) → Telegram DC
//! ```
//!
//! See [`tg_ws_proxy_rs::proxy`] for the connection handling logic and
//! [`tg_ws_proxy_rs::crypto`] for the MTProto obfuscation details.

use std::fmt;
use std::io::IsTerminal as _;

use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{Format, FormatEvent, FormatFields, Writer};
use tracing_subscriber::registry::LookupSpan;

use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::direct;
#[cfg(feature = "log-disk")]
use tg_ws_proxy_rs::dump;
use tg_ws_proxy_rs::log::schema::ShutdownSignal;
use tg_ws_proxy_rs::server::{self, RunError};

#[tokio::main]
async fn main() {
    let config = Config::from_args();

    // A reader verb instead of the server: nothing below this line is set up
    // for it — no rustls provider, no `tracing` subscriber, no runtime work —
    // because reading a segment is a file operation with a JSON answer, and a
    // router that asked "what is on the stick" should not start a proxy to
    // find out. The verbs themselves are in a build with the `log-disk`
    // feature, which is the only one that has segments to read.
    #[cfg(feature = "log-disk")]
    if let Some(command) = &config.command {
        let code = match dump::run(command) {
            std::process::ExitCode::SUCCESS => 0,
            _ => 1,
        };
        std::process::exit(code);
    }

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring CryptoProvider");

    init_foreign_logging();

    match server::run(config, shutdown_signal()).await {
        Ok(()) => {}
        // The report went to stdout and is the reason for the exit code; a
        // second line repeating "connectivity check failed" would be noise
        // under it.
        Err(RunError::CheckFailed) => std::process::exit(1),
        Err(RunError::InvalidOutbound(e)) => {
            direct!("invalid outbound proxy config: {e}");
            std::process::exit(2);
        }
        // Bind and InvalidListenAddress are ordinary user mistakes -- "port
        // already in use" must not reach the user as a panic with a
        // RUST_BACKTRACE suggestion attached.
        Err(e) => {
            direct!("{e}");
            std::process::exit(1);
        }
    }
}

/// Resolves when the process is asked to stop.
///
/// Without this the binary runs until the kernel kills it, and `SIGTERM` — what
/// init and systemd send — takes the log with it: the sink's default durability
/// commits without syncing, so a killed process loses everything since the last
/// sync. Measured in stage 6: a `SIGTERM` three seconds into a run left an empty
/// segment. Handling the signal turns that into an ordinary stop, which flushes
/// and syncs on the way out.
///
/// The signal is the future's *value* rather than a line printed here: the
/// record of the stop is written by the server, which owns the log handle (and
/// before that, by nothing — this task has no sink to write into).
///
/// A *second* signal exits immediately, so a stop that hangs is still a stop.
async fn shutdown_signal() -> ShutdownSignal {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let Ok(mut term) = signal(SignalKind::terminate()) else {
            return std::future::pending().await;
        };
        let Ok(mut int) = signal(SignalKind::interrupt()) else {
            return std::future::pending().await;
        };

        let received = tokio::select! {
            _ = term.recv() => ShutdownSignal::Term,
            _ = int.recv() => ShutdownSignal::Int,
        };

        // Held by this task, which outlives the shutdown future: the sink's
        // drain window is milliseconds, so anything still here is stuck.
        //
        // Printed rather than recorded, unlike every other line about a stop:
        // the process is about to exit, and a record that has not reached the
        // writer task yet would be lost with it — which is the one thing this
        // line exists to avoid.
        tokio::spawn(async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
            direct!("still stopping; second signal exits now");
            std::process::exit(130);
        });

        received
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        ShutdownSignal::Int
    }
}

/// Sends other crates' `tracing` lines to stderr — the one stream this process
/// does not own.
///
/// Off unless `RUST_LOG` names a target: `rustls` and `tungstenite` narrate
/// their handshakes at debug, which is worth having when a TLS failure makes no
/// sense and is otherwise a hundred lines nobody asked for. What this process
/// itself has to say is a record ([`tg_ws_proxy_rs::log`]) or a
/// `tg-ws-proxy:` line ([`direct!`]), and neither goes through here.
fn init_foreign_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"))
        // Our own targets emit nothing through `tracing` at all, so this only
        // keeps a broad `RUST_LOG=debug` from promising a stream that is not
        // there.
        .add_directive(
            "tg_ws_proxy_rs=off"
                .parse()
                .expect("a literal directive parses"),
        );

    // ANSI colour codes are not rendered correctly on Windows consoles that
    // lack Virtual Terminal Processing support, so they are disabled there and
    // whenever stderr is not a terminal (output piped or redirected).
    let use_ansi = std::io::stderr().is_terminal() && !cfg!(windows);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(use_ansi)
        .with_writer(std::io::stderr)
        .event_format(ForeignLine)
        .init();
}

/// Formats a foreign crate's line the way this process writes its own: one
/// `tg-ws-proxy:`-prefixed line, so a reader can tell the two apart without
/// knowing which crates are in the build.
struct ForeignLine;

impl<S, N> FormatEvent<S, N> for ForeignLine
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        write!(writer, "tg-ws-proxy: ")?;
        Format::default().format_event(ctx, writer, event)
    }
}
