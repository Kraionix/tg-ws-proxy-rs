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

use std::io::IsTerminal as _;

use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::log::schema::ShutdownSignal;
use tg_ws_proxy_rs::server::{self, RunError};

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring CryptoProvider");

    let config = Config::from_args();
    init_logging(&config);

    match server::run(config, shutdown_signal()).await {
        Ok(()) => {}
        Err(RunError::CheckFailed) => std::process::exit(1),
        Err(RunError::InvalidOutbound(e)) => {
            eprintln!("invalid outbound proxy config: {e}");
            std::process::exit(2);
        }
        // Bind and InvalidListenAddress are ordinary user mistakes -- "port
        // already in use" must not reach the user as a panic with a
        // RUST_BACKTRACE suggestion attached.
        Err(e) => {
            eprintln!("{e}");
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
        // This one line stays a console line even after stage 5 turns the rest
        // of the log into records: the process is about to exit, and a record
        // that has not reached the writer task yet would be lost with it.
        tokio::spawn(async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
            tracing::warn!("still stopping; second signal exits now");
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

fn init_logging(config: &Config) {
    let log_level = if config.quiet {
        "off"
    } else if config.verbose {
        "debug"
    } else {
        "info"
    };

    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| log_level.into());

    if let Some(ref path) = config.log_file {
        // File output: always disable ANSI color codes in log files.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| panic!("cannot open log file '{}': {}", path, e));
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_writer(file)
            .init();
    } else {
        // Console output: ANSI color codes are not rendered correctly on
        // Windows consoles that lack Virtual Terminal Processing support, so
        // disable them there.  Also disable when stderr is not a terminal
        // (e.g. output is piped or redirected).
        let use_ansi = std::io::stderr().is_terminal() && !cfg!(windows);
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(use_ansi)
            .init();
    }
}
