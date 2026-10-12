//! The text view: one record in, one console line out.
//!
//! This module is the whole of the human-readable log. Before it, the console
//! line and the record were two independent statements of the same fact, and
//! they had already drifted — the line named the host a rung dialled and the
//! record did not, the record classified a failure and the line printed a
//! sentence. Now the line is a projection of the record: nothing here decides
//! *what* happened, and a fact that is not in the record cannot appear in the
//! text.
//!
//! Two things follow from that, and both are load-bearing:
//!
//! * [`render`] matches on every [`Event`] variant, so adding an event without
//!   giving it a line does not compile. The exhaustive match is the test that
//!   the text view stays complete.
//! * The line is written into a caller-owned [`String`] rather than returned.
//!   A busy router emits tens of thousands of records a day, and the view is
//!   the only allocator on that path.
//!
//! The wording is the console's own, minus the `tracing` target: the module a
//! line came from is derivable from the event, and where it still matters it is
//! a bracket tag (`[pool]`, `[accept]`, `[upstream]`) rather than a crate path.
//! Durations and byte counts are the formats the old lines used, because they
//! are what an operator's eye is calibrated to.
//!
//! One thing here is not a projection: the `[peer]` prefix. The record carries
//! the peer only in `session_opened` — every later event of a session is about
//! the route rather than the caller — so the prefix comes from the stream, and
//! the caller passes what it learned from the session's open record. Records
//! written before the schema change, or read from the middle of a segment, have
//! no peer and render as `[?]`.

use std::fmt::Write as _;

use super::schema::{
    ClosedBy, CooldownKind, Ctx, DiscardReason, DomainSource, ErrorCode, Event, HandshakeKind,
    Level, LogRecord, Peer, Reason, ShutdownPhase, ShutdownSignal, Tier,
};

/// Appends the line for `record` to `out`, and returns whether there was one.
///
/// `false` is not a failure: two events deliberately have no console line.
/// `startup_summary` is the banner, which is printed once at startup by
/// `server.rs` and would be a wall of text in the middle of the stream, and
/// `probe_result` is the output of `--check`, which prints a report rather than
/// a log. Anything else — including an event this build has no line for, which
/// cannot happen because the match is exhaustive — is a line.
///
/// `peer` is the session's client address as the stream reported it, or `None`
/// when the stream did not say; see the module docs.
pub fn render(record: &LogRecord, peer: Option<&str>, out: &mut String) -> bool {
    let Some(event) = record.event.as_ref() else {
        return false;
    };

    // Written first, rolled back if the event turns out to have no line: that
    // keeps the "no line" decision in one place instead of asking twice.
    let start = out.len();
    write_timestamp(record.ts_ns, out);
    out.push(' ');
    out.push_str(level_tag(record.level));
    out.push(' ');
    if record.conn_id == 0 {
        let tag = event_tag(event);
        if !tag.is_empty() {
            out.push_str(tag);
            out.push(' ');
        }
    } else {
        out.push('[');
        out.push_str(peer.unwrap_or("?"));
        out.push_str("] ");
    }

    if !write_message(event, out) {
        out.truncate(start);
        return false;
    }

    out.push('\n');
    true
}

/// The client address of a session, as the `[peer]` prefix spells it.
///
/// `Peer.addr` holds one of the three encodings `70_SECURITY.md` defines, and
/// the two flags say which: a redacted address is hex because that is all it
/// is, and the record must not look like a readable address it is not.
pub fn peer_text(peer: &Peer) -> String {
    let mut text = String::with_capacity(peer.addr.len() + 8);
    if peer.hashed {
        for byte in &peer.addr {
            let _ = write!(text, "{byte:02x}");
        }
    } else if peer.encrypted {
        text.push_str("enc:");
        for byte in &peer.addr {
            let _ = write!(text, "{byte:02x}");
        }
    } else {
        match peer.addr.len() {
            4 => {
                let octets = <[u8; 4]>::try_from(peer.addr.as_slice()).expect("length checked");
                let _ = write!(
                    text,
                    "{}.{}.{}.{}",
                    octets[0], octets[1], octets[2], octets[3]
                );
            }
            16 => {
                let octets = <[u8; 16]>::try_from(peer.addr.as_slice()).expect("length checked");
                let _ = write!(text, "{}", std::net::Ipv6Addr::from(octets));
            }
            _ => {
                for byte in &peer.addr {
                    let _ = write!(text, "{byte:02x}");
                }
            }
        }
    }

    if peer.port != 0 {
        let _ = write!(text, ":{}", peer.port);
    }
    if text.is_empty() {
        text.push('?');
    }

    text
}

/// `2026-10-12T11:23:16.612026Z` — UTC, ISO-8601, microseconds, from unix ns.
///
/// Hand-written because the crate has no date library and this is the only
/// place that needs one; the calendar arithmetic is Howard Hinnant's
/// `civil_from_days`, which is valid for the whole range of `i64` days and so
/// has no case for a clock that is wrong in either direction.
fn write_timestamp(ts_ns: u64, out: &mut String) {
    let seconds = ts_ns / 1_000_000_000;
    let micros = (ts_ns % 1_000_000_000) / 1_000;
    let days = (seconds / 86_400) as i64;
    let second_of_day = seconds % 86_400;

    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60,
    );

    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z"
    );
}

/// Days since 1970-01-01 to a proleptic Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01, which puts the leap day at the end of the
    // year and makes the month lengths a repeating pattern rather than a table.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_position + 2) / 5 + 1) as u32;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The five-character level column, which is what `tracing` printed and what
/// keeps the messages of a column aligned.
///
/// A level this build does not know — a discriminant a later writer added,
/// which `prost` preserves as an integer — is rendered as `???` rather than
/// dropped: the line is still the only copy of that fact on the console.
fn level_tag(level: i32) -> &'static str {
    match Level::try_from(level) {
        Ok(Level::Debug) => "DEBUG",
        Ok(Level::Info) => " INFO",
        Ok(Level::Warn) => " WARN",
        Ok(Level::Error) => "ERROR",
        Ok(Level::Unspecified) | Err(_) => "  ???",
    }
}

/// The bracket tag a process-wide line carries, for the lines whose message
/// does not already say where they came from.
///
/// Session-scoped lines get `[peer]` instead — see [`render`] — so this is only
/// ever the empty string or one of the subsystem tags.
fn event_tag(event: &Event) -> &'static str {
    match event {
        Event::PoolHit(_)
        | Event::PoolMiss(_)
        | Event::PoolRefill(_)
        | Event::PoolDiscard(_)
        | Event::WarmupComplete(_) => "[pool]",
        Event::FdSnapshot(_) | Event::AcceptError(_) => "[accept]",
        Event::RelayInitRetries(_) => "[upstream]",
        Event::LogOverflow(_) => "[log]",
        _ => "",
    }
}

/// Appends the message half of the line, or reports that the event has none.
fn write_message(event: &Event, out: &mut String) -> bool {
    match event {
        Event::SessionOpened(opened) => {
            write_dc(opened.ctx.as_ref(), out);
            out.push_str("session opened");
        }
        Event::SessionClosed(closed) => {
            write_dc_tier(closed.ctx.as_ref(), out);
            out.push_str("session closed");
            // "by client" and "by upstream" name the side that ended the
            // session; a session with no route was ended by neither, and no
            // host carried it, so the two clauses would both be empty.
            if ClosedBy::try_from(closed.closed_by) != Ok(ClosedBy::NoRoute) {
                if !closed.via.is_empty() {
                    out.push_str(" via ");
                    out.push_str(&closed.via);
                }
                out.push_str(" by ");
                out.push_str(closed_by_text(closed.closed_by));
            }
            out.push_str(": \u{2191}");
            write_bytes(closed.bytes_up, out);
            out.push_str("  \u{2193}");
            write_bytes(closed.bytes_down, out);
            out.push_str("  ");
            write_seconds_from_millis(closed.dur_ms, out);
        }
        Event::TierAttempt(attempt) => {
            write_dc_tier(attempt.ctx.as_ref(), out);
            if attempt.ok {
                out.push_str("connected");
                if !attempt.host.is_empty() {
                    out.push_str(" via ");
                    out.push_str(&attempt.host);
                }
            } else {
                out.push_str("failed");
                if !attempt.host.is_empty() {
                    out.push_str(" on ");
                    out.push_str(&attempt.host);
                }
                out.push_str(": ");
                write_error(attempt.err, attempt.err_code, attempt.errno, out);
            }
            out.push_str(" (");
            write_nanos(attempt.dur_ns, out);
            out.push(')');
        }
        Event::TierFallback(fallback) => {
            write_dc(fallback.ctx.as_ref(), out);
            out.push_str(tier_slug(
                Tier::try_from(fallback.from_tier).unwrap_or_default(),
            ));
            out.push('\u{2192}');
            out.push_str(tier_slug(
                Tier::try_from(fallback.to_tier).unwrap_or_default(),
            ));
            out.push_str(" (");
            out.push_str(reason_slug(fallback.reason));
            out.push(')');
        }
        Event::CooldownArmed(armed) => {
            write_dc(armed.ctx.as_ref(), out);
            out.push_str(cooldown_kind_text(armed.kind));
            out.push_str(" failed, cooldown ");
            write_span_seconds(u64::from(armed.dur_s), out);
            if !armed.key_display.is_empty() {
                out.push_str(" for ");
                out.push_str(&armed.key_display);
            }
            out.push_str(" (");
            out.push_str(error_slug(armed.err));
            if armed.err_code != 0 {
                let _ = write!(out, " {}", armed.err_code);
            }
            out.push(')');
        }
        Event::CooldownCleared(cleared) => {
            write_dc(cleared.ctx.as_ref(), out);
            out.push_str(cooldown_kind_text(cleared.kind));
            out.push_str(" cooldown cleared");
            if !cleared.key_display.is_empty() {
                out.push_str(" for ");
                out.push_str(&cleared.key_display);
            }
        }
        Event::CooldownSkipped(skipped) => {
            write_dc(skipped.ctx.as_ref(), out);
            out.push_str(cooldown_kind_text(skipped.kind));
            out.push_str(" in cooldown, skipping");
            if !skipped.key_display.is_empty() {
                out.push_str(" (");
                out.push_str(&skipped.key_display);
                out.push(')');
            }
        }
        Event::PoolHit(hit) => {
            write_dc_tier(hit.ctx.as_ref(), out);
            let _ = write!(out, "pool hit ({} left)", hit.left);
        }
        Event::PoolMiss(miss) => {
            write_dc_tier(miss.ctx.as_ref(), out);
            out.push_str("pool miss");
        }
        Event::PoolRefill(refill) => {
            write_dc_tier(refill.ctx.as_ref(), out);
            let _ = write!(
                out,
                "pool refilled: +{} ({} ready, ",
                refill.added, refill.ready
            );
            write_millis(refill.dur_ms, out);
            out.push(')');
            if refill.err != 0 {
                out.push_str(" failed: ");
                write_error(refill.err, 0, refill.errno, out);
            }
        }
        Event::PoolDiscard(discard) => {
            write_dc_tier(discard.ctx.as_ref(), out);
            out.push_str("pool discarded a ");
            out.push_str(discard_reason_text(discard.reason));
            out.push_str(" connection");
        }
        Event::TlsHandshake(handshake) => {
            write_dc_tier(handshake.ctx.as_ref(), out);
            out.push_str("TLS handshake");
            // A handshake that failed before the server's Finished, or one the
            // dial never observed, has no negotiated kind to name — and naming
            // it `unspecified` would read as a fact rather than as an absence.
            if handshake.kind != HandshakeKind::Unspecified as i32 {
                out.push(' ');
                out.push_str(handshake_kind_text(handshake.kind));
            }
            if handshake.err != 0 {
                out.push_str(" failed: ");
                write_error(handshake.err, 0, handshake.errno, out);
            }
            out.push_str(" (");
            write_nanos(handshake.dur_ns, out);
            out.push(')');
        }
        Event::RelayInitRetries(retries) => {
            let _ = write!(
                out,
                "relay init needed {} {}",
                retries.n,
                if retries.n == 1 { "retry" } else { "retries" }
            );
        }
        Event::AcceptError(error) => {
            out.push_str("accept error");
            if error.err != 0 || error.errno != 0 {
                out.push_str(": ");
                write_error(error.err, 0, error.errno, out);
            }
            if error.backoff_ms != 0 {
                out.push_str(" \u{2014} backing off ");
                write_millis(error.backoff_ms, out);
            }
        }
        Event::FdSnapshot(snapshot) => {
            let _ = write!(
                out,
                "fds {}/{}, permits {}",
                snapshot.open, snapshot.soft_limit, snapshot.sem_avail
            );
        }
        Event::LogOverflow(overflow) => {
            let _ = write!(out, "log dropped {} records over ", overflow.dropped);
            write_nanos(overflow.window_ns, out);
        }
        Event::WarmupComplete(warmup) => {
            let _ = write!(out, "warmup complete: {} ready (", warmup.ready);
            write_millis(warmup.dur_ms, out);
            out.push(')');
        }
        Event::AttemptSkipped(skipped) => {
            write_dc(skipped.ctx.as_ref(), out);
            out.push_str("skip ");
            out.push_str(tier_slug(Tier::try_from(skipped.tier).unwrap_or_default()));
            out.push_str(" (");
            out.push_str(reason_slug(skipped.reason));
            out.push(')');
        }
        Event::DomainListFetched(fetched) => {
            let _ = write!(out, "default CF domains: {} from ", fetched.count);
            out.push_str(domain_source_text(fetched.source));
            if fetched.err != 0 {
                out.push_str(" (fetch failed: ");
                out.push_str(error_slug(fetched.err));
                if fetched.err_code != 0 {
                    let _ = write!(out, " {}", fetched.err_code);
                }
                out.push(')');
            }
        }
        Event::Shutdown(shutdown) => match ShutdownPhase::try_from(shutdown.phase) {
            Ok(ShutdownPhase::Complete) => out.push_str("proxy stopped"),
            Ok(ShutdownPhase::Forced) => out.push_str("second signal: exiting now"),
            Ok(ShutdownPhase::Requested) | Ok(ShutdownPhase::Unspecified) | Err(_) => {
                out.push_str(shutdown_signal_text(shutdown.signal));
                out.push_str(" received, stopping");
            }
        },
        // The banner and the `--check` report are printed by their own modes;
        // a line here would be the same fact twice in two formats.
        Event::StartupSummary(_) | Event::ProbeResult(_) => return false,
    }

    true
}

/// `DC2m ` / `DC2` / `DC? ` — the prefix every session line has carried, with
/// the separating space so that the message beside it needs no leading one.
fn write_dc(ctx: Option<&Ctx>, out: &mut String) {
    match ctx {
        Some(ctx) if ctx.dc != 0 => {
            let _ = write!(out, "DC{}", ctx.dc);
            if ctx.is_media {
                out.push('m');
            }
        }
        _ => out.push_str("DC?"),
    }
    out.push(' ');
}

/// `DC2m WS ` — the same prefix with the rung, for the events that are about a
/// route through the session rather than about the session itself.
fn write_dc_tier(ctx: Option<&Ctx>, out: &mut String) {
    write_dc(ctx, out);
    if let Some(ctx) = ctx {
        let tier = ctx_tier(ctx);
        if tier != Tier::Unspecified {
            out.push_str(tier_text(tier));
            out.push(' ');
        }
    }
}

fn ctx_tier(ctx: &Ctx) -> Tier {
    Tier::try_from(ctx.tier).unwrap_or_default()
}

/// The rung as a sentence subject: `WS`, `CF Worker`, `MTProto`.
fn tier_text(tier: Tier) -> &'static str {
    match tier {
        Tier::Ws => "WS",
        Tier::Cfworker => "CF Worker",
        Tier::Cfproxy => "CF proxy",
        Tier::Mtproto => "MTProto",
        Tier::Tcp => "TCP",
        Tier::Unspecified => "unspecified",
    }
}

/// The rung inside an arrow or a skip: `ws`, `cfworker`.
///
/// Two spellings on purpose: `WS connected` reads as a sentence, `ws→cfworker`
/// reads as the step down a ladder, and the console has always written both.
fn tier_slug(tier: Tier) -> &'static str {
    match tier {
        Tier::Ws => "ws",
        Tier::Cfworker => "cfworker",
        Tier::Cfproxy => "cfproxy",
        Tier::Mtproto => "mtproto",
        Tier::Tcp => "tcp",
        Tier::Unspecified => "unspecified",
    }
}

fn closed_by_text(closed_by: i32) -> &'static str {
    match ClosedBy::try_from(closed_by) {
        Ok(ClosedBy::Client) => "client",
        Ok(ClosedBy::Upstream) => "upstream",
        // Named by the message itself: "closed by no route" is not a sentence
        // anybody writes, and the record's other fields say nothing else.
        Ok(ClosedBy::NoRoute) => "no route",
        Ok(ClosedBy::Unspecified) | Err(_) => "unknown",
    }
}

fn reason_slug(reason: i32) -> &'static str {
    match Reason::try_from(reason) {
        Ok(Reason::WsFail) => "ws_fail",
        Ok(Reason::IpCooldown) => "ip_cooldown",
        Ok(Reason::CfWorkerFail) => "cfworker_fail",
        Ok(Reason::CfProxyFail) => "cfproxy_fail",
        Ok(Reason::UpstreamFail) => "upstream_fail",
        Ok(Reason::NotInDcIp) => "not_in_dc_ip",
        Ok(Reason::Pinned) => "pinned",
        Ok(Reason::NoFallback) => "no_fallback",
        Ok(Reason::Unspecified) | Err(_) => "unspecified",
    }
}

fn error_slug(err: i32) -> &'static str {
    match ErrorCode::try_from(err) {
        Ok(ErrorCode::Dns) => "dns",
        Ok(ErrorCode::TcpConnect) => "tcp_connect",
        Ok(ErrorCode::TcpConnectTimeout) => "tcp_connect_timeout",
        Ok(ErrorCode::Tls) => "tls",
        Ok(ErrorCode::TlsTimeout) => "tls_timeout",
        Ok(ErrorCode::HttpStatus) => "http_status",
        Ok(ErrorCode::HttpRedirect) => "http_redirect",
        Ok(ErrorCode::Upgrade) => "upgrade",
        Ok(ErrorCode::Protocol) => "protocol",
        Ok(ErrorCode::Read) => "read",
        Ok(ErrorCode::Resource) => "resource",
        Ok(ErrorCode::LocalIo) => "local_io",
        Ok(ErrorCode::FsUnsupported) => "fs_unsupported",
        Ok(ErrorCode::WriterConflict) => "writer_conflict",
        Ok(ErrorCode::Unspecified) | Err(_) => "unspecified",
    }
}

/// `tcp_connect (os error 111)` — what failed, then the diagnosis behind it.
///
/// The numeric detail is what tells two failures of the same class apart, which
/// is the whole reason the record carries it: `ENETUNREACH` and `ECONNREFUSED`
/// are both `tcp_connect` and call for different answers.
fn write_error(err: i32, err_code: u32, errno: i32, out: &mut String) {
    out.push_str(error_slug(err));
    if err_code != 0 {
        let _ = write!(out, " (status {err_code})");
    }
    if errno != 0 {
        let _ = write!(out, " (os error {errno})");
    }
}

/// `WS failed`, `IP` — what the cooldown was armed against.
fn cooldown_kind_text(kind: i32) -> &'static str {
    match CooldownKind::try_from(kind) {
        Ok(CooldownKind::WsFail) => "WS",
        Ok(CooldownKind::IpFail) => "IP",
        Ok(CooldownKind::UpstreamFail) => "upstream",
        Ok(CooldownKind::CfWorkerFail) => "CF Worker",
        Ok(CooldownKind::CfEdgeTlsFail) => "CF edge TLS",
        Ok(CooldownKind::CfEdgePlaintext) => "CF edge plaintext",
        Ok(CooldownKind::Unspecified) | Err(_) => "route",
    }
}

fn discard_reason_text(reason: i32) -> &'static str {
    match DiscardReason::try_from(reason) {
        Ok(DiscardReason::Stale) => "stale",
        Ok(DiscardReason::Closed) => "closed",
        Ok(DiscardReason::Unspecified) | Err(_) => "unusable",
    }
}

fn handshake_kind_text(kind: i32) -> &'static str {
    match HandshakeKind::try_from(kind) {
        Ok(HandshakeKind::Full) => "full",
        Ok(HandshakeKind::Resumed) => "resumed",
        Ok(HandshakeKind::Unspecified) | Err(_) => "unspecified",
    }
}

fn domain_source_text(source: i32) -> &'static str {
    match DomainSource::try_from(source) {
        Ok(DomainSource::Github) => "github",
        Ok(DomainSource::Builtin) => "built-in fallback",
        Ok(DomainSource::Unspecified) | Err(_) => "an unnamed source",
    }
}

fn shutdown_signal_text(signal: i32) -> &'static str {
    match ShutdownSignal::try_from(signal) {
        Ok(ShutdownSignal::Term) => "SIGTERM",
        Ok(ShutdownSignal::Int) => "SIGINT",
        Ok(ShutdownSignal::Unspecified) | Err(_) => "a stop signal",
    }
}

/// `23.4KB`, `5.3MB` — the byte format the console has always used, written
/// into the line's buffer rather than into a `String` of its own.
fn write_bytes(n: u64, out: &mut String) {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    let mut value = n as f64;
    for unit in UNITS {
        if value < 1024.0 {
            let _ = write!(out, "{value:.1}{unit}");
            return;
        }
        value /= 1024.0;
    }

    let _ = write!(out, "{value:.1}PB");
}

/// A duration measured in nanoseconds: `340ns`, `12.4µs`, `48.2ms`, `305ms`,
/// `1.20s`.
///
/// The tenth is dropped once a millisecond is a rounding error rather than a
/// measurement — `305.0ms` is a dial that timed out, not a dial timed to a
/// tenth of a millisecond.
fn write_nanos(ns: u64, out: &mut String) {
    match ns {
        0..1_000 => {
            let _ = write!(out, "{ns}ns");
        }
        1_000..1_000_000 => {
            let _ = write!(out, "{:.1}\u{b5}s", ns as f64 / 1_000.0);
        }
        1_000_000..100_000_000 => {
            let _ = write!(out, "{:.1}ms", ns as f64 / 1_000_000.0);
        }
        100_000_000..1_000_000_000 => {
            let _ = write!(out, "{:.0}ms", ns as f64 / 1_000_000.0);
        }
        _ => {
            let _ = write!(out, "{:.2}s", ns as f64 / 1_000_000_000.0);
        }
    }
}

/// A duration the record carries in whole milliseconds: `241ms`, `1.5s`.
fn write_millis(ms: u32, out: &mut String) {
    if ms < 1_000 {
        let _ = write!(out, "{ms}ms");
    } else {
        let _ = write!(out, "{:.1}s", f64::from(ms) / 1_000.0);
    }
}

/// A span held in whole seconds, as cooldowns are: `60s`, `2m30s`, `1h0m`.
fn write_span_seconds(seconds: u64, out: &mut String) {
    if seconds < 120 {
        let _ = write!(out, "{seconds}s");
    } else if seconds < 3_600 {
        let _ = write!(out, "{}m{}s", seconds / 60, seconds % 60);
    } else {
        let _ = write!(out, "{}h{}m", seconds / 3_600, (seconds % 3_600) / 60);
    }
}

/// A session's duration, which the record carries in milliseconds and the
/// console has always printed to a tenth of a second: `64.5s`.
fn write_seconds_from_millis(ms: u32, out: &mut String) {
    let _ = write!(out, "{:.1}s", f64::from(ms) / 1_000.0);
}

#[cfg(test)]
mod tests;
