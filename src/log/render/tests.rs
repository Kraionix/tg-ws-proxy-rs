//! The render corpus: one case per event, plus the shapes that break formatters.
//!
//! A synthetic corpus rather than a captured one, because what these tests are
//! for is the *form* of the line: a real segment would pin today's wording and
//! prove nothing about the events that did not happen to occur in it.
//!
//! Every expected line is written out in full, level column and peer prefix
//! included. That column is the part of the console this refactor is allowed to
//! change, so a change to it has to show up as a change to this table.

use super::*;
use crate::log::schema::{
    AcceptError, AttemptSkipped, ClosedBy, CooldownArmed, CooldownCleared, CooldownKind,
    CooldownSkipped, Ctx, DiscardReason, DomainListFetched, DomainSource, ErrorCode, Event,
    FdSnapshot, HandshakeKind, Level, LogOverflow, LogRecord, Peer, PoolDiscard, PoolHit, PoolMiss,
    PoolRefill, ProbeResult, Reason, RelayInitRetries, SessionClosed, SessionOpened, Shutdown,
    ShutdownPhase, ShutdownSignal, StartupSummary, Tier, TierAttempt, TierFallback, TlsHandshake,
    WarmupComplete,
};

/// `2026-10-12T11:23:16.612026Z`, the stamp every case below is written at.
const TS: u64 = 1_791_804_196_612_026_000;

const PEER: &str = "192.168.1.60:51719";

fn at(conn_id: u64, level: Level, event: Event) -> LogRecord {
    LogRecord {
        ts_ns: TS,
        conn_id,
        seq: 1,
        level: level as i32,
        category: 0,
        event: Some(event),
    }
}

/// A session-scoped record, which is what carries the `[peer]` prefix.
fn session(level: Level, event: Event) -> LogRecord {
    at(7, level, event)
}

fn ctx(dc: u32, is_media: bool, tier: Tier) -> Option<Ctx> {
    Some(Ctx::new(dc, is_media, tier))
}

/// Renders and returns the line without its newline, panicking if there is none.
fn line(record: &LogRecord, peer: Option<&str>) -> String {
    let mut out = String::new();
    assert!(render(record, peer, &mut out), "expected a line");
    assert!(out.ends_with('\n'), "every line ends in a newline");
    out.pop();
    out
}

/// The line as it appears on the console: everything after the timestamp.
///
/// Byte-for-byte, which is the point — a wording change without a table change
/// is the drift this module exists to end.
fn rest(record: &LogRecord, peer: Option<&str>) -> String {
    let rendered = line(record, peer);
    rendered
        .strip_prefix("2026-10-12T11:23:16.612026Z ")
        .expect("every line starts with the timestamp")
        .to_string()
}

fn ipv4(addr: [u8; 4], port: u32) -> Peer {
    Peer {
        addr: addr.to_vec(),
        port,
        hashed: false,
        encrypted: false,
    }
}

// ── The corpus ─────────────────────────────────────────────────────────────

#[test]
fn the_corpus_renders_the_console_lines() {
    let cases: Vec<(&str, LogRecord, &str)> = vec![
        (
            "session opened",
            session(
                Level::Info,
                Event::SessionOpened(SessionOpened {
                    ctx: ctx(2, true, Tier::Unspecified),
                    peer: Some(ipv4([192, 168, 1, 60], 51719)),
                }),
            ),
            " INFO [192.168.1.60:51719] DC2m session opened",
        ),
        (
            "session closed",
            session(
                Level::Info,
                Event::SessionClosed(SessionClosed {
                    ctx: ctx(2, true, Tier::Ws),
                    closed_by: ClosedBy::Client as i32,
                    bytes_up: 23_961,
                    bytes_down: 5_557_452,
                    dur_ms: 64_512,
                    via: "kws2.web.telegram.org".into(),
                }),
            ),
            " INFO [192.168.1.60:51719] DC2m WS session closed via kws2.web.telegram.org \
             by client: \u{2191}23.4KB  \u{2193}5.3MB  64.5s",
        ),
        (
            "session closed with nothing recorded about the route",
            session(
                Level::Info,
                Event::SessionClosed(SessionClosed {
                    ctx: None,
                    closed_by: ClosedBy::Unspecified as i32,
                    bytes_up: 0,
                    bytes_down: 0,
                    dur_ms: 0,
                    via: String::new(),
                }),
            ),
            " INFO [192.168.1.60:51719] DC? session closed by unknown: \
             \u{2191}0.0B  \u{2193}0.0B  0.0s",
        ),
        (
            "a rung that connected",
            session(
                Level::Info,
                Event::TierAttempt(TierAttempt {
                    ctx: ctx(2, false, Tier::Ws),
                    host: "kws2.web.telegram.org".into(),
                    ok: true,
                    dur_ns: 312_400_000,
                    err: 0,
                    err_code: 0,
                    errno: 0,
                }),
            ),
            " INFO [192.168.1.60:51719] DC2 WS connected via kws2.web.telegram.org (312ms)",
        ),
        (
            "a rung that failed, with the errno behind the classification",
            session(
                Level::Warn,
                Event::TierAttempt(TierAttempt {
                    ctx: ctx(2, false, Tier::Ws),
                    host: "kws2.web.telegram.org".into(),
                    ok: false,
                    dur_ns: 305_000_000,
                    err: ErrorCode::TcpConnect as i32,
                    err_code: 0,
                    errno: 111,
                }),
            ),
            " WARN [192.168.1.60:51719] DC2 WS failed on kws2.web.telegram.org: \
             tcp_connect (os error 111) (305ms)",
        ),
        (
            "an HTTP status failure, which carries its number instead",
            session(
                Level::Warn,
                Event::TierAttempt(TierAttempt {
                    ctx: ctx(2, false, Tier::Cfproxy),
                    host: "cf.example.com".into(),
                    ok: false,
                    dur_ns: 48_200_000,
                    err: ErrorCode::HttpStatus as i32,
                    err_code: 502,
                    errno: 0,
                }),
            ),
            " WARN [192.168.1.60:51719] DC2 CF proxy failed on cf.example.com: \
             http_status (status 502) (48.2ms)",
        ),
        (
            "a rung that did not name a host",
            session(
                Level::Warn,
                Event::TierAttempt(TierAttempt {
                    ctx: ctx(1, false, Tier::Tcp),
                    host: String::new(),
                    ok: false,
                    dur_ns: 1_000_000_000,
                    err: ErrorCode::TcpConnectTimeout as i32,
                    err_code: 0,
                    errno: 0,
                }),
            ),
            " WARN [192.168.1.60:51719] DC1 TCP failed: tcp_connect_timeout (1.00s)",
        ),
        (
            "the ladder stepping down",
            session(
                Level::Info,
                Event::TierFallback(TierFallback {
                    ctx: ctx(2, false, Tier::Ws),
                    from_tier: Tier::Ws as i32,
                    to_tier: Tier::Cfworker as i32,
                    reason: Reason::WsFail as i32,
                }),
            ),
            " INFO [192.168.1.60:51719] DC2 ws\u{2192}cfworker (ws_fail)",
        ),
        (
            "a cooldown being armed",
            session(
                Level::Warn,
                Event::CooldownArmed(CooldownArmed {
                    ctx: ctx(2, false, Tier::Cfworker),
                    kind: CooldownKind::CfWorkerFail as i32,
                    key_display: "worker.example.workers.dev".into(),
                    dur_s: 60,
                    err: ErrorCode::TlsTimeout as i32,
                    err_code: 0,
                }),
            ),
            " WARN [192.168.1.60:51719] DC2 CF Worker failed, cooldown 60s for \
             worker.example.workers.dev (tls_timeout)",
        ),
        (
            "a cooldown long enough to need minutes",
            session(
                Level::Warn,
                Event::CooldownArmed(CooldownArmed {
                    ctx: ctx(2, true, Tier::Ws),
                    kind: CooldownKind::IpFail as i32,
                    key_display: "149.154.167.51".into(),
                    dur_s: 3_600,
                    err: ErrorCode::TcpConnect as i32,
                    err_code: 0,
                }),
            ),
            " WARN [192.168.1.60:51719] DC2m IP failed, cooldown 1h0m for \
             149.154.167.51 (tcp_connect)",
        ),
        (
            "a cooldown cleared by a success",
            session(
                Level::Debug,
                Event::CooldownCleared(CooldownCleared {
                    ctx: ctx(1, false, Tier::Unspecified),
                    kind: CooldownKind::WsFail as i32,
                    key_display: "kws1.web.telegram.org".into(),
                }),
            ),
            "DEBUG [192.168.1.60:51719] DC1 WS cooldown cleared for kws1.web.telegram.org",
        ),
        (
            "a rung skipped because of a cooldown",
            session(
                Level::Debug,
                Event::CooldownSkipped(CooldownSkipped {
                    ctx: ctx(2, false, Tier::Cfworker),
                    kind: CooldownKind::CfWorkerFail as i32,
                    key_display: "worker.example.workers.dev".into(),
                }),
            ),
            "DEBUG [192.168.1.60:51719] DC2 CF Worker in cooldown, skipping \
             (worker.example.workers.dev)",
        ),
        (
            "a pool hit",
            session(
                Level::Debug,
                Event::PoolHit(PoolHit {
                    ctx: ctx(2, true, Tier::Ws),
                    left: 3,
                }),
            ),
            "DEBUG [192.168.1.60:51719] DC2m WS pool hit (3 left)",
        ),
        (
            "a pool miss",
            session(
                Level::Debug,
                Event::PoolMiss(PoolMiss {
                    ctx: ctx(2, true, Tier::Ws),
                }),
            ),
            "DEBUG [192.168.1.60:51719] DC2m WS pool miss",
        ),
        (
            "a pool refill",
            session(
                Level::Debug,
                Event::PoolRefill(PoolRefill {
                    ctx: ctx(2, true, Tier::Cfworker),
                    added: 4,
                    ready: 4,
                    dur_ms: 241,
                }),
            ),
            "DEBUG [192.168.1.60:51719] DC2m CF Worker pool refilled: +4 (4 ready, 241ms)",
        ),
        (
            "an idle connection thrown away",
            session(
                Level::Debug,
                Event::PoolDiscard(PoolDiscard {
                    ctx: ctx(2, true, Tier::Ws),
                    reason: DiscardReason::Stale as i32,
                }),
            ),
            "DEBUG [192.168.1.60:51719] DC2m WS pool discarded a stale connection",
        ),
        (
            "a TLS handshake",
            session(
                Level::Debug,
                Event::TlsHandshake(TlsHandshake {
                    ctx: ctx(2, false, Tier::Ws),
                    kind: HandshakeKind::Full as i32,
                    dur_ns: 1_200_000,
                    err: 0,
                    errno: 0,
                }),
            ),
            "DEBUG [192.168.1.60:51719] DC2 WS TLS handshake full (1.2ms)",
        ),
        (
            "a TLS handshake that failed",
            session(
                Level::Warn,
                Event::TlsHandshake(TlsHandshake {
                    ctx: ctx(2, false, Tier::Ws),
                    kind: HandshakeKind::Resumed as i32,
                    dur_ns: 5_000_000_000,
                    err: ErrorCode::TlsTimeout as i32,
                    errno: 0,
                }),
            ),
            " WARN [192.168.1.60:51719] DC2 WS TLS handshake resumed failed: \
             tls_timeout (5.00s)",
        ),
        (
            "a rung the ladder never dialled",
            session(
                Level::Info,
                Event::AttemptSkipped(AttemptSkipped {
                    ctx: ctx(2, true, Tier::Unspecified),
                    tier: Tier::Ws as i32,
                    reason: Reason::IpCooldown as i32,
                }),
            ),
            " INFO [192.168.1.60:51719] DC2m skip ws (ip_cooldown)",
        ),
    ];

    for (name, record, expected) in cases {
        assert_eq!(rest(&record, Some(PEER)), expected, "case {name:?}");
    }
}

/// The lines that belong to no session, which carry a subsystem tag instead of
/// a peer.
#[test]
fn process_wide_events_carry_a_subsystem_tag() {
    let cases: Vec<(&str, LogRecord, &str)> = vec![
        (
            "relay init retries, singular",
            at(
                0,
                Level::Warn,
                Event::RelayInitRetries(RelayInitRetries { n: 1 }),
            ),
            " WARN [upstream] relay init needed 1 retry",
        ),
        (
            "relay init retries, plural",
            at(
                0,
                Level::Warn,
                Event::RelayInitRetries(RelayInitRetries { n: 3 }),
            ),
            " WARN [upstream] relay init needed 3 retries",
        ),
        (
            "an accept failure",
            at(
                0,
                Level::Warn,
                Event::AcceptError(AcceptError {
                    errno: 24,
                    backoff_ms: 50,
                    err: ErrorCode::Resource as i32,
                }),
            ),
            " WARN [accept] accept error: resource (os error 24) \u{2014} backing off 50ms",
        ),
        (
            "an accept failure with nothing but an errno",
            at(
                0,
                Level::Warn,
                Event::AcceptError(AcceptError {
                    errno: 0,
                    backoff_ms: 0,
                    err: 0,
                }),
            ),
            " WARN [accept] accept error",
        ),
        (
            "a descriptor snapshot",
            at(
                0,
                Level::Debug,
                Event::FdSnapshot(FdSnapshot {
                    open: 22,
                    soft_limit: 1024,
                    sem_avail: 464,
                }),
            ),
            "DEBUG [accept] fds 22/1024, permits 464",
        ),
        (
            "dropped records",
            at(
                0,
                Level::Warn,
                Event::LogOverflow(LogOverflow {
                    dropped: 12,
                    window_ns: 30_000_000_000,
                }),
            ),
            " WARN [log] log dropped 12 records over 30.00s",
        ),
        (
            "a finished warm-up",
            at(
                0,
                Level::Info,
                Event::WarmupComplete(WarmupComplete {
                    ready: 8,
                    dur_ms: 1_200,
                }),
            ),
            " INFO [pool] warmup complete: 8 ready (1.2s)",
        ),
        (
            "the domain list that is in use",
            at(
                0,
                Level::Info,
                Event::DomainListFetched(DomainListFetched {
                    source: DomainSource::Github as i32,
                    count: 5,
                    err: 0,
                    err_code: 0,
                }),
            ),
            " INFO default CF domains: 5 from github",
        ),
        (
            "the built-in list, because the fetch failed",
            at(
                0,
                Level::Warn,
                Event::DomainListFetched(DomainListFetched {
                    source: DomainSource::Builtin as i32,
                    count: 3,
                    err: ErrorCode::Dns as i32,
                    err_code: 0,
                }),
            ),
            " WARN default CF domains: 3 from built-in fallback (fetch failed: dns)",
        ),
        (
            "a stop signal",
            at(
                0,
                Level::Info,
                Event::Shutdown(Shutdown {
                    phase: ShutdownPhase::Requested as i32,
                    signal: ShutdownSignal::Term as i32,
                }),
            ),
            " INFO SIGTERM received, stopping",
        ),
        (
            "the stop finishing",
            at(
                0,
                Level::Info,
                Event::Shutdown(Shutdown {
                    phase: ShutdownPhase::Complete as i32,
                    signal: ShutdownSignal::Unspecified as i32,
                }),
            ),
            " INFO proxy stopped",
        ),
        (
            "a stop cut short",
            at(
                0,
                Level::Warn,
                Event::Shutdown(Shutdown {
                    phase: ShutdownPhase::Forced as i32,
                    signal: ShutdownSignal::Int as i32,
                }),
            ),
            " WARN second signal: exiting now",
        ),
        (
            "a handshake outside any session",
            at(
                0,
                Level::Debug,
                Event::TlsHandshake(TlsHandshake {
                    ctx: ctx(2, true, Tier::Unspecified),
                    kind: HandshakeKind::Full as i32,
                    dur_ns: 900_000,
                    err: 0,
                    errno: 0,
                }),
            ),
            "DEBUG DC2m TLS handshake full (900.0\u{b5}s)",
        ),
    ];

    for (name, record, expected) in cases {
        assert_eq!(rest(&record, None), expected, "case {name:?}");
    }
}

/// The level column is five characters wide, which is what keeps the messages
/// of a column aligned — and it is the record's own level that is printed, not
/// a table's.
#[test]
fn the_level_column_is_five_characters_wide() {
    let cases = [
        (Level::Debug, "DEBUG"),
        (Level::Info, " INFO"),
        (Level::Warn, " WARN"),
        (Level::Error, "ERROR"),
    ];

    for (level, tag) in cases {
        let record = session(
            level,
            Event::PoolMiss(PoolMiss {
                ctx: ctx(2, false, Tier::Ws),
            }),
        );
        assert_eq!(
            rest(&record, Some(PEER)),
            format!("{tag} [192.168.1.60:51719] DC2 WS pool miss"),
            "{} did not render its own tag",
            level.name()
        );
    }
}

// ── Timestamps ─────────────────────────────────────────────────────────────

/// The calendar arithmetic, on the cases that break a naive implementation.
#[test]
fn timestamps_are_iso_8601_utc_with_microseconds() {
    let cases = [
        ("the epoch", 0, "1970-01-01T00:00:00.000000Z"),
        (
            "a leap day",
            1_709_210_096_123_456_000,
            "2024-02-29T12:34:56.123456Z",
        ),
        (
            "the day after a leap day",
            1_709_296_496_000_000_000,
            "2024-03-01T12:34:56.000000Z",
        ),
        (
            "the next leap day, eight years on",
            1_961_670_896_123_456_000,
            "2032-02-29T12:34:56.123456Z",
        ),
        (
            "one microsecond before a day boundary",
            1_791_849_599_999_999_000,
            "2026-10-12T23:59:59.999999Z",
        ),
        (
            "the day boundary itself",
            1_791_849_600_000_000_000,
            "2026-10-13T00:00:00.000000Z",
        ),
        (
            "a century that is not a leap year: 2100-02-28",
            4_107_542_399_999_999_000,
            "2100-02-28T23:59:59.999999Z",
        ),
        (
            "and the day after it, which is March",
            4_107_542_400_000_000_000,
            "2100-03-01T00:00:00.000000Z",
        ),
        (
            "a century that is a leap year",
            951_782_400_000_000_000,
            "2000-02-29T00:00:00.000000Z",
        ),
        (
            "the 32-bit second boundary",
            2_147_483_648_000_000_000,
            "2038-01-19T03:14:08.000000Z",
        ),
        (
            "a sub-microsecond stamp, which truncates",
            1_791_804_196_612_026_999,
            "2026-10-12T11:23:16.612026Z",
        ),
    ];

    for (name, ts_ns, expected) in cases {
        let mut out = String::new();
        write_timestamp(ts_ns, &mut out);
        assert_eq!(out, expected, "case {name:?} stamped unexpectedly");
    }
}

// ── Peers ──────────────────────────────────────────────────────────────────

#[test]
fn peers_render_in_every_encoding_the_schema_allows() {
    let cases = [
        ("ipv4", ipv4([192, 168, 1, 60], 51719), "192.168.1.60:51719"),
        (
            "ipv6, as the standard library prints it",
            Peer {
                addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].to_vec(),
                port: 443,
                hashed: false,
                encrypted: false,
            },
            "2001:db8::1:443",
        ),
        (
            "a hashed address, which is all the record has left",
            Peer {
                addr: vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04],
                port: 51719,
                hashed: true,
                encrypted: false,
            },
            "deadbeef01020304:51719",
        ),
        (
            "an encrypted address, tag byte and all",
            Peer {
                addr: vec![0x10, 0xaa, 0xbb],
                port: 0,
                hashed: false,
                encrypted: true,
            },
            "enc:10aabb",
        ),
        (
            "nothing at all, which is a record rather than a crash",
            Peer {
                addr: Vec::new(),
                port: 0,
                hashed: false,
                encrypted: false,
            },
            "?",
        ),
    ];

    for (name, peer, expected) in cases {
        assert_eq!(peer_text(&peer), expected, "case {name:?} rendered oddly");
    }
}

/// The nil-byte and long-domain cases the corpus exists for.
#[test]
fn a_long_domain_and_a_nil_byte_survive_the_round_trip() {
    let long_host = format!("{}.example.com", "a".repeat(180));
    let record = session(
        Level::Warn,
        Event::TierAttempt(TierAttempt {
            ctx: ctx(203, true, Tier::Cfproxy),
            host: long_host.clone(),
            ok: false,
            dur_ns: 0,
            err: ErrorCode::Dns as i32,
            err_code: 0,
            errno: 0,
        }),
    );
    let rendered = line(&record, Some(PEER));
    assert!(rendered.contains(&long_host), "the host was truncated");
    assert!(rendered.contains("(0ns)"), "a zero duration is not a gap");

    let with_nil = session(
        Level::Warn,
        Event::TierAttempt(TierAttempt {
            ctx: ctx(2, false, Tier::Ws),
            host: "kws\u{0}2.example".into(),
            ok: false,
            dur_ns: 1,
            err: ErrorCode::Read as i32,
            err_code: 0,
            errno: 0,
        }),
    );
    let rendered = line(&with_nil, Some(PEER));
    assert!(
        rendered.contains("kws\u{0}2.example"),
        "a nil byte must pass through rather than split the line"
    );
}

// ── Unknown values, which a later writer may have produced ─────────────────

#[test]
fn unknown_discriminants_render_as_marks_rather_than_panicking() {
    let record = session(
        Level::Info,
        Event::TierFallback(TierFallback {
            ctx: Some(Ctx {
                dc: 0,
                is_media: false,
                tier: 99,
            }),
            from_tier: 99,
            to_tier: 99,
            reason: 99,
        }),
    );
    assert_eq!(
        rest(&record, None),
        " INFO [?] DC? unspecified\u{2192}unspecified (unspecified)"
    );

    let unknown_level = LogRecord {
        level: 99,
        ..session(
            Level::Info,
            Event::PoolMiss(PoolMiss {
                ctx: ctx(2, false, Tier::Ws),
            }),
        )
    };
    assert_eq!(
        rest(&unknown_level, Some(PEER)),
        "  ??? [192.168.1.60:51719] DC2 WS pool miss"
    );
}

// ── The contract the view depends on ───────────────────────────────────────

/// Every variant the schema knows, rendered.
///
/// The exhaustive `match` in [`write_message`] already refuses to compile when
/// an event has no line; this is the other half — that the line it does have is
/// produced for the schema's own corpus, whose fields are all at their extremes.
#[test]
fn every_event_variant_renders() {
    let mut without_a_line = Vec::new();
    for record in crate::log::schema::canonical_records() {
        let mut out = String::new();
        if !render(&record, Some(PEER), &mut out) {
            without_a_line.push(record.event);
        }
    }

    let named: Vec<&str> = without_a_line
        .iter()
        .map(|event| match event {
            Some(Event::StartupSummary(_)) => "startup_summary",
            Some(Event::ProbeResult(_)) => "probe_result",
            other => panic!("{other:?} has no line and should have one"),
        })
        .collect();
    assert_eq!(named, ["probe_result", "startup_summary"]);
}

/// Two events have no line, and they are the two that are printed by the mode
/// that produced them.
#[test]
fn the_banner_and_the_probe_report_have_no_line() {
    let banner = at(
        0,
        Level::Info,
        Event::StartupSummary(StartupSummary {
            version: "2.5.4-struct-logging".into(),
            listen: "0.0.0.0:1443".into(),
            dc_ips: Vec::new(),
            tiers: Vec::new(),
            categories: Vec::new(),
        }),
    );
    let probe = at(
        0,
        Level::Info,
        Event::ProbeResult(ProbeResult {
            kind: 1,
            target: "cf.example.com".into(),
            ok: true,
            dur_ns: 1,
            err: 0,
            err_code: 0,
        }),
    );

    for record in [banner, probe] {
        let mut out = String::from("kept");
        assert!(!render(&record, Some(PEER), &mut out));
        assert_eq!(out, "kept", "a skipped record must leave the buffer alone");
    }
}

/// The view reuses one buffer for the life of the process, so a render appends
/// to whatever is already there and never clears it.
#[test]
fn rendering_appends_to_the_buffer_it_is_given() {
    let record = session(
        Level::Info,
        Event::PoolMiss(PoolMiss {
            ctx: ctx(2, true, Tier::Ws),
        }),
    );

    let mut out = String::new();
    assert!(render(&record, Some(PEER), &mut out));
    let once = out.len();
    assert!(render(&record, Some(PEER), &mut out));
    assert_eq!(out.len(), once * 2);
    assert_eq!(out.matches("DC2m WS pool miss").count(), 2);
}

/// A record whose payload is missing is a decode artefact, not a panic.
#[test]
fn a_record_without_a_payload_renders_nothing() {
    let record = LogRecord {
        ts_ns: TS,
        conn_id: 7,
        seq: 1,
        level: Level::Info as i32,
        category: 1,
        event: None,
    };
    let mut out = String::new();
    assert!(!render(&record, Some(PEER), &mut out));
    assert!(out.is_empty());
}

/// The length budget: a line is read by a human and shipped to a syslog, so the
/// worst case has to stay sane even when every field is at its maximum.
#[test]
fn the_worst_case_line_fits_a_terminal() {
    let closed = session(
        Level::Info,
        Event::SessionClosed(SessionClosed {
            ctx: ctx(203, true, Tier::Cfworker),
            closed_by: ClosedBy::Upstream as i32,
            bytes_up: u64::MAX,
            bytes_down: u64::MAX,
            dur_ms: u32::MAX,
            via: format!("{}.workers.dev", "w".repeat(120)),
        }),
    );

    let rendered = line(&closed, Some(PEER));
    assert!(
        rendered.len() < 512,
        "a session line grew to {} bytes",
        rendered.len()
    );
    assert!(
        rendered.contains("16384.0PB"),
        "u64::MAX is not a small number: {rendered}"
    );
    assert!(
        rendered.contains("4294967.3s"),
        "the longest session there is"
    );
}
