use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use prost::Message;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::schema::*;
use super::writer::{BatchSink, Writer, WriterError};
use super::*;

/// A record with a fixed, non-zero envelope: every sample differs only in its
/// payload, which is the part whose size the storage budget depends on.
fn record(event: Event) -> LogRecord {
    LogRecord {
        ts_ns: 1_700_000_000_123_456_789,
        conn_id: 42,
        seq: 7,
        level: Level::Info as i32,
        category: Category::Routing as i32,
        event: Some(event),
    }
}

/// One representative record per `oneof` variant, named after its `EVT:*`.
fn samples() -> Vec<(&'static str, LogRecord)> {
    vec![
        (
            "session_opened",
            record(Event::SessionOpened(SessionOpened {
                ctx: Some(Ctx::new(2, false, Tier::Unspecified)),
                peer: Some(Peer {
                    addr: vec![203, 0, 113, 5],
                    port: 51234,
                    hashed: false,
                    encrypted: false,
                }),
            })),
        ),
        (
            "session_closed",
            record(Event::SessionClosed(SessionClosed {
                ctx: Some(Ctx::new(2, true, Tier::Ws)),
                closed_by: ClosedBy::Upstream as i32,
                bytes_up: 1 << 20,
                bytes_down: 1 << 22,
                dur_ms: 120_000,
                via: "kws2.web.telegram.org".to_string(),
            })),
        ),
        (
            "tier_attempt",
            record(Event::TierAttempt(TierAttempt {
                ctx: Some(Ctx::new(4, true, Tier::Cfproxy)),
                host: "cf.example.com".to_string(),
                ok: false,
                dur_ns: 2_500_000_000,
                err: ErrorCode::TcpConnect as i32,
                err_code: 0,
                errno: 113,
            })),
        ),
        (
            "tier_fallback",
            record(Event::TierFallback(TierFallback {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                from_tier: Tier::Ws as i32,
                to_tier: Tier::Cfworker as i32,
                reason: Reason::WsFail as i32,
            })),
        ),
        (
            "cooldown_armed",
            record(Event::CooldownArmed(CooldownArmed {
                ctx: Some(Ctx::new(2, false, Tier::Cfworker)),
                kind: CooldownKind::WsFail as i32,
                key_display: "kws2.web.telegram.org:443".to_string(),
                dur_s: 300,
                err: ErrorCode::HttpStatus as i32,
                err_code: 403,
            })),
        ),
        (
            "cooldown_cleared",
            record(Event::CooldownCleared(CooldownCleared {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                kind: CooldownKind::IpFail as i32,
                key_display: "149.154.167.220".to_string(),
            })),
        ),
        (
            "cooldown_skipped",
            record(Event::CooldownSkipped(CooldownSkipped {
                ctx: Some(Ctx::new(2, true, Tier::Mtproto)),
                kind: CooldownKind::UpstreamFail as i32,
                key_display: "proxy.example:443".to_string(),
            })),
        ),
        (
            "pool_hit",
            record(Event::PoolHit(PoolHit {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                left: 3,
            })),
        ),
        (
            "pool_miss",
            record(Event::PoolMiss(PoolMiss {
                ctx: Some(Ctx::new(2, true, Tier::Cfworker)),
            })),
        ),
        (
            "pool_refill",
            record(Event::PoolRefill(PoolRefill {
                ctx: Some(Ctx::new(203, false, Tier::Cfproxy)),
                added: 4,
                ready: 4,
                dur_ms: 850,
            })),
        ),
        (
            "tls_handshake",
            record(Event::TlsHandshake(TlsHandshake {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                kind: HandshakeKind::Full as i32,
                dur_ns: 180_000_000,
                err: ErrorCode::Unspecified as i32,
                errno: 0,
            })),
        ),
        (
            "relay_init_retries",
            record(Event::RelayInitRetries(RelayInitRetries { n: 3 })),
        ),
        (
            "accept_error",
            record(Event::AcceptError(AcceptError {
                errno: 24,
                backoff_ms: 100,
                err: ErrorCode::Resource as i32,
            })),
        ),
        (
            "fd_snapshot",
            record(Event::FdSnapshot(FdSnapshot {
                open: 214,
                soft_limit: 1024,
                sem_avail: 810,
            })),
        ),
        (
            "probe_result",
            record(Event::ProbeResult(ProbeResult {
                kind: ProbeKind::CfDomain as i32,
                target: "cf.example.com".to_string(),
                ok: false,
                dur_ns: 90_000_000,
                err: ErrorCode::HttpStatus as i32,
                err_code: 502,
            })),
        ),
        (
            "log_overflow",
            record(Event::LogOverflow(LogOverflow {
                dropped: 12,
                window_ns: 2_000_000_000,
            })),
        ),
        (
            "startup_summary",
            record(Event::StartupSummary(StartupSummary {
                version: env!("CARGO_PKG_VERSION").to_string(),
                listen: "127.0.0.1:17443".to_string(),
                dc_ips: (1..=5)
                    .map(|dc| DcIp {
                        dc,
                        ip: format!("149.154.167.{dc}"),
                    })
                    .collect(),
                tiers: ["ws", "cfproxy", "cfworker", "mtproto", "tcp"]
                    .iter()
                    .map(|t| t.to_string())
                    .collect(),
                categories: ["session", "routing", "pool", "cooldown", "tls", "accept"]
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
            })),
        ),
        (
            "pool_discard",
            record(Event::PoolDiscard(PoolDiscard {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                reason: DiscardReason::Stale as i32,
            })),
        ),
        (
            "warmup_complete",
            record(Event::WarmupComplete(WarmupComplete {
                ready: 16,
                dur_ms: 1_200,
            })),
        ),
        (
            "attempt_skipped",
            record(Event::AttemptSkipped(AttemptSkipped {
                ctx: Some(Ctx::new(2, true, Tier::Mtproto)),
                tier: Tier::Mtproto as i32,
                reason: Reason::Pinned as i32,
            })),
        ),
        (
            "domain_list_fetched",
            record(Event::DomainListFetched(DomainListFetched {
                source: DomainSource::Github as i32,
                count: 5,
                err: ErrorCode::Unspecified as i32,
                err_code: 0,
            })),
        ),
        (
            "shutdown",
            record(Event::Shutdown(Shutdown {
                phase: ShutdownPhase::Requested as i32,
                signal: ShutdownSignal::Term as i32,
            })),
        ),
    ]
}

fn sample(name: &str) -> LogRecord {
    samples()
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("no sample named {name}"))
        .1
}

#[test]
fn every_event_variant_round_trips() {
    let samples = samples();
    assert_eq!(samples.len(), 22, "one sample per oneof variant");

    for (name, record) in samples {
        let encoded = record.encode_to_vec();
        let decoded = LogRecord::decode(encoded.as_slice())
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
        assert_eq!(decoded, record, "{name} did not survive the round trip");
        assert!(decoded.event.is_some(), "{name} lost its event");
    }
}

#[test]
fn every_field_survives_the_round_trip_individually() {
    // The whole-record comparison above is only as good as the fixture behind
    // it: a sample that quietly lost a field would make its test vacuous. These
    // are the values the size, mask and split assertions depend on.
    match sample("session_opened").event.unwrap() {
        Event::SessionOpened(e) => {
            let peer = e.peer.expect("the peer is part of the fixture");
            assert_eq!(peer.addr, vec![203, 0, 113, 5]);
            assert_eq!(peer.port, 51234);
            let ctx = e.ctx.expect("the session's own facts are part of it");
            assert_eq!((ctx.dc, ctx.is_media), (2, false));
        }
        other => panic!("wrong variant: {other:?}"),
    }
    match sample("session_closed").event.unwrap() {
        Event::SessionClosed(e) => {
            assert_eq!((e.bytes_up, e.bytes_down), (1 << 20, 1 << 22));
            assert_eq!(e.closed_by, ClosedBy::Upstream as i32);
            assert_eq!(e.dur_ms, 120_000);
            assert_eq!(e.via, "kws2.web.telegram.org");
            let ctx = e.ctx.expect("the session's own facts are part of it");
            assert_eq!((ctx.dc, ctx.is_media, ctx.tier), (2, true, Tier::Ws as i32));
        }
        other => panic!("wrong variant: {other:?}"),
    }
    match sample("tier_attempt").event.unwrap() {
        Event::TierAttempt(e) => {
            assert_eq!(e.host, "cf.example.com");
            assert_eq!(e.err, ErrorCode::TcpConnect as i32);
            assert_eq!(e.err_code, 0);
            assert_eq!(e.errno, 113);
        }
        other => panic!("wrong variant: {other:?}"),
    }
    match sample("cooldown_armed").event.unwrap() {
        Event::CooldownArmed(e) => {
            assert_eq!(e.key_display, "kws2.web.telegram.org:443");
            assert_eq!(e.err_code, 403);
        }
        other => panic!("wrong variant: {other:?}"),
    }
    match sample("startup_summary").event.unwrap() {
        Event::StartupSummary(e) => {
            assert_eq!(e.dc_ips.len(), 5);
            assert_eq!(e.dc_ips[4].ip, "149.154.167.5");
            assert_eq!(e.tiers.len(), 5);
            assert_eq!(e.categories.len(), 6);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn category_names_round_trip_and_cover_every_category() {
    // The names are read back by `--log-category` and printed by the startup
    // record, so one direction drifting from the other is a filter the operator
    // cannot use and a record they cannot read.
    for category in Category::ALL {
        assert_eq!(
            Category::from_name(category.name()),
            Some(category),
            "{} does not parse back",
            category.name()
        );
    }

    // `Unspecified` is the schema's zero, not a category: nothing emits it.
    assert_eq!(Category::ALL.len(), super::CATEGORY_COUNT - 1);
    assert_eq!(Category::from_name("unspecified"), None);
    assert_eq!(Category::from_name("nonsense"), None);
}

#[test]
fn level_names_are_the_ones_the_flags_spell() {
    assert_eq!(Level::Debug.name(), "debug");
    assert_eq!(Level::Info.name(), "info");
    assert_eq!(Level::Warn.name(), "warn");
    assert_eq!(Level::Error.name(), "error");
    // Present in the enum because proto3 needs a zero, and named so that a
    // record carrying it is readable rather than blank.
    assert_eq!(Level::Unspecified.name(), "unspecified");
}

/// The ladder's failure vocabulary is printed as well as recorded, and these
/// four strings are what it printed before the record existed. The rest have no
/// `tracing` line of their own.
#[test]
fn reason_names_are_the_ones_the_ladder_prints() {
    assert_eq!(Reason::NotInDcIp.as_str(), "not in --dc-ip config");
    assert_eq!(Reason::IpCooldown.as_str(), "IP in cooldown");
    assert_eq!(Reason::WsFail.as_str(), "WS failed");
    assert_eq!(Reason::Pinned.as_str(), "pinned");
}

#[test]
fn dc_bit_maps_the_documented_table() {
    assert_eq!(dc_bit(1), Some(0));
    assert_eq!(dc_bit(2), Some(1));
    assert_eq!(dc_bit(3), Some(2));
    assert_eq!(dc_bit(4), Some(3));
    assert_eq!(dc_bit(5), Some(4));
    assert_eq!(dc_bit(203), Some(5));

    // No collision between the six bits, and no bit outside the documented six.
    let mut seen = 0u32;
    for dc in [1, 2, 3, 4, 5, 203] {
        let bit = 1u32 << dc_bit(dc).unwrap();
        assert_eq!(seen & bit, 0, "dc {dc} shares a bit");
        seen |= bit;
    }
    assert_eq!(seen, 0b11_1111);

    // The artifact's formula underflows on these; they must be rejected, not
    // shifted into an unrelated slot.
    for absent in [0, 6, 202, 204, u32::MAX] {
        assert_eq!(dc_bit(absent), None, "dc {absent}");
    }
}

#[test]
fn header_masks_follow_the_records() {
    let mut records = vec![
        record(Event::SessionOpened(SessionOpened {
            ctx: Some(Ctx::new(2, true, Tier::Unspecified)),
            peer: None,
        })),
        record(Event::SessionClosed(SessionClosed {
            ctx: Some(Ctx::new(203, false, Tier::Ws)),
            closed_by: ClosedBy::Client as i32,
            bytes_up: 0,
            bytes_down: 0,
            dur_ms: 1,
            via: String::new(),
        })),
        record(Event::TlsHandshake(TlsHandshake {
            ctx: Some(Ctx::new(4, false, Tier::Ws)),
            kind: HandshakeKind::Full as i32,
            dur_ns: 1,
            err: ErrorCode::Unspecified as i32,
            errno: 0,
        })),
        record(Event::TierAttempt(TierAttempt {
            ctx: Some(Ctx::new(2, false, Tier::Ws)),
            host: String::new(),
            ok: true,
            dur_ns: 1,
            err: ErrorCode::Unspecified as i32,
            err_code: 0,
            errno: 0,
        })),
        // A record whose event never got set: counted, but contributing no bit.
        LogRecord {
            event: None,
            ..record(Event::PoolHit(PoolHit {
                ctx: Some(Ctx::new(1, false, Tier::Ws)),
                left: 0,
            }))
        },
        record(Event::PoolHit(PoolHit {
            ctx: Some(Ctx::new(1, false, Tier::Ws)),
            left: 0,
        })),
    ];

    for (i, ts_ns) in [300, 100, 500, 400, 200, 600].into_iter().enumerate() {
        records[i].ts_ns = ts_ns;
    }

    let batches = build_batch(&records);
    assert_eq!(batches.len(), 1);
    let header = batches[0].header.clone().unwrap();

    assert_eq!(header.record_count, 6);
    assert_eq!(header.ts_first_ns, 100);
    assert_eq!(header.ts_last_ns, 600);
    // session_opened 16, session_closed 17, tier_attempt 18, pool_hit 23,
    // tls_handshake 26 — with the eventless record's bit 4 staying clear.
    assert_eq!(
        header.kind_mask,
        (1 << 0) | (1 << 1) | (1 << 2) | (1 << 7) | (1 << 10)
    );
    // dc 1 → bit 0, dc 2 → bit 1, dc 4 → bit 3, dc 203 → bit 5: the DC of a
    // record now comes from its own context, so a handshake contributes its
    // session's DC like the rest.
    assert_eq!(header.dc_mask, 0b10_1011);
    // Only the dc 2 session is a media session.
    assert_eq!(header.dc_media_mask, 0b10);
    assert_eq!(header.conn_ids, vec![42]);
    assert_eq!(batches[0].records, records);
}

#[test]
fn split_respects_the_unique_conn_bound() {
    // Two rounds over the same 16 connections do not split: the bound is on
    // distinct connections, not on record count.
    let mut records: Vec<LogRecord> = (0..2)
        .flat_map(|_| {
            (0..16u64).map(|conn| {
                event_for(
                    conn,
                    Event::PoolMiss(PoolMiss {
                        ctx: Some(Ctx::new(2, false, Tier::Ws)),
                    }),
                )
            })
        })
        .collect();
    assert_eq!(build_batch(&records).len(), 1);

    // A seventeenth connection in the middle splits where it appears, not at
    // the end and not on the record that happens to be last.
    records.insert(
        5,
        event_for(
            99,
            Event::PoolHit(PoolHit {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                left: 0,
            }),
        ),
    );

    let batches = build_batch(&records);
    assert_eq!(batches.len(), 2);
    for batch in &batches {
        let header = batch.header.as_ref().unwrap();
        assert!(
            header.conn_ids.len() <= BATCH_MAX_UNIQUE_CONNS,
            "{header:?}"
        );
        assert_eq!(header.record_count as usize, batch.records.len());
        assert!(
            header.conn_ids.windows(2).all(|w| w[0] < w[1]),
            "conn_ids must be sorted and deduplicated: {header:?}"
        );
    }
    assert_eq!(
        batches[0].header.as_ref().unwrap().record_count,
        16,
        "the split happens on the record that would introduce a seventeenth connection"
    );

    let flattened: Vec<u64> = batches
        .iter()
        .flat_map(|b| b.records.iter().map(|r| r.conn_id))
        .collect();
    assert_eq!(
        flattened,
        records.iter().map(|r| r.conn_id).collect::<Vec<_>>()
    );
}

#[test]
fn empty_input_makes_no_batches() {
    assert!(build_batch(&[]).is_empty());
}

#[test]
fn truncated_records_error_instead_of_panicking() {
    let encoded = sample("session_closed").encode_to_vec();

    // A prefix that ends inside the fixed64 timestamp cannot be a record.
    assert!(LogRecord::decode(&encoded[..3]).is_err());
    // Field 2 is a varint; one whose continuation bit is set at the end of the
    // buffer is not a value.
    assert!(LogRecord::decode([0x10u8, 0x80].as_slice()).is_err());

    // Whatever the cut, decoding is total: no index-out-of-bounds, no panic.
    for cut in 0..encoded.len() {
        let _ = LogRecord::decode(&encoded[..cut]);
    }
}

#[test]
fn unknown_enum_values_are_preserved_as_integers() {
    // R7: a binary that knows fewer error codes than the writer must still be
    // able to read the file and report the number.
    let mut record = sample("tier_attempt");
    match record.event.as_mut().unwrap() {
        Event::TierAttempt(e) => {
            e.err = 99;
            e.err_code = 403;
        }
        other => panic!("wrong variant: {other:?}"),
    }

    assert!(ErrorCode::try_from(99).is_err(), "99 must be unknown here");
    let decoded = LogRecord::decode(record.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded, record);

    match decoded.event.unwrap() {
        Event::TierAttempt(e) => {
            assert_eq!(e.err, 99);
            assert_eq!(e.err_code, 403);
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // A code this build does know still resolves as one.
    match sample("tier_attempt").event.unwrap() {
        Event::TierAttempt(e) => {
            assert_eq!(ErrorCode::try_from(e.err), Ok(ErrorCode::TcpConnect));
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn unset_error_fields_do_not_reach_the_wire() {
    let attempt = |err: ErrorCode, err_code: u32| {
        record(Event::TierAttempt(TierAttempt {
            ctx: Some(Ctx::new(2, false, Tier::Ws)),
            host: "kws2.web.telegram.org".to_string(),
            ok: true,
            dur_ns: 120_000_000,
            err: i32::from(err),
            err_code,
            errno: 0,
        }))
    };

    // `ok` is held fixed so the difference is attributable to the error fields
    // alone — and `ok` is a bool, so it is itself omitted when false.
    let clean = attempt(ErrorCode::Unspecified, 0);
    let failed = attempt(ErrorCode::HttpRedirect, 302);

    // proto3 does not write a zero-valued scalar, so the successful attempt
    // pays for neither field: the difference is exactly `err = 7` (one-byte key,
    // one byte of value) and `err_code = 302` (one-byte key, two bytes).
    assert_eq!(
        failed.encoded_len() - clean.encoded_len(),
        5,
        "unset error fields must not reach the wire"
    );
}

#[test]
fn encoded_sizes_fit_the_storage_budget() {
    let mut sizes: Vec<(&'static str, usize)> = samples()
        .into_iter()
        .map(|(name, record)| (name, record.encoded_len()))
        .collect();
    sizes.sort_by_key(|(_, size)| std::cmp::Reverse(*size));

    println!("encoded record size by variant:");
    for (name, size) in &sizes {
        println!("  {size:>4} B  {name}");
    }
    let total: usize = sizes.iter().map(|(_, s)| s).sum();
    println!("  {:>4} B  mean", total / sizes.len());

    let size_of = |name: &str| {
        sizes
            .iter()
            .find(|(n, _)| *n == name)
            .expect("sample exists")
            .1
    };

    // The budget in §1.2 of the plan: one record per session is what a day is
    // made of, and at 5 ev/s a day's worth has to stay inside the retention
    // estimate.
    assert!(
        size_of("session_closed") < 80,
        "session_closed grew to {} B",
        size_of("session_closed")
    );
    // A startup summary is the largest record by construction and is written
    // once per process; the ceiling keeps a future field from making the shape
    // of the file depend on the banner.
    assert!(
        size_of("startup_summary") < 512,
        "startup_summary grew to {} B",
        size_of("startup_summary")
    );
}

fn event_for(conn_id: u64, event: Event) -> LogRecord {
    LogRecord {
        conn_id,
        ..record(event)
    }
}

// ── Pipeline ───────────────────────────────────────────────────────────────

fn pool_hit(dc: u32) -> Event {
    Event::PoolHit(PoolHit {
        ctx: Some(Ctx::new(dc, false, Tier::Ws)),
        left: 0,
    })
}

/// What a sink was asked to write, kept for the test to inspect.
#[derive(Default)]
struct Recording {
    batches: StdMutex<Vec<LogBatch>>,
    attempts: AtomicUsize,
    fail_next: AtomicBool,
}

impl Recording {
    fn attempts(&self) -> usize {
        self.attempts.load(Relaxed)
    }

    fn batch_count(&self) -> usize {
        self.batches.lock().unwrap().len()
    }

    fn batches(&self) -> Vec<LogBatch> {
        self.batches.lock().unwrap().clone()
    }
}

struct RecordingSink {
    shared: Arc<Recording>,
    notify: Option<UnboundedSender<LogBatch>>,
}

impl BatchSink for RecordingSink {
    fn write(&mut self, batch: &LogBatch) -> Result<(), WriterError> {
        self.shared.attempts.fetch_add(1, Relaxed);
        if self.shared.fail_next.swap(false, Relaxed) {
            return Err(WriterError::Io(std::io::Error::other(
                "the sink is having a bad day",
            )));
        }
        self.shared.batches.lock().unwrap().push(batch.clone());
        if let Some(notify) = &self.notify {
            let _ = notify.send(batch.clone());
        }
        Ok(())
    }
}

fn recording() -> (RecordingSink, Arc<Recording>, UnboundedReceiver<LogBatch>) {
    let shared = Arc::new(Recording::default());
    let (notify, batches) = unbounded_channel();
    let sink = RecordingSink {
        shared: Arc::clone(&shared),
        notify: Some(notify),
    };
    (sink, shared, batches)
}

/// Settings with a deliberately long interval, so that only the behaviour under
/// test — a full batch, a warning, a shutdown — can cause a flush.
fn quiet(batch_max: usize) -> Settings {
    Settings {
        batch_max,
        flush_interval: Duration::from_secs(60),
        ..Settings::default()
    }
}

async fn next_batch(batches: &mut UnboundedReceiver<LogBatch>) -> LogBatch {
    tokio::time::timeout(Duration::from_secs(5), batches.recv())
        .await
        .expect("the writer flushed within 5 s")
        .expect("the sink keeps its notifier alive")
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition never became true");
}

/// A runtime that never polls the writer task, so that everything the producers
/// do is observable without a race.
fn unpolled_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
}

#[tokio::test]
async fn a_full_batch_is_written_as_one_batch() {
    let (sink, shared, mut batches) = recording();
    let handle = start(sink, quiet(DEFAULT_BATCH_MAX));

    for _ in 0..DEFAULT_BATCH_MAX {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(2));
    }

    let batch = next_batch(&mut batches).await;
    assert_eq!(batch.records.len(), DEFAULT_BATCH_MAX);
    assert_eq!(
        batch.header.expect("every batch has a header").record_count as usize,
        DEFAULT_BATCH_MAX
    );
    assert_eq!(shared.batch_count(), 1);
    assert_eq!(handle.dropped(), 0);

    handle.shutdown().await;
}

#[tokio::test]
async fn a_lone_record_is_flushed_by_the_interval() {
    let (sink, _shared, mut batches) = recording();
    let handle = start(
        sink,
        Settings {
            flush_interval: Duration::from_millis(100),
            ..quiet(DEFAULT_BATCH_MAX)
        },
    );

    // The interval is bounded on both sides: the default is what the operator
    // gets, and it is the reason a record cannot sit unwritten for longer than
    // the window a post-mortem cares about.
    assert_eq!(Settings::default().flush_interval, Duration::from_secs(2));
    handle.emit(1, Category::Routing, Level::Info, pool_hit(2));

    let batch = next_batch(&mut batches).await;
    assert_eq!(batch.records.len(), 1);

    handle.shutdown().await;
}

#[tokio::test]
async fn a_warning_flushes_at_once_when_asked_to() {
    let (sink, _shared, mut batches) = recording();
    let handle = start(
        sink,
        Settings {
            flush_on_warn: true,
            ..quiet(DEFAULT_BATCH_MAX)
        },
    );

    handle.emit(
        1,
        Category::Accept,
        Level::Warn,
        Event::AcceptError(AcceptError {
            errno: 24,
            backoff_ms: 100,
            err: ErrorCode::Resource as i32,
        }),
    );

    let batch = next_batch(&mut batches).await;
    assert_eq!(batch.records.len(), 1);

    handle.shutdown().await;
}

#[tokio::test]
async fn a_warning_waits_for_the_interval_when_not_asked_to() {
    let (sink, shared, mut batches) = recording();
    let handle = start(sink, quiet(DEFAULT_BATCH_MAX));

    handle.emit(
        1,
        Category::Accept,
        Level::Warn,
        Event::AcceptError(AcceptError {
            errno: 24,
            backoff_ms: 100,
            err: ErrorCode::Resource as i32,
        }),
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(200), batches.recv())
            .await
            .is_err(),
        "nothing may be written before the interval"
    );
    assert_eq!(shared.batch_count(), 0);

    handle.shutdown().await;
}

#[test]
fn the_batch_buffer_is_allocated_once_and_reused() {
    let (sink, shared, _batches) = recording();
    let mut writer = Writer::new(sink, DEFAULT_BATCH_MAX);
    let capacity = writer.buffered_capacity();
    assert_eq!(capacity, DEFAULT_BATCH_MAX);

    for _ in 0..10 {
        for _ in 0..DEFAULT_BATCH_MAX {
            writer.push(event_for(1, pool_hit(2)));
        }
        assert_eq!(writer.flush().expect("the sink accepts"), DEFAULT_BATCH_MAX);
    }

    assert_eq!(shared.batch_count(), 10);
    assert_eq!(
        writer.buffered_capacity(),
        capacity,
        "the buffer was reallocated mid-flight"
    );
}

#[test]
fn a_full_channel_drops_only_what_does_not_fit() {
    // The writer task is spawned but never polled, so the channel is the only
    // thing consuming anything, and the arithmetic is exact.
    let runtime = unpolled_runtime();
    let (sink, _shared, _batches) = recording();
    let handle = runtime.block_on(async { start(sink, Settings::default()) });

    for i in 0..CHANNEL_CAPACITY {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(i as u32));
    }
    assert_eq!(
        handle.dropped(),
        0,
        "the channel takes exactly its capacity"
    );

    handle.emit(1, Category::Routing, Level::Info, pool_hit(2));
    assert_eq!(handle.dropped(), 1);
    handle.emit(1, Category::Routing, Level::Info, pool_hit(2));
    assert_eq!(handle.dropped(), 2);
}

#[test]
fn dropped_records_are_reported_at_the_next_flush() {
    // Emitted while the writer is not being polled at all, so every record past
    // the channel's capacity is dropped and counted; then the runtime is given
    // a moment to run the writer, whose next flush has to say so.
    let runtime = unpolled_runtime();
    let (sink, shared, _batches) = recording();
    let handle = runtime.block_on(async {
        start(
            sink,
            Settings {
                flush_interval: Duration::from_millis(50),
                ..Settings::default()
            },
        )
    });

    for i in 0..CHANNEL_CAPACITY + 5 {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(i as u32));
    }
    assert_eq!(handle.dropped(), 5);

    runtime.block_on(async {
        for _ in 0..50 {
            if handle.dropped() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let reported = shared
        .batches()
        .iter()
        .flat_map(|batch| batch.records.iter())
        .find_map(|record| match &record.event {
            Some(Event::LogOverflow(overflow)) => Some(overflow.dropped),
            _ => None,
        });
    assert_eq!(reported, Some(5));
    assert_eq!(handle.dropped(), 0, "the report takes the counter");

    runtime.block_on(handle.shutdown());
}

#[tokio::test]
async fn shutdown_flushes_what_is_buffered_before_it_returns() {
    let (sink, shared, mut batches) = recording();
    let handle = start(sink, quiet(DEFAULT_BATCH_MAX));

    for _ in 0..3 {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(2));
    }
    handle.shutdown().await;

    assert_eq!(
        shared.batch_count(),
        1,
        "the flush happened during shutdown"
    );
    assert_eq!(next_batch(&mut batches).await.records.len(), 3);
}

#[tokio::test]
async fn a_sink_that_fails_does_not_stop_the_writer() {
    let (sink, shared, mut batches) = recording();
    shared.fail_next.store(true, Relaxed);
    let handle = start(sink, quiet(DEFAULT_BATCH_MAX));

    for _ in 0..DEFAULT_BATCH_MAX {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(2));
    }
    wait_until(|| shared.attempts() == 1).await;
    assert_eq!(shared.batch_count(), 0, "the failed batch is gone");

    for _ in 0..DEFAULT_BATCH_MAX {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(2));
    }
    assert_eq!(
        next_batch(&mut batches).await.records.len(),
        DEFAULT_BATCH_MAX
    );
    assert_eq!(shared.attempts(), 2);

    handle.shutdown().await;
}

#[tokio::test]
async fn emitting_outside_a_scope_is_a_no_op() {
    assert!(!inside_scope());
    assert!(!enabled(Category::Routing, Level::Info));
    emit(Category::Routing, Level::Info, pool_hit(2));

    let (sink, shared, _batches) = recording();
    let handle = Arc::new(start(sink, quiet(DEFAULT_BATCH_MAX)));

    scope(7, Arc::clone(&handle), async {
        assert!(inside_scope());
        assert!(enabled(Category::Routing, Level::Info));
        emit(Category::Routing, Level::Info, pool_hit(2));
    })
    .await;

    assert!(!inside_scope(), "the scope must not outlive its future");
    handle.shutdown().await;

    let batches = shared.batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(
        batches[0].records[0].conn_id, 7,
        "the record carries the scoped session, not the emit site's"
    );
}

#[tokio::test]
async fn the_macro_builds_the_payload_and_skips_what_the_filter_drops() {
    let (sink, shared, _batches) = recording();
    let handle = Arc::new(start(sink, quiet(DEFAULT_BATCH_MAX)));
    let dc = 2;
    let is_media = false;

    scope(3, Arc::clone(&handle), async {
        crate::log_event!(
            Category::Routing,
            Level::Info,
            Event::PoolHit {
                ctx: Some(Ctx::new(dc, is_media, Tier::Ws)),
                left: 0,
            }
        );
        crate::log_event!(
            Category::Routing,
            Level::Debug,
            Event::PoolMiss {
                ctx: Some(Ctx::new(dc, is_media, Tier::Ws)),
            },
        );
    })
    .await;

    handle.shutdown().await;

    let batches = shared.batches();
    assert_eq!(batches.len(), 1, "the debug record must not be written");
    assert_eq!(batches[0].records.len(), 1);
    assert_eq!(batches[0].records[0].level, Level::Info as i32);
}

#[tokio::test]
async fn a_category_can_be_quieter_than_the_global_level() {
    let (sink, shared, _batches) = recording();
    let mut settings = quiet(DEFAULT_BATCH_MAX);
    settings.disk[Category::Pool as usize] = Filter::at(Level::Warn);
    let handle = Arc::new(start(sink, settings));

    scope(1, Arc::clone(&handle), async {
        crate::log_event!(
            Category::Pool,
            Level::Info,
            Event::PoolHit {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                left: 0,
            }
        );
        crate::log_event!(
            Category::Routing,
            Level::Info,
            Event::PoolHit {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                left: 0,
            }
        );
        crate::log_event!(
            Category::Pool,
            Level::Warn,
            Event::PoolHit {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                left: 0,
            }
        );
    })
    .await;

    handle.shutdown().await;

    let batches = shared.batches();
    let kept: Vec<i32> = batches
        .iter()
        .flat_map(|batch| batch.records.iter())
        .map(|record| record.category)
        .collect();
    assert_eq!(
        kept,
        vec![Category::Routing as i32, Category::Pool as i32],
        "the pool's info record is below its own threshold, its warning is not"
    );
}

#[test]
fn a_filter_keeps_its_floor_and_everything_above_it() {
    let info = Filter::at(Level::Info);
    assert!(info.keeps(Level::Info));
    assert!(info.keeps(Level::Warn));
    assert!(info.keeps(Level::Error));
    assert!(!info.keeps(Level::Debug));
    assert_eq!(info.floor(), Some(Level::Info));
    assert_eq!(info.name(), "info");
    assert!(!info.is_off());

    assert!(!Filter::off().keeps(Level::Error));
    assert_eq!(Filter::off().floor(), None);
    assert_eq!(Filter::off().name(), "off");
    assert!(Filter::off().is_off());
}

#[test]
fn the_gate_is_the_union_of_the_three_policies() {
    let runtime = unpolled_runtime();

    // Disk at warn, text at info, ring off: the union is info, so an info
    // payload is built for the text view even though the segment drops it.
    let (sink, _shared, _batches) = recording();
    let settings = Settings {
        disk: [Filter::at(Level::Warn); CATEGORY_COUNT],
        text: Filter::at(Level::Info),
        ring: Filter::off(),
        ..Settings::default()
    };
    let handle = runtime.block_on(async { start(sink, settings) });
    assert!(handle.enabled(Category::Pool, Level::Info));
    assert!(!handle.enabled(Category::Pool, Level::Debug));

    // Only the ring wants debug, and that alone is enough.
    let (sink, _shared, _batches) = recording();
    let settings = Settings {
        disk: [Filter::at(Level::Warn); CATEGORY_COUNT],
        text: Filter::off(),
        ring: Filter::at(Level::Debug),
        ..Settings::default()
    };
    let handle = runtime.block_on(async { start(sink, settings) });
    assert!(handle.enabled(Category::Pool, Level::Debug));

    // Nobody wants it: the payload is not built at all.
    let (sink, _shared, _batches) = recording();
    let settings = Settings {
        disk: [Filter::at(Level::Warn); CATEGORY_COUNT],
        text: Filter::off(),
        ring: Filter::off(),
        ..Settings::default()
    };
    let handle = runtime.block_on(async { start(sink, settings) });
    assert!(!handle.enabled(Category::Pool, Level::Debug));
}

#[tokio::test]
async fn a_record_the_segment_does_not_keep_never_reaches_it() {
    // The counterpart of the union above: widening the gate must not widen the
    // file, or the three policies would be one policy with extra steps.
    let (sink, shared, _batches) = recording();
    let mut settings = quiet(DEFAULT_BATCH_MAX);
    settings.disk = [Filter::off(); CATEGORY_COUNT];
    settings.text = Filter::at(Level::Info);
    let handle = Arc::new(start(sink, settings));

    scope(1, Arc::clone(&handle), async {
        assert!(enabled(Category::Routing, Level::Info));
        crate::log_event!(
            Category::Routing,
            Level::Info,
            Event::PoolHit {
                ctx: Some(Ctx::new(2, false, Tier::Ws)),
                left: 0,
            }
        );
    })
    .await;

    handle.shutdown().await;

    assert!(
        shared.batches().is_empty(),
        "the text view's record must not be written to the segment"
    );
}

#[test]
fn session_ids_start_at_one_and_never_repeat_zero() {
    let runtime = unpolled_runtime();
    let (sink, _shared, _batches) = recording();
    let handle = runtime.block_on(async { start(sink, Settings::default()) });

    assert_eq!(handle.next_conn_id(), 1);
    assert_eq!(handle.next_conn_id(), 2);
    assert_eq!(handle.next_conn_id(), 3);
}

#[test]
fn the_channel_fits_the_router_ram_budget() {
    let record = std::mem::size_of::<LogRecord>();
    let queue = record * CHANNEL_CAPACITY;
    println!(
        "LogRecord {record} B, Event {} B, queue {queue} B for {CHANNEL_CAPACITY} records",
        std::mem::size_of::<Event>()
    );

    // The whole reason the channel is not deeper. Every record carries its
    // payload inline — boxing the one large variant would add an allocation to
    // the emit path — so the depth is a memory decision, not a throughput one.
    assert!(
        queue < 256 * 1024,
        "{CHANNEL_CAPACITY} records of {record} B is {queue} B of a router's RAM"
    );
}

#[test]
fn emit_does_not_wait_for_the_writer() {
    // The writer task is never polled, so the channel has room for exactly its
    // capacity and every send succeeds: this measures the emit path itself —
    // filter, timestamp, sequence number, non-blocking send — with no sink
    // work behind it to hide behind. A fresh handle per round keeps the
    // channel from filling up.
    const ROUNDS: u32 = 8;
    let runtime = unpolled_runtime();
    let mut elapsed = Duration::ZERO;
    let mut dropped = 0;

    for _ in 0..ROUNDS {
        let (sink, _shared, _batches) = recording();
        let handle = runtime.block_on(async { start(sink, Settings::default()) });

        let started = Instant::now();
        for _ in 0..CHANNEL_CAPACITY {
            handle.emit(1, Category::Routing, Level::Info, pool_hit(2));
        }
        elapsed += started.elapsed();
        dropped += handle.dropped();
    }

    let emitted = ROUNDS as usize * CHANNEL_CAPACITY;
    let per_record = elapsed.as_nanos() as f64 / emitted as f64;
    println!("emit: {per_record:.0} ns/record over {emitted} records, {dropped} dropped");

    assert_eq!(dropped, 0, "a dropped record measures the fast path");
    assert!(
        per_record < 20_000.0,
        "emit took {per_record:.0} ns/record, three orders of magnitude off"
    );
}

// ── Storage ────────────────────────────────────────────────────────────────

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "log-zstd")]
use super::storage::Compression;
use super::storage::{self, DurabilityMode, FileSink, Options};

/// A directory under the system temp dir, removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("tgws-log-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("a writable temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .expect("the directory exists")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `(ts_first_ns, seq)` is the `STOR:main` key, so every synthetic batch needs
/// its own: a fixture that reused one would silently overwrite batches and make
/// half these tests pass for the wrong reason.
fn next_stamp() -> (u64, u32) {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    let n = NEXT.fetch_add(1, Relaxed) as u64;
    (1_700_000_000_000_000_000 + n, n as u32)
}

/// A batch of `conn_id`s, one record each, the way the writer would build it.
fn batch_of(conn_ids: &[u64]) -> LogBatch {
    let (ts_ns, seq) = next_stamp();
    let records: Vec<LogRecord> = conn_ids
        .iter()
        .map(|conn| {
            let mut record = event_for(*conn, pool_hit(2));
            record.ts_ns = ts_ns;
            record.seq = seq;
            record
        })
        .collect();
    let mut batches = build_batch(&records);
    assert_eq!(batches.len(), 1, "the fixture fits in one batch");
    batches.remove(0)
}

/// A batch with the variety real traffic has: mixed event kinds, different
/// sessions, counters that move. A fixture of 256 identical records would
/// compress to almost nothing and flatter the ratio this test exists to report.
#[cfg(feature = "log-zstd")]
fn rich_batch() -> LogBatch {
    let (ts_ns, seq) = next_stamp();
    // xorshift64: deterministic across runs, which a random generator would not
    // be, and varied enough that zstd sees more than one record shape.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let records: Vec<LogRecord> = (0..DEFAULT_BATCH_MAX)
        .map(|i| {
            let r = next();
            let event = match r % 5 {
                0 => Event::SessionClosed(SessionClosed {
                    ctx: Some(Ctx::new(1 + (r % 5) as u32, r % 2 == 0, Tier::Ws)),
                    closed_by: ClosedBy::Client as i32,
                    bytes_up: r % 1_000_000,
                    bytes_down: r % 4_000_000,
                    dur_ms: (r % 600_000) as u32,
                    via: format!("kws{}.web.telegram.org", 1 + r % 5),
                }),
                1 => Event::TierAttempt(TierAttempt {
                    ctx: Some(Ctx::new(1 + (r % 5) as u32, r % 2 == 0, Tier::Cfproxy)),
                    host: format!("cf{}.example.com", 1 + r % 3),
                    ok: r % 3 == 0,
                    dur_ns: r % 40_000_000_000,
                    err: ErrorCode::TlsTimeout as i32,
                    err_code: (r % 600) as u32,
                    errno: (r % 120) as i32,
                }),
                2 => Event::CooldownArmed(CooldownArmed {
                    ctx: Some(Ctx::new(1 + (r % 5) as u32, r % 2 == 0, Tier::Ws)),
                    kind: CooldownKind::WsFail as i32,
                    key_display: format!("kws{}.web.telegram.org:443", 1 + r % 5),
                    dur_s: 300,
                    err: ErrorCode::TlsTimeout as i32,
                    err_code: 0,
                }),
                3 => Event::PoolHit(PoolHit {
                    ctx: Some(Ctx::new(1 + (r % 5) as u32, r % 2 == 0, Tier::Ws)),
                    left: (r % 8) as u32,
                }),
                _ => Event::TlsHandshake(TlsHandshake {
                    ctx: Some(Ctx::new(1 + (r % 5) as u32, r % 2 == 0, Tier::Ws)),
                    kind: HandshakeKind::Full as i32,
                    dur_ns: r % 400_000_000,
                    err: ErrorCode::Unspecified as i32,
                    errno: 0,
                }),
            };

            let mut record = event_for(1 + r % 16, event);
            record.ts_ns = ts_ns + i as u64 * 1_000_000;
            record.seq = seq + i as u32;
            record
        })
        .collect();

    build_batch(&records).remove(0)
}

fn open_sink(dir: &Path, options: Options) -> FileSink {
    FileSink::open(dir, options).expect("the sink opens")
}

#[test]
fn a_segment_from_another_schema_is_refused_rather_than_appended_to() {
    use redb::{Database, TableDefinition};

    const META: TableDefinition<&str, &[u8]> = TableDefinition::new("STOR:meta");

    let dir = TempDir::new("schema-guard");
    let path = dir
        .path()
        .join(format!("{}.redb", storage::day_name(storage::today())));

    // A segment this build wrote and then left is the ordinary restart: the
    // same day's file is reopened and appended to.
    drop(open_sink(dir.path(), Options::default()));
    open_sink(dir.path(), Options::default());

    // Rewrite its fingerprint into one no build of this source ever wrote, which
    // is what a segment from an older schema looks like from here.
    let db = Database::open(&path).expect("the segment reopens for the edit");
    let write = db.begin_write().expect("a write transaction");
    {
        let mut table = write.open_table(META).expect("the meta table");
        table
            .insert("schema_hash", 0u64.to_le_bytes().as_slice())
            .expect("the fingerprint is written");
    }
    write.commit().expect("the edit commits");
    drop(db);

    let error = match FileSink::open(dir.path(), Options::default()) {
        Ok(_) => panic!("a segment from another schema must not be appended to"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(message.contains("different log schema"), "{message}");
    assert!(message.contains("move it out"), "{message}");
}

#[test]
fn a_segment_round_trips_every_batch() {
    let dir = TempDir::new("roundtrip");
    let day = storage::today();
    let mut sink = open_sink(dir.path(), Options::default());

    let first = batch_of(&[1, 2, 3]);
    let second = batch_of(&[4]);
    sink.write(&first).expect("the batch is written");
    sink.write(&second).expect("the batch is written");
    drop(sink);

    let read_back = storage::iter_batches(dir.path(), &storage::day_name(day)).expect("readable");
    assert_eq!(read_back, vec![first, second]);
}

#[test]
fn the_by_conn_index_returns_exactly_one_session() {
    let dir = TempDir::new("byconn");
    let day = storage::today();
    let mut sink = open_sink(dir.path(), Options::default());

    let mine = batch_of(&[7]);
    sink.write(&mine).expect("written");
    sink.write(&batch_of(&[8, 9])).expect("written");
    sink.write(&batch_of(&[7, 10])).expect("written");
    drop(sink);

    let date = storage::day_name(day);
    let mine_back = storage::iter_conn_batches(dir.path(), &date, 7).expect("readable");
    assert_eq!(mine_back.len(), 2, "two batches mention connection 7");
    assert_eq!(mine_back[0], mine);
    assert!(
        mine_back
            .iter()
            .all(|batch| batch.header.as_ref().expect("header").conn_ids.contains(&7))
    );

    assert_eq!(
        storage::iter_conn_batches(dir.path(), &date, 8)
            .expect("readable")
            .len(),
        1
    );
    assert!(
        storage::iter_conn_batches(dir.path(), &date, 99)
            .expect("readable")
            .is_empty()
    );
}

#[test]
fn a_restart_inside_the_same_day_appends_to_the_same_segment() {
    let dir = TempDir::new("restart");
    let day = storage::today();

    let first = batch_of(&[1]);
    let mut sink = open_sink(dir.path(), Options::default());
    sink.write(&first).expect("written");
    drop(sink);

    let second = batch_of(&[2]);
    let mut sink = open_sink(dir.path(), Options::default());
    sink.write(&second).expect("written");
    drop(sink);

    assert_eq!(
        dir.entries(),
        vec![format!("{}.redb", storage::day_name(day))],
        "one segment for the day, not one per run"
    );
    assert_eq!(
        storage::iter_batches(dir.path(), &storage::day_name(day)).expect("readable"),
        vec![first, second]
    );
}

#[test]
fn both_durability_modes_survive_a_clean_close() {
    for mode in [DurabilityMode::Eventual, DurabilityMode::Immediate] {
        let dir = TempDir::new("durability");
        let day = storage::today();
        let batch = batch_of(&[1]);

        let mut sink = open_sink(
            dir.path(),
            Options {
                durability: mode,
                ..Options::default()
            },
        );
        sink.write(&batch).expect("written");
        drop(sink);

        assert_eq!(
            storage::iter_batches(dir.path(), &storage::day_name(day)).expect("readable"),
            vec![batch],
            "{mode:?} lost a batch on a clean close"
        );
    }
}

#[test]
fn a_record_emitted_while_the_writer_is_stopping_still_reaches_the_sink() {
    // The accept loop stops before a session that is still tearing down, so the
    // moment between "stop" and "the writer exits" is exactly when the last
    // session's close record is produced. Dropping it would make the end of a
    // session the one thing a clean stop is allowed to lose.
    let runtime = unpolled_runtime();
    let (sink, _shared, mut batches) = recording();
    let handle = Arc::new(runtime.block_on(async { start(sink, quiet(DEFAULT_BATCH_MAX)) }));
    let late = Arc::clone(&handle);

    runtime.block_on(async move {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            late.emit(9, Category::Session, Level::Info, pool_hit(2));
        });
        handle.shutdown().await;
    });

    let mut seen = 0;
    while let Ok(batch) = batches.try_recv() {
        seen += batch.records.len();
    }
    assert_eq!(seen, 1, "the record emitted during the stop was dropped");
}

#[cfg(not(feature = "log-zstd"))]
#[test]
fn a_build_without_zstd_names_the_build_that_could_read_a_compressed_batch() {
    // The framing byte is part of the on-disk format whatever this build can
    // do, so a compressed batch is recognised and explained: reporting it as
    // corruption would send the operator looking for damage that is not there.
    let error = storage::decode(&[1, 0x28, 0xb5, 0x2f, 0xfd, 0x00]).expect_err("no zstd here");
    let message = error.to_string();
    assert!(message.contains("log-zstd"), "{message}");
}

#[cfg(feature = "log-zstd")]
#[test]
fn zstd_shrinks_a_rich_batch_and_round_trips_it() {
    let batch = rich_batch();

    let raw = storage::encode(&batch, Compression::None).expect("encoded");
    let compressed = storage::encode(&batch, Compression::ZstdL1).expect("encoded");

    assert_eq!(storage::decode(&raw).expect("decoded"), batch);
    assert_eq!(storage::decode(&compressed).expect("decoded"), batch);
    assert_eq!(raw[0], 0, "the framing byte says raw");
    assert_eq!(compressed[0], 1, "the framing byte says zstd");
    assert!(
        compressed.len() < raw.len(),
        "zstd grew the batch: {} vs {} bytes",
        compressed.len(),
        raw.len()
    );

    println!(
        "batch: {} B raw, {} B zstd ({}%)",
        raw.len(),
        compressed.len(),
        compressed.len() * 100 / raw.len()
    );
}

#[cfg(feature = "log-zstd")]
#[test]
fn a_compressed_segment_reads_back_as_written() {
    let dir = TempDir::new("compressed");
    let day = storage::today();
    let batch = rich_batch();

    let mut sink = open_sink(
        dir.path(),
        Options {
            compress: Compression::ZstdL1,
            ..Options::default()
        },
    );
    sink.write(&batch).expect("written");
    drop(sink);

    assert_eq!(
        storage::iter_batches(dir.path(), &storage::day_name(day)).expect("readable"),
        vec![batch]
    );
}

#[test]
fn the_filesystem_gate_refuses_the_fat_family() {
    for refused in [
        "vfat", "msdos", "umsdos", "exfat", "ntfs", "ntfs3", "fuseblk", "hpfs",
    ] {
        assert!(
            !storage::carries_locks(refused),
            "{refused} must be refused"
        );
    }
    // Including the filesystems this container and its users actually run on:
    // overlayfs is Docker, tmpfs is /tmp, and the rest are what a USB stick
    // would be formatted with if it were formatted sensibly.
    for accepted in [
        "ext2",
        "ext3",
        "ext4",
        "xfs",
        "btrfs",
        "f2fs",
        "tmpfs",
        "overlay",
        "apfs",
        "hfs",
        "zfs",
        "some-future-fs",
    ] {
        assert!(
            storage::carries_locks(accepted),
            "{accepted} must be accepted"
        );
    }
}

#[test]
fn the_filesystem_gate_accepts_the_directory_this_test_runs_on() {
    let dir = TempDir::new("fsgate");
    storage::check_filesystem(dir.path()).expect("the temp dir is usable for logs");
    // And the gate is on the path the sink actually creates, not on the
    // directory name: a directory that does not exist yet still resolves to its
    // parent's filesystem.
    storage::check_filesystem(&dir.path().join("nested/then/deeper"))
        .expect("a directory that does not exist yet resolves to its parent");
}

#[test]
fn a_second_sink_on_the_same_directory_is_refused() {
    let dir = TempDir::new("conflict");
    let _first = open_sink(dir.path(), Options::default());

    let second = FileSink::open(dir.path(), Options::default());
    match second {
        Err(LogError::WriterConflict(path)) => {
            assert!(path.ends_with(format!("{}.redb", storage::day_name(storage::today()))));
        }
        Err(other) => panic!("expected a writer conflict, got {other}"),
        Ok(_) => panic!("a second writer took the segment"),
    }
}

#[test]
fn the_segment_records_its_provenance() {
    let dir = TempDir::new("meta");
    let date = storage::day_name(storage::today());
    drop(open_sink(dir.path(), Options::default()));

    let version = storage::meta(dir.path(), &date, "app_version")
        .expect("readable")
        .expect("app_version is written");
    assert_eq!(version, env!("CARGO_PKG_VERSION").as_bytes());

    assert_eq!(
        storage::meta(dir.path(), &date, "writer_protocol")
            .expect("readable")
            .expect("writer_protocol is written"),
        storage::WRITER_PROTOCOL.to_le_bytes()
    );
    assert_eq!(
        storage::meta(dir.path(), &date, "schema_hash")
            .expect("readable")
            .expect("schema_hash is written"),
        fingerprint().to_le_bytes()
    );
    assert!(
        storage::meta(dir.path(), &date, "created_ns")
            .expect("readable")
            .is_some()
    );
}

#[test]
fn the_fingerprint_follows_the_schema() {
    // Pinned so that a change to a field number, a tag or an enum value cannot
    // land without someone noticing that it moved.
    assert_eq!(
        fingerprint(),
        0xfcde_72a6_61a5_28b2_u64,
        "the wire format changed"
    );
}

#[test]
fn retention_deletes_expired_segments_and_nothing_else() {
    let dir = TempDir::new("retention");
    let today = storage::today();
    let mut expected = Vec::new();

    for age in 0..12 {
        let name = format!("{}.redb", storage::day_name(today - age));
        fs::write(dir.path().join(&name), b"").expect("a placeholder segment");
        if age < 7 {
            expected.push(name);
        }
    }
    fs::write(dir.path().join("notes.txt"), b"keep me").expect("a file that is not ours");

    drop(open_sink(
        dir.path(),
        Options {
            retention_days: 7,
            ..Options::default()
        },
    ));

    expected.push("notes.txt".to_string());
    expected.sort();
    assert_eq!(dir.entries(), expected, "seven days kept, the rest swept");
}

#[test]
fn retention_zero_keeps_everything() {
    let dir = TempDir::new("keepall");
    let today = storage::today();
    let ancient = format!("{}.redb", storage::day_name(today - 400));
    fs::write(dir.path().join(&ancient), b"").expect("a placeholder segment");

    drop(open_sink(
        dir.path(),
        Options {
            retention_days: 0,
            ..Options::default()
        },
    ));

    assert!(dir.entries().contains(&ancient));
}

#[test]
fn rotation_moves_to_the_next_day_without_losing_the_previous_one() {
    let dir = TempDir::new("rotation");
    let today = storage::today();
    let mut sink = open_sink(dir.path(), Options::default());

    let first = batch_of(&[1]);
    sink.write(&first).expect("written");
    sink.rotate(today + 1).expect("rotation opens the next day");
    let second = batch_of(&[2]);
    sink.write(&second).expect("written");
    drop(sink);

    assert_eq!(
        dir.entries(),
        vec![
            format!("{}.redb", storage::day_name(today)),
            format!("{}.redb", storage::day_name(today + 1)),
        ]
    );
    assert_eq!(
        storage::iter_batches(dir.path(), &storage::day_name(today)).expect("readable"),
        vec![first]
    );
    assert_eq!(
        storage::iter_batches(dir.path(), &storage::day_name(today + 1)).expect("readable"),
        vec![second]
    );
}

#[cfg(unix)]
#[test]
fn a_segment_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new("mode");
    let date = storage::day_name(storage::today());
    drop(open_sink(dir.path(), Options::default()));

    let mode = fs::metadata(dir.path().join(format!("{date}.redb")))
        .expect("the segment exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the segment holds every session's metadata");
}

#[test]
fn records_written_through_the_pipeline_are_readable_back() {
    let runtime = unpolled_runtime();
    let dir = TempDir::new("pipeline");
    let day = storage::today();
    let sink = open_sink(dir.path(), Options::default());
    let handle = runtime.block_on(async { start(sink, Settings::default()) });

    for conn in 1..=3 {
        for _ in 0..(DEFAULT_BATCH_MAX / 3) {
            handle.emit(conn, Category::Session, Level::Info, pool_hit(2));
        }
    }
    runtime.block_on(handle.shutdown());

    let batches = storage::iter_batches(dir.path(), &storage::day_name(day)).expect("readable");
    let records: usize = batches.iter().map(|batch| batch.records.len()).sum();
    assert_eq!(records, 3 * (DEFAULT_BATCH_MAX / 3));
    let conns: Vec<u64> = batches
        .iter()
        .flat_map(|batch| batch.records.iter().map(|record| record.conn_id))
        .collect();
    assert!(conns.contains(&1) && conns.contains(&2) && conns.contains(&3));
}

#[test]
fn an_empty_segment_reads_back_as_an_empty_day() {
    // redb creates a table on its first write, so a segment that never took a
    // record has no `STOR:main` at all. Refusing to read it would turn "nothing
    // happened today" into a corrupt-file error — and `--log-level error` over
    // a healthy proxy is exactly a day with nothing in it.
    let dir = TempDir::new("empty");
    let date = storage::day_name(storage::today());
    drop(open_sink(dir.path(), Options::default()));

    assert!(
        storage::iter_batches(dir.path(), &date)
            .expect("an empty day is readable")
            .is_empty()
    );
    assert!(
        storage::iter_conn_batches(dir.path(), &date, 1)
            .expect("an empty day is readable")
            .is_empty()
    );
}

#[test]
fn init_starts_a_writable_segment_from_the_public_entry_point() {
    // What the startup path calls, with none of the test's own plumbing in
    // between: `init` opens the directory, spawns the writer, and the record
    // comes back out of the file on the other side.
    let runtime = unpolled_runtime();
    let dir = TempDir::new("init");
    let day = storage::today();

    let handle = runtime
        .block_on(async { init(dir.path(), Settings::default(), Options::default()) })
        .expect("the sink starts");
    handle.emit(1, Category::Accept, Level::Info, pool_hit(2));
    runtime.block_on(handle.shutdown());

    let batches = storage::iter_batches(dir.path(), &storage::day_name(day)).expect("readable");
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.records.len())
            .sum::<usize>(),
        1
    );
}

#[test]
fn a_truncated_segment_is_refused_rather_than_half_read() {
    let dir = TempDir::new("truncated");
    let date = storage::day_name(storage::today());
    let mut sink = open_sink(dir.path(), Options::default());
    for conn in 1..=4 {
        sink.write(&batch_of(&[conn])).expect("written");
    }
    drop(sink);

    let path = dir.path().join(format!("{date}.redb"));
    let segment = fs::read(&path).expect("the segment exists");
    assert_eq!(
        storage::iter_batches(dir.path(), &date)
            .expect("the intact segment reads")
            .len(),
        4
    );

    // redb keeps its commit slots at the head of the file and the pages they
    // point at after them, so cutting the tail off does not leave the earlier
    // commits readable: the file stops being a database at all. That is the
    // behaviour worth pinning — the alternative is a repair that accepts the
    // damage and silently drops whatever it cannot reach.
    for divisor in [2, 4, 8, 16] {
        fs::write(&path, &segment[..segment.len() / divisor]).expect("truncated");
        let outcome = storage::iter_batches(dir.path(), &date);
        assert!(
            matches!(outcome, Err(LogError::Segment(_))),
            "a segment truncated to 1/{divisor} read back as {outcome:?}"
        );
    }
}

#[test]
#[ignore = "prints a segment for a human to read; run with --ignored --nocapture"]
fn dump_segment() {
    let Some(dir) = std::env::var_os("TG_DUMP_DIR") else {
        panic!("set TG_DUMP_DIR to the log directory to dump");
    };
    let dir = PathBuf::from(dir);
    let date =
        std::env::var("TG_DUMP_DATE").unwrap_or_else(|_| storage::day_name(storage::today()));

    for batch in storage::iter_batches(&dir, &date).expect("readable") {
        let header = batch.header.expect("header");
        println!(
            "batch ts={} records={} conns={:?}",
            header.ts_first_ns, header.record_count, header.conn_ids
        );
        for record in &batch.records {
            println!(
                "  seq={} conn={} level={} category={} {:?}",
                record.seq, record.conn_id, record.level, record.category, record.event
            );
        }
    }
}

/// The connection counter is 32 bits wide, because the MIPS release targets
/// have no 64-bit atomics, so a wrap is possible in principle and has to keep
/// the one property the log relies on: zero means "not a session".
#[test]
fn a_wrapped_connection_id_is_never_zero() {
    let counters = Counters::default();
    counters.conn.store(u32::MAX, Relaxed);

    assert_eq!(counters.next_conn(), u64::from(u32::MAX));
    assert_eq!(counters.next_conn(), 1, "the wrap skips the reserved zero");
    assert_eq!(counters.next_conn(), 2);
}
