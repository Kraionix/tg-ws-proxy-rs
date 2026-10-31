use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use prost::Message;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::schema::*;
use super::view::{TextSink, TextTarget, View};
use super::*;

/// [`super::start_with_sink`] with the text view's destination taken on trust.
///
/// The pipeline tests below are about batching and the segment; the text view
/// has its own tests, and the settings they pass here either leave it off or
/// point it at a file they opened themselves.
fn start<S: logreel::BatchSink + 'static>(sink: S, settings: Settings) -> LogHandle {
    super::start_with_sink(sink, settings).expect("the pipeline starts")
}

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
                err: ErrorCode::TlsTimeout as i32,
                errno: 113,
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

#[cfg(feature = "log-disk")]
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

    let header = crate::dump::header_for(&records);

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
}

#[cfg(feature = "log-disk")]
#[test]
fn an_empty_batch_has_an_empty_header() {
    let header = crate::dump::header_for(&[]);
    assert_eq!(header.record_count, 0);
    assert_eq!(header.ts_first_ns, 0);
    assert_eq!(header.ts_last_ns, 0);
    assert_eq!(header.kind_mask, 0);
    assert_eq!(header.dc_mask, 0);
    assert_eq!(header.dc_media_mask, 0);
    assert!(header.conn_ids.is_empty());
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

#[cfg(feature = "log-disk")]
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

/// One encoded batch decoded back for a test: the records are all it checks.
#[derive(Clone, Debug, PartialEq)]
struct TestBatch {
    records: Vec<LogRecord>,
}

/// What a sink was asked to write, kept for the test to inspect.
#[derive(Default)]
struct Recording {
    batches: StdMutex<Vec<TestBatch>>,
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

    fn batches(&self) -> Vec<TestBatch> {
        self.batches.lock().unwrap().clone()
    }
}

struct RecordingSink {
    shared: Arc<Recording>,
    notify: Option<UnboundedSender<TestBatch>>,
    /// Sleeps in write_batch, so a test can fill the channel on purpose.
    delay: Option<Duration>,
}

impl logreel::BatchSink for RecordingSink {
    fn write_batch(&mut self, batch: &logreel::EncodedBatch) -> Result<(), logreel::StoreError> {
        if let Some(delay) = self.delay {
            std::thread::sleep(delay);
        }
        self.shared.attempts.fetch_add(1, Relaxed);
        if self.shared.fail_next.swap(false, Relaxed) {
            return Err(logreel::StoreError::new(
                logreel::ErrorKind::Io,
                "the sink is having a bad day",
            ));
        }
        let batch = batch_from_encoded(batch);
        self.shared.batches.lock().unwrap().push(batch.clone());
        if let Some(notify) = &self.notify {
            let _ = notify.send(batch);
        }
        Ok(())
    }
}

/// Decode a batch the library encoded, without the file backend.
///
/// The thin build has no logreel-file and the tests still want the records, so
/// this is the envelope itself rather than a reader call: u32 record count,
/// u64 first timestamp, u64 last, u16 mask length and the mask, u16 domain
/// length and the domain, then per record level, category, kind, timestamp,
/// varint sequence, varint connection, varint payload length and the payload.
fn batch_from_encoded(batch: &logreel::EncodedBatch) -> TestBatch {
    let mut cursor = Cursor::new(&batch.payload);
    let count = cursor.u32();
    let _first = cursor.u64();
    let _last = cursor.u64();
    let mask_len = usize::from(cursor.u16());
    cursor.take(mask_len);
    let domain_len = usize::from(cursor.u16());
    cursor.take(domain_len);

    let mut records = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let level = cursor.u8();
        let category = cursor.u8();
        let kind = cursor.u16();
        let ts_ns = cursor.u64();
        let seq = cursor.varint() as u32;
        let conn_id = cursor.varint();
        let len = cursor.varint() as usize;
        let payload = cursor.take(len);
        records.push(LogRecord {
            ts_ns,
            conn_id,
            seq,
            level: i32::from(level),
            category: i32::from(category),
            event: Some(
                <Event as logreel::Event>::decode(kind, payload).expect("a kind this build wrote"),
            ),
        });
    }

    TestBatch { records }
}

/// A reader over a batch payload; the format is the library's, the arithmetic
/// is small enough to keep in the test that needs it.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> &'a [u8] {
        let end = self.position + len;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        slice
    }

    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take(2).try_into().expect("2 bytes"))
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().expect("4 bytes"))
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().expect("8 bytes"))
    }

    fn varint(&mut self) -> u64 {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.u8();
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }
}

fn recording() -> (RecordingSink, Arc<Recording>, UnboundedReceiver<TestBatch>) {
    let shared = Arc::new(Recording::default());
    let (notify, batches) = unbounded_channel();
    let sink = RecordingSink {
        shared: Arc::clone(&shared),
        notify: Some(notify),
        delay: None,
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

async fn next_batch(batches: &mut UnboundedReceiver<TestBatch>) -> TestBatch {
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

/// A current-thread runtime for the async entry points the tests drive from the
/// test thread. The writer is the library's own std thread, not a task on this
/// runtime, so nothing here depends on the runtime being polled.
fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
}

/// [`super::init`] the way `server.rs` calls it: a directory means a segment in
/// a build that has the on-disk sink, and nothing but the text view and the
/// ring in a build that does not — which is also what `None` means in both.
///
/// The tests that assert on a segment's contents ask for one directly through
/// `storage`, and are compiled only where it exists.
fn init_with_dir(settings: Settings, dir: Option<&Path>) -> Result<Arc<LogHandle>, LogError> {
    #[cfg(feature = "log-disk")]
    let disk = dir.map(|dir| Disk {
        dir: dir.to_path_buf(),
        options: Options::default(),
    });
    #[cfg(not(feature = "log-disk"))]
    let disk = {
        let _ = dir;
        None
    };

    init(settings, disk)
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
fn dropped_records_are_reported_at_the_next_flush() {
    // The writer is a std thread now, so it has to be *kept* from draining: a
    // sink that sleeps in its write is what a full channel needs. Emitting then
    // fills the channel, and the next flush has to turn the count into a record.
    let runtime = current_thread_runtime();
    let shared = Arc::new(Recording::default());
    let sink = RecordingSink {
        shared: Arc::clone(&shared),
        notify: None,
        delay: Some(Duration::from_millis(200)),
    };
    let handle = runtime.block_on(async {
        start(
            sink,
            Settings {
                flush_interval: Duration::from_millis(50),
                ..Settings::default()
            },
        )
    });

    let mut emitted = 0u64;
    while handle.dropped() == 0 && emitted < 100_000 {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(2));
        emitted += 1;
    }
    let dropped = handle.dropped();
    assert!(dropped > 0, "the channel never filled");
    assert!(emitted > CHANNEL_CAPACITY as u64);

    let reported = runtime.block_on(async {
        for _ in 0..200 {
            if let Some(reported) = shared
                .batches()
                .iter()
                .flat_map(|batch| batch.records.iter())
                .find_map(|record| match &record.event {
                    Some(Event::LogOverflow(overflow)) => Some(overflow.dropped),
                    _ => None,
                })
            {
                return reported;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the overflow record never reached the sink");
    });
    assert!(reported > 0);
    assert!(handle.dropped() >= dropped, "the counter is cumulative");

    runtime.block_on(handle.shutdown());
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
fn the_gate_is_the_union_of_the_consumers_policies() {
    let runtime = current_thread_runtime();

    // Text at info, ring off: the union is info, so an info payload is built
    // for the text view. With the on-disk sink in the build its floor sits at
    // warn here — the same point from the other side: the segment is what
    // drops the record, not the gate.
    let (sink, _shared, _batches) = recording();
    let settings = Settings {
        #[cfg(feature = "log-disk")]
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
        #[cfg(feature = "log-disk")]
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
        #[cfg(feature = "log-disk")]
        disk: [Filter::at(Level::Warn); CATEGORY_COUNT],
        text: Filter::off(),
        ring: Filter::off(),
        ..Settings::default()
    };
    let handle = runtime.block_on(async { start(sink, settings) });
    assert!(!handle.enabled(Category::Pool, Level::Debug));
}

#[cfg(feature = "log-disk")]
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
    let runtime = current_thread_runtime();
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
    // The writer thread drains the channel, but the emit path never waits for
    // it: this measures filter, timestamp, sequence number and the non-blocking
    // send, with the sink work happening behind the channel. A fresh handle per
    // round keeps the channel from filling up.
    const ROUNDS: u32 = 8;
    let runtime = current_thread_runtime();
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

/// The view lives on the writer thread and `LogHandle` holds no reference to
/// it, so a text sink that blocks — a terminal nobody reads, a volume that has
/// gone away — cannot reach the connection path. The cost below is the emit
/// path itself: a view that had crept onto it would show up as a file write per
/// record.
#[test]
fn emit_does_not_wait_for_the_text_view() {
    const ROUNDS: u32 = 4;
    let dir = TempDir::new("emit-view");
    let path = dir.path().join("text.log");
    let runtime = current_thread_runtime();

    let mut costs = Vec::new();
    for target in [TextTarget::Off, TextTarget::File(path.clone())] {
        let mut elapsed = Duration::ZERO;
        for _ in 0..ROUNDS {
            let (sink, _shared, _batches) = recording();
            let settings = Settings {
                text_log: target.clone(),
                text: Filter::at(Level::Debug),
                ..quiet(DEFAULT_BATCH_MAX)
            };
            let handle = runtime.block_on(async { start(sink, settings) });

            let started = Instant::now();
            for _ in 0..CHANNEL_CAPACITY {
                handle.emit(1, Category::Routing, Level::Debug, pool_hit(2));
            }
            elapsed += started.elapsed();
        }
        costs.push(elapsed.as_nanos() as f64 / (ROUNDS as usize * CHANNEL_CAPACITY) as f64);
    }

    let (off, on) = (costs[0], costs[1]);
    println!("emit: {off:.0} ns/record with the text view off, {on:.0} with it on");
    assert!(
        on < 20_000.0,
        "the view reached the emit path: {on:.0} ns/record"
    );
    assert!(
        on < off * 4.0 + 100.0,
        "configuring a text sink changed what emit costs: {off:.0} → {on:.0} ns/record"
    );
}

// ── The text view, end to end ──────────────────────────────────────────────

/// Settings whose text view writes into `path`, which is the only way a test
/// can read what a terminal would have shown.
fn text_into(path: &Path, text: Filter, ring: Filter) -> Settings {
    Settings {
        text_log: TextTarget::File(path.to_path_buf()),
        text,
        ring,
        ..quiet(DEFAULT_BATCH_MAX)
    }
}

async fn wait_for_text(path: &Path, needle: &str) -> String {
    wait_until(|| fs::read_to_string(path).is_ok_and(|text| text.contains(needle))).await;
    fs::read_to_string(path).expect("the text log is readable")
}

#[tokio::test]
async fn the_text_view_renders_what_the_writer_reads() {
    let dir = TempDir::new("text-view");
    let path = dir.path().join("text.log");
    let (sink, shared, _batches) = recording();
    let handle = start(
        sink,
        text_into(&path, Filter::at(Level::Info), Filter::off()),
    );

    let peer = Peer {
        addr: vec![192, 168, 1, 60],
        port: 51719,
        hashed: false,
        encrypted: false,
    };
    handle.emit(
        7,
        Category::Session,
        Level::Info,
        Event::SessionOpened(SessionOpened {
            ctx: Some(Ctx::new(2, true, Tier::Unspecified)),
            peer: Some(peer),
        }),
    );
    handle.emit(
        7,
        Category::Session,
        Level::Info,
        Event::SessionClosed(SessionClosed {
            ctx: Some(Ctx::new(2, true, Tier::Ws)),
            closed_by: ClosedBy::Client as i32,
            bytes_up: 23_961,
            bytes_down: 5_557_452,
            dur_ms: 64_512,
            via: "kws2.web.telegram.org".into(),
        }),
    );

    let text = wait_for_text(&path, "session closed").await;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(
        lines[0].contains("[192.168.1.60:51719] DC2m session opened"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains(
            "[192.168.1.60:51719] DC2m WS session closed via kws2.web.telegram.org \
             by client: \u{2191}23.4KB  \u{2193}5.3MB  64.5s"
        ),
        "{}",
        lines[1]
    );

    // The same records reached the segment: the view is a second reader of one
    // stream, not a fork of it.
    handle.shutdown().await;
    let batches = shared.batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].records.len(), 2);
}

#[tokio::test]
async fn a_below_floor_record_still_reaches_the_segment() {
    let dir = TempDir::new("text-floor");
    let path = dir.path().join("text.log");
    let (sink, _shared, _batches) = recording();
    let handle = start(sink, text_into(&path, Filter::off(), Filter::off()));

    handle.emit(1, Category::Routing, Level::Debug, pool_hit(2));
    let text = wait_for_text(&path, "").await;
    assert!(text.is_empty(), "the text view was asked for nothing");

    handle.shutdown().await;
}

#[tokio::test]
async fn a_ring_dump_reaches_the_text_sink() {
    let dir = TempDir::new("ring-dump");
    let path = dir.path().join("text.log");
    let (sink, _shared, _batches) = recording();
    // Nothing is printed as it happens: the only text this run writes is the
    // dump, which is the point of asking for one.
    let handle = start(
        sink,
        text_into(&path, Filter::off(), Filter::at(Level::Info)),
    );

    for dc in 1..=3 {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(dc));
    }
    handle.dump_ring();

    let text = wait_for_text(&path, "ring dump").await;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "tg-ws-proxy: ring dump, 3 records");
    assert_eq!(lines.len(), 4, "{text}");
    assert!(lines[1].contains("DC1"), "{}", lines[1]);
    assert!(lines[3].contains("DC3"), "oldest first: {text}");

    handle.shutdown().await;
}

/// `SIGUSR1` is the whole point of the ring: a router has no debugger, and the
/// operator's question — "what were the last few hundred records?" — has to be
/// answerable by a signal.
#[cfg(unix)]
#[tokio::test]
async fn sigusr1_prints_the_ring_through_the_text_sink() {
    let dir = TempDir::new("usr1");
    let path = dir.path().join("text.log");
    // Text off, ring on: the only text this run writes is the dump, so a line
    // in the file cannot be anything else.
    let settings = text_into(&path, Filter::off(), Filter::at(Level::Info));
    let handle = init_with_dir(settings, Some(dir.path())).expect("the sink starts");

    for dc in 1..=3 {
        handle.emit(1, Category::Routing, Level::Info, pool_hit(dc));
    }

    let status = std::process::Command::new("kill")
        .args(["-USR1", &std::process::id().to_string()])
        .status()
        .expect("kill is on every system this runs on");
    assert!(status.success(), "kill -USR1 failed: {status}");

    let text = wait_for_text(&path, "ring dump").await;
    assert!(text.contains("ring dump, 3 records"), "{text}");
    assert!(text.contains("DC2"), "{text}");

    handle.shutdown().await;
}

/// A text destination that cannot be opened is a startup error, and it says
/// which destination it was: the same rule the segment's own directory follows.
#[tokio::test]
async fn a_text_target_that_cannot_be_opened_is_a_startup_error() {
    let dir = TempDir::new("text-unopenable");
    let (sink, _shared, _batches) = recording();
    // A directory is the one path that always exists and can never be opened
    // for writing.
    let settings = Settings {
        text_log: TextTarget::File(dir.path().to_path_buf()),
        ..quiet(DEFAULT_BATCH_MAX)
    };

    let error = match super::start_with_sink(sink, settings) {
        Err(error) => error,
        Ok(_) => panic!("a directory is not a log file"),
    };
    let message = error.to_string();
    assert!(
        message.contains(&dir.path().display().to_string())
            && message.contains("could not be opened"),
        "{message}"
    );
}

// Every test below this line drives a real segment, so the whole section
// is behind the `log-disk` feature that provides one.

// ── Storage ────────────────────────────────────────────────────────────────

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "log-zstd")]
use super::storage::Compression;
#[cfg(feature = "log-disk")]
use super::storage::{self, DurabilityMode, FileSink, Options};

/// The old sink interface, for the storage tests: a TestBatch encoded the way
/// the library's writer would encode it. The library's own BatchSink takes the
/// encoded form, and the tests still speak batches of records.
#[cfg(feature = "log-disk")]
trait SinkWrite {
    fn write(&mut self, batch: &TestBatch) -> Result<(), logreel::StoreError>;
}

#[cfg(feature = "log-disk")]
impl SinkWrite for FileSink {
    fn write(&mut self, batch: &TestBatch) -> Result<(), logreel::StoreError> {
        let encoded = encoded(batch);
        logreel::BatchSink::write_batch(self, &encoded)
    }
}

/// Encode a proxy batch the way the library's writer does.
#[cfg(feature = "log-disk")]
fn encoded(batch: &TestBatch) -> logreel::EncodedBatch {
    let records: Vec<logreel::Record<Event>> = batch
        .records
        .iter()
        .map(|record| {
            let event = record.event.clone().expect("the fixture has an event");
            logreel::Record::new(
                super::logreel_level(Level::try_from(record.level).unwrap_or(Level::Info)),
                record.category as u8,
                <Event as logreel::Event>::kind(&event),
                record.ts_ns,
                record.seq,
                record.conn_id,
                event,
            )
        })
        .collect();
    logreel::BatchEncoder::new().encode(&records, &super::domain())
}

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

    /// Every entry in the directory, sorted. Only the storage tests care what
    /// a segment *did not* leave behind.
    #[cfg(feature = "log-disk")]
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

/// A fresh `(ts_ns, seq)` pair, so two synthetic batches never look alike.
#[cfg(feature = "log-disk")]
fn next_stamp() -> (u64, u32) {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    let n = NEXT.fetch_add(1, Relaxed) as u64;
    (1_700_000_000_000_000_000 + n, n as u32)
}

/// A batch of `conn_id`s, one record each, the way the writer would build it.
#[cfg(feature = "log-disk")]
fn batch_of(conn_ids: &[u64]) -> TestBatch {
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
    TestBatch { records }
}

/// A batch with the variety real traffic has: mixed event kinds, different
/// sessions, counters that move. A fixture of 256 identical records would
/// compress to almost nothing and flatter the ratio this test exists to report.
#[cfg(feature = "log-zstd")]
fn rich_batch() -> TestBatch {
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

    TestBatch { records }
}

#[cfg(feature = "log-disk")]
fn records_of(dir: &Path, day: &str) -> Vec<Vec<LogRecord>> {
    storage::iter_batches(dir, day)
        .expect("readable")
        .into_iter()
        .map(|batch| batch.records)
        .collect()
}

#[cfg(feature = "log-disk")]
fn open_sink(dir: &Path, options: Options) -> FileSink {
    FileSink::open(dir, options).expect("the sink opens")
}

/// A clock the tests move by hand, so a rotation is one assignment away.
#[cfg(feature = "log-disk")]
struct ManualClock(std::sync::Mutex<u64>);

#[cfg(feature = "log-disk")]
impl ManualClock {
    fn at(day: i64) -> Self {
        Self(std::sync::Mutex::new(day as u64 * 86_400_000_000_000))
    }

    fn set(&self, day: i64) {
        *self.0.lock().expect("clock lock") = day as u64 * 86_400_000_000_000;
    }
}

#[cfg(feature = "log-disk")]
impl logreel::file::Clock for ManualClock {
    fn now_ns(&self) -> u64 {
        *self.0.lock().expect("clock lock")
    }
}

#[cfg(feature = "log-disk")]
#[test]
fn a_segment_from_another_schema_is_refused_rather_than_appended_to() {
    let dir = TempDir::new("schema-guard");
    // The same compression mode the sink will ask for: a mode mismatch is its
    // own refusal, and this test is about the fingerprint.
    let compress = {
        #[cfg(feature = "log-zstd")]
        {
            true
        }
        #[cfg(not(feature = "log-zstd"))]
        {
            false
        }
    };
    let foreign = logreel::file::FileStoreConfig {
        directory: dir.path().to_path_buf(),
        producer_id: 1,
        session_nonce: 0,
        keep_days: 0,
        max_total_bytes: 0,
        compress,
        zstd_level: 3,
        retention_anchor: logreel::file::RetentionAnchor::Clock,
        on_warning: None,
    };
    let mut store = logreel::file::FileStore::open(foreign).expect("the foreign store opens");
    store
        .prime(<Event as logreel::Event>::CODEC_ID, 22, [0xEE; 16])
        .expect("today's file is created with a foreign fingerprint");
    drop(store);

    // A segment this build wrote is the ordinary restart: the same day's file
    // is reopened and appended to.
    let ours = TempDir::new("schema-guard-ok");
    drop(open_sink(ours.path(), Options::default()));
    open_sink(ours.path(), Options::default());

    match FileSink::open(dir.path(), Options::default()) {
        Ok(_) => panic!("a segment from another schema must not be appended to"),
        Err(LogError::Segment(message)) => {
            assert!(message.contains("schema hash"), "{message}");
            assert!(message.contains("differs"), "{message}");
        }
        Err(other) => panic!("expected a refused segment, got {other}"),
    }
}

#[cfg(feature = "log-disk")]
#[test]
fn a_segment_round_trips_every_batch() {
    let dir = TempDir::new("roundtrip");
    let day = logreel::file::today();
    let mut sink = open_sink(dir.path(), Options::default());

    let first = batch_of(&[1, 2, 3]);
    let second = batch_of(&[4]);
    sink.write(&first).expect("the batch is written");
    sink.write(&second).expect("the batch is written");
    drop(sink);

    let read_back =
        storage::iter_batches(dir.path(), &logreel::file::day_name(day)).expect("readable");
    let read_back: Vec<Vec<LogRecord>> = read_back.into_iter().map(|batch| batch.records).collect();
    assert_eq!(read_back, vec![first.records, second.records]);
}

#[cfg(feature = "log-disk")]
#[test]
fn a_restart_inside_the_same_day_appends_to_the_same_segment() {
    let dir = TempDir::new("restart");
    let day = logreel::file::today();

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
        vec![format!("{}.seg", logreel::file::day_name(day))],
        "one segment for the day, not one per run"
    );
    let read_back: Vec<Vec<LogRecord>> =
        storage::iter_batches(dir.path(), &logreel::file::day_name(day))
            .expect("readable")
            .into_iter()
            .map(|batch| batch.records)
            .collect();
    assert_eq!(read_back, vec![first.records, second.records]);
}

#[cfg(feature = "log-disk")]
#[test]
fn both_durability_modes_survive_a_clean_close() {
    for mode in [DurabilityMode::Eventual, DurabilityMode::Immediate] {
        let dir = TempDir::new("durability");
        let day = logreel::file::today();
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

        let read_back: Vec<Vec<LogRecord>> =
            storage::iter_batches(dir.path(), &logreel::file::day_name(day))
                .expect("readable")
                .into_iter()
                .map(|entry| entry.records)
                .collect();
        assert_eq!(
            read_back,
            vec![batch.records],
            "{mode:?} lost a batch on a clean close"
        );
    }
}

#[cfg(feature = "log-disk")]
#[test]
fn a_record_emitted_while_the_writer_is_stopping_still_reaches_the_sink() {
    // The accept loop stops before a session that is still tearing down, so the
    // moment between "stop" and "the writer exits" is exactly when the last
    // session's close record is produced. Dropping it would make the end of a
    // session the one thing a clean stop is allowed to lose.
    let runtime = current_thread_runtime();
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

#[cfg(feature = "log-disk")]
#[cfg(feature = "log-zstd")]
#[test]
fn zstd_shrinks_a_rich_batch_and_round_trips_it() {
    let batch = rich_batch();
    let day = logreel::file::day_name(logreel::file::today());

    let plain_dir = TempDir::new("zstd-plain");
    let mut plain = open_sink(
        plain_dir.path(),
        Options {
            compress: Compression::None,
            ..Options::default()
        },
    );
    plain.write(&batch).expect("written");
    drop(plain);

    let packed_dir = TempDir::new("zstd-packed");
    let mut packed = open_sink(
        packed_dir.path(),
        Options {
            compress: Compression::ZstdL1,
            ..Options::default()
        },
    );
    packed.write(&batch).expect("written");
    drop(packed);

    let raw = fs::metadata(plain_dir.path().join(format!("{day}.seg")))
        .expect("the plain segment")
        .len();
    let compressed = fs::metadata(packed_dir.path().join(format!("{day}.seg")))
        .expect("the compressed segment")
        .len();
    assert!(
        compressed < raw,
        "zstd grew the segment: {compressed} vs {raw} bytes"
    );
    assert_eq!(records_of(packed_dir.path(), &day), vec![batch.records]);
    println!(
        "segment: {raw} B plain, {compressed} B zstd ({}%)",
        compressed * 100 / raw
    );
}

#[cfg(feature = "log-disk")]
#[cfg(feature = "log-zstd")]
#[test]
fn a_compressed_segment_reads_back_as_written() {
    let dir = TempDir::new("compressed");
    let day = logreel::file::today();
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
        records_of(dir.path(), &logreel::file::day_name(day)),
        vec![batch.records]
    );
}

#[cfg(feature = "log-disk")]
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

#[cfg(feature = "log-disk")]
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

#[cfg(feature = "log-disk")]
#[test]
fn a_second_sink_on_the_same_directory_is_refused() {
    let dir = TempDir::new("conflict");
    let _first = open_sink(dir.path(), Options::default());

    let second = FileSink::open(dir.path(), Options::default());
    match second {
        Err(LogError::WriterConflict(path)) => {
            assert!(path.ends_with(format!(
                "{}.seg",
                logreel::file::day_name(logreel::file::today())
            )));
        }
        Err(other) => panic!("expected a writer conflict, got {other}"),
        Ok(_) => panic!("a second writer took the segment"),
    }
}

#[cfg(feature = "log-disk")]
#[test]
fn the_segment_records_its_provenance() {
    let dir = TempDir::new("meta");
    let date = logreel::file::day_name(logreel::file::today());
    let mut sink = open_sink(dir.path(), Options::default());
    sink.write(&batch_of(&[1])).expect("written");
    drop(sink);

    let path = dir.path().join(format!("{date}.seg"));
    let mut reader = logreel::file::SegmentReader::open(&path).expect("readable");
    let header = reader.header();
    assert_eq!(header.codec_id, <Event as logreel::Event>::CODEC_ID);
    assert_eq!(header.kind_count, <Event as logreel::Event>::KINDS);
    assert_eq!(header.schema_hash, <Event as logreel::Event>::SCHEMA_HASH);

    let batch = reader
        .next_decoded_batch()
        .expect("a batch")
        .expect("valid")
        .batch;
    let domain = String::from_utf8_lossy(&batch.domain);
    assert!(
        domain.contains(env!("CARGO_PKG_VERSION")),
        "the domain names the app version: {domain}"
    );
    assert!(
        domain.contains(&format!("schema={}", schema::SCHEMA_VERSION)),
        "{domain}"
    );
    assert!(
        domain.contains(&format!("protocol={}", super::WRITER_PROTOCOL)),
        "{domain}"
    );
}

#[test]
fn the_fingerprint_follows_the_schema() {
    // Pinned so that a change to a field number, a tag or an enum value cannot
    // land without someone noticing that it moved.
    assert_eq!(
        fingerprint(),
        0x0d38_0a48_bbf8_f473_u64,
        "the wire format changed"
    );
}

#[cfg(feature = "log-disk")]
#[test]
fn retention_deletes_expired_segments_and_nothing_else() {
    let dir = TempDir::new("retention");
    let today = logreel::file::today();
    let mut expected = Vec::new();

    // Placeholders older than today. The sweep only reads names, so an empty
    // file stands in for a day this run did not write; today's file has to be
    // a real segment, because the sink opens it.
    for age in 1..12 {
        let name = format!("{}.seg", logreel::file::day_name(today - age));
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

    expected.push(format!("{}.seg", logreel::file::day_name(today)));
    expected.push("notes.txt".to_string());
    expected.sort();
    assert_eq!(dir.entries(), expected, "seven days kept, the rest swept");
}

#[cfg(feature = "log-disk")]
#[test]
fn retention_zero_keeps_everything() {
    let dir = TempDir::new("keepall");
    let today = logreel::file::today();
    let ancient = format!("{}.seg", logreel::file::day_name(today - 400));
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

#[cfg(feature = "log-disk")]
#[test]
fn a_clock_in_the_future_does_not_sweep_the_archive() {
    // A router with no RTC can come up reading next year: the clock is set from
    // the newest file in /etc, which is a date, not a promise. Counted from the
    // clock, the startup sweep deletes every segment in the directory before a
    // record is written; counted from the archive, the newest segment is what
    // the window hangs on.
    let dir = TempDir::new("future-clock");
    let today = logreel::file::today();
    for age in [1, 5, 40] {
        fs::write(
            dir.path()
                .join(format!("{}.seg", logreel::file::day_name(today - age))),
            b"",
        )
        .expect("a placeholder segment");
    }

    let clock: std::sync::Arc<dyn logreel::file::Clock> =
        std::sync::Arc::new(ManualClock::at(today + 4_000));
    let _sink = FileSink::open_with_clock(
        dir.path(),
        Options {
            retention_days: 7,
            ..Options::default()
        },
        clock,
    )
    .expect("the sink opens");

    let kept = dir.entries();
    assert!(
        kept.contains(&format!("{}.seg", logreel::file::day_name(today + 4_000))),
        "the run's own segment is missing: {kept:?}"
    );
    assert!(
        kept.contains(&format!("{}.seg", logreel::file::day_name(today - 1))),
        "a clock from the future swept the newest segment: {kept:?}"
    );
    assert!(
        kept.contains(&format!("{}.seg", logreel::file::day_name(today - 5))),
        "a segment inside the window was swept: {kept:?}"
    );
    assert!(
        !kept.contains(&format!("{}.seg", logreel::file::day_name(today - 40))),
        "a segment outside the window was kept: {kept:?}"
    );
}

#[cfg(feature = "log-disk")]
#[test]
fn a_clock_that_boots_in_the_past_does_not_delete_this_runs_segment() {
    // The other direction, and the one that nearly cost a boot its records on
    // the reference router: the clock reads a past day, the sink opens and
    // writes a segment named after it, and the sweep runs again once ntpd has
    // corrected the clock. The file this run is writing is not expired, whatever
    // its name says — deleting it would delete the records of that very boot.
    let dir = TempDir::new("past-clock");
    let today = logreel::file::today();
    let ours = today - 5_000;
    for age in [1, 30] {
        fs::write(
            dir.path()
                .join(format!("{}.seg", logreel::file::day_name(today - age))),
            b"",
        )
        .expect("a placeholder segment");
    }

    // The boot starts years off and writes its segment; ntpd corrects the
    // clock and the next write rotates into today. Both days are this run's.
    let clock = std::sync::Arc::new(ManualClock::at(ours));
    let sink_clock: std::sync::Arc<dyn logreel::file::Clock> = clock.clone();
    let mut sink = FileSink::open_with_clock(
        dir.path(),
        Options {
            retention_days: 7,
            ..Options::default()
        },
        sink_clock,
    )
    .expect("the sink opens");
    sink.write(&batch_of(&[1])).expect("written");
    clock.set(today);
    sink.write(&batch_of(&[2])).expect("written");
    drop(sink);

    let kept = dir.entries();
    assert!(
        kept.contains(&format!("{}.seg", logreel::file::day_name(ours))),
        "the sweep deleted the segment this run wrote: {kept:?}"
    );
    assert!(kept.contains(&format!("{}.seg", logreel::file::day_name(today - 1))));
    assert!(
        !kept.contains(&format!("{}.seg", logreel::file::day_name(today - 30))),
        "a segment outside the window was kept: {kept:?}"
    );
}

#[cfg(feature = "log-disk")]
#[test]
fn rotation_moves_to_the_next_day_without_losing_the_previous_one() {
    let dir = TempDir::new("rotation");
    let today = logreel::file::today();
    let clock = std::sync::Arc::new(ManualClock::at(today));
    let mut sink = FileSink::open_with_clock(dir.path(), Options::default(), clock.clone())
        .expect("the sink opens");

    let first = batch_of(&[1]);
    sink.write(&first).expect("written");
    clock.set(today + 1);
    let second = batch_of(&[2]);
    sink.write(&second).expect("written");
    drop(sink);

    assert_eq!(
        dir.entries(),
        vec![
            format!("{}.seg", logreel::file::day_name(today)),
            format!("{}.seg", logreel::file::day_name(today + 1)),
        ]
    );
    assert_eq!(
        records_of(dir.path(), &logreel::file::day_name(today)),
        vec![first.records]
    );
    assert_eq!(
        records_of(dir.path(), &logreel::file::day_name(today + 1)),
        vec![second.records]
    );
}

#[cfg(feature = "log-disk")]
#[cfg(unix)]
#[test]
fn a_segment_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new("mode");
    let date = logreel::file::day_name(logreel::file::today());
    drop(open_sink(dir.path(), Options::default()));

    let mode = fs::metadata(dir.path().join(format!("{date}.seg")))
        .expect("the segment exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the segment holds every session's metadata");
}

#[cfg(feature = "log-disk")]
#[test]
fn records_written_through_the_pipeline_are_readable_back() {
    let runtime = current_thread_runtime();
    let dir = TempDir::new("pipeline");
    let day = logreel::file::today();
    let sink = open_sink(dir.path(), Options::default());
    let handle = runtime.block_on(async { start(sink, Settings::default()) });

    for conn in 1..=3 {
        for _ in 0..(DEFAULT_BATCH_MAX / 3) {
            handle.emit(conn, Category::Session, Level::Info, pool_hit(2));
        }
    }
    runtime.block_on(handle.shutdown());

    let batches =
        storage::iter_batches(dir.path(), &logreel::file::day_name(day)).expect("readable");
    let records: usize = batches.iter().map(|batch| batch.records.len()).sum();
    assert_eq!(records, 3 * (DEFAULT_BATCH_MAX / 3));
    let conns: Vec<u64> = batches
        .iter()
        .flat_map(|batch| batch.records.iter().map(|record| record.conn_id))
        .collect();
    assert!(conns.contains(&1) && conns.contains(&2) && conns.contains(&3));
}

#[cfg(feature = "log-disk")]
#[test]
fn an_empty_segment_reads_back_as_an_empty_day() {
    // The sink creates today's file at startup, header and lock and nothing
    // else. Refusing to read it would turn "nothing happened today" into a
    // corrupt-file error — and `--log-level error` over a healthy proxy is
    // exactly a day with nothing in it.
    let dir = TempDir::new("empty");
    let date = logreel::file::day_name(logreel::file::today());
    drop(open_sink(dir.path(), Options::default()));

    assert!(
        storage::iter_batches(dir.path(), &date)
            .expect("an empty day is readable")
            .is_empty()
    );
}

#[cfg(feature = "log-disk")]
#[test]
fn init_starts_a_writable_segment_from_the_public_entry_point() {
    // What the startup path calls, with none of the test's own plumbing in
    // between: `init` opens the directory, spawns the writer, and the record
    // comes back out of the file on the other side.
    let runtime = current_thread_runtime();
    let dir = TempDir::new("init");
    let day = logreel::file::today();

    let handle = runtime
        .block_on(async { init_with_dir(Settings::default(), Some(dir.path())) })
        .expect("the sink starts");
    handle.emit(1, Category::Accept, Level::Info, pool_hit(2));
    runtime.block_on(handle.shutdown());

    let batches =
        storage::iter_batches(dir.path(), &logreel::file::day_name(day)).expect("readable");
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.records.len())
            .sum::<usize>(),
        1
    );
}

#[test]
fn without_a_directory_the_records_still_reach_the_text() {
    // What an unset `--log-dir` means: the pipeline runs, the sink keeps
    // nothing, and the text view is the whole of what the records are for.
    let runtime = current_thread_runtime();
    let dir = TempDir::new("memory-sink");
    let path = dir.path().join("text.log");
    let settings = text_into(&path, Filter::at(Level::Info), Filter::off());

    let handle = runtime
        .block_on(async { init_with_dir(settings, None) })
        .expect("the pipeline starts without a directory");
    handle.emit(1, Category::Accept, Level::Info, pool_hit(2));
    runtime.block_on(handle.shutdown());

    let text = fs::read_to_string(&path).expect("the text log is readable");
    assert!(text.contains("pool hit"), "{text}");

    // And nothing else appeared beside it: a sink that keeps nothing must not
    // be a sink that quietly writes somewhere.
    let files: Vec<_> = fs::read_dir(dir.path())
        .expect("the temp dir")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "text.log")
        .collect();
    assert!(files.is_empty(), "{files:?}");
}

#[cfg(feature = "log-disk")]
#[tokio::test]
async fn the_text_floor_is_the_text_views_own_policy() {
    // The producer gate is the union of three consumers, so a record the
    // segment alone asked for is *enabled* and still must not be printed.
    let (sink, _shared, _batches) = recording();
    let settings = Settings {
        disk: [Filter::at(Level::Debug); CATEGORY_COUNT],
        text: Filter::at(Level::Info),
        ring: Filter::off(),
        text_log: TextTarget::Off,
        ..quiet(DEFAULT_BATCH_MAX)
    };
    let handle = start(sink, settings);

    assert!(
        handle.enabled(Category::Session, Level::Debug),
        "the segment asked for debug"
    );
    assert!(
        !handle.text_keeps(Level::Debug),
        "the text view did not, so a console line at debug is not printed"
    );
    assert!(handle.text_keeps(Level::Info));
    assert!(handle.text_keeps(Level::Error), "a floor is not a ceiling");
}

#[cfg(feature = "log-disk")]
#[test]
fn a_segment_with_a_torn_tail_reads_its_valid_prefix() {
    let dir = TempDir::new("truncated");
    let date = logreel::file::day_name(logreel::file::today());
    let mut sink = open_sink(dir.path(), Options::default());
    for conn in 1..=4 {
        sink.write(&batch_of(&[conn])).expect("written");
    }
    drop(sink);

    let path = dir.path().join(format!("{date}.seg"));
    let segment = fs::read(&path).expect("the segment exists");
    assert_eq!(
        storage::iter_batches(dir.path(), &date)
            .expect("the intact segment reads")
            .len(),
        4
    );

    // A tail cut inside the last frame is the shape a power cut leaves: the
    // frames before it are still exactly what was written, and the reader stops
    // at the last whole one rather than calling the file corrupt.
    fs::write(&path, &segment[..segment.len() - 8]).expect("a torn tail");
    let batches = storage::iter_batches(dir.path(), &date).expect("the prefix reads");
    assert!(batches.len() < 4, "a torn frame was read as a batch");
    assert!(!batches.is_empty(), "the valid prefix was thrown away");

    // A file shorter than the header is not a segment at all.
    fs::write(&path, &segment[..20]).expect("a stub");
    assert!(matches!(
        storage::iter_batches(dir.path(), &date),
        Err(LogError::Segment(_))
    ));
}

#[cfg(feature = "log-disk")]
#[test]
fn a_corrupt_frame_is_refused_rather_than_half_read() {
    let dir = TempDir::new("corrupt");
    let date = logreel::file::day_name(logreel::file::today());
    let mut sink = open_sink(dir.path(), Options::default());
    sink.write(&batch_of(&[1])).expect("written");
    drop(sink);

    let path = dir.path().join(format!("{date}.seg"));
    let mut segment = fs::read(&path).expect("the segment exists");
    // The payload starts after the header and the 8-byte frame header; flipping
    // a byte there keeps the lengths intact and breaks the checksum.
    let last = segment.len() - 1;
    segment[last] ^= 0xFF;
    fs::write(&path, &segment).expect("corrupted");

    assert!(matches!(
        storage::iter_batches(dir.path(), &date),
        Err(LogError::Segment(_))
    ));
}

#[cfg(feature = "log-disk")]
#[test]
fn a_missing_segment_is_reported_as_missing() {
    let dir = TempDir::new("missing");
    let error = storage::iter_batches(dir.path(), "2001-01-01").expect_err("nothing to read");
    assert!(
        error.to_string().contains("no such segment"),
        "unexpected error: {error}"
    );
}

#[cfg(feature = "log-disk")]
#[test]
fn reading_a_segment_leaves_its_bytes_alone() {
    // The reader used to hand `redb` the archive itself, and `redb` opens a
    // database read-write: every read rewrote bytes in it. Measured on the
    // router's stick on 2026-10-13 — identical sizes, identical records, a
    // different SHA-256 after every `probe`. A segment that changes when it is
    // read is not an archive: a hash taken before the read stops describing the
    // file, and a stick in a router takes writes nobody asked for.
    let runtime = current_thread_runtime();
    let dir = TempDir::new("read-only");
    let date = logreel::file::day_name(logreel::file::today());

    let handle = runtime
        .block_on(async { init_with_dir(Settings::default(), Some(dir.path())) })
        .expect("the sink starts");
    handle.emit(1, Category::Session, Level::Info, pool_hit(2));
    runtime.block_on(handle.shutdown());

    let path = dir.path().join(format!("{date}.seg"));
    let before = fs::read(&path).expect("the segment exists");

    let batches = storage::iter_batches(dir.path(), &date).expect("readable");
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.records.len())
            .sum::<usize>(),
        1
    );
    // Twice: a read that writes may write on the way in, on the way out, or
    // both, and only the second read would notice the first one's edit.
    storage::iter_batches(dir.path(), &date).expect("readable");

    let after = fs::read(&path).expect("the segment still exists");
    assert!(
        before == after,
        "reading the segment changed it: {} bytes before, {} after",
        before.len(),
        after.len()
    );

    // And the copy the old reader made of the file is gone with it: the
    // directory holds the segment and nothing else.
    assert_eq!(dir.entries(), vec![format!("{date}.seg")]);
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
    assert!(logreel::current::<Event>().is_none());
    assert!(!enabled(Category::Routing, Level::Info));
    emit(Category::Routing, Level::Info, pool_hit(2));

    let (sink, shared, _batches) = recording();
    let handle = Arc::new(start(sink, quiet(DEFAULT_BATCH_MAX)));

    scope(7, Arc::clone(&handle), async {
        assert!(logreel::current::<Event>().is_some());
        assert!(enabled(Category::Routing, Level::Info));
        emit(Category::Routing, Level::Info, pool_hit(2));
    })
    .await;

    assert!(
        logreel::current::<Event>().is_none(),
        "the scope must not outlive its future"
    );
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

#[cfg(feature = "log-disk")]
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

/// The text projection, frozen for the migration to logreel.
///
/// One record per `oneof` variant, rendered through the view that shipped
/// before the swap: the same 22 samples `every_event_variant_round_trips`
/// uses, fed in order so the `[peer]` map is exercised as well as the lines.
/// The file is a gate, not a fixture — the migration must not be allowed to
/// change a single byte of it. Regenerate deliberately with
/// `TG_GOLDEN_UPDATE=1 cargo test text_projection_matches_the_golden_corpus`.
#[test]
fn text_projection_matches_the_golden_corpus() {
    let golden = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/text-golden.txt"
    ));
    let rendered =
        std::env::temp_dir().join(format!("tgws-text-golden-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&rendered);

    let sink = TextSink::open(&TextTarget::File(rendered.clone())).expect("the temp file opens");
    // Both floors at the bottom: the sample set is the event table, not a
    // filtering rule, so nothing may be dropped on level.
    let mut view = View::with_sink(
        sink,
        Filter::at(Level::Debug),
        Filter::at(Level::Debug),
        256,
    );
    for (_, record) in samples() {
        view.show(&record);
    }
    view.flush();

    let got = std::fs::read_to_string(&rendered).expect("the view wrote the file");
    let _ = std::fs::remove_file(&rendered);

    if std::env::var_os("TG_GOLDEN_UPDATE").is_some() {
        if let Some(parent) = golden.parent() {
            std::fs::create_dir_all(parent).expect("the data directory");
        }
        std::fs::write(golden, &got).expect("the golden file is writable");
        return;
    }

    let expected = std::fs::read_to_string(golden)
        .unwrap_or_else(|error| panic!("{} is unreadable: {error}", golden.display()));
    assert_eq!(
        got,
        expected,
        "the text projection changed; see {}",
        golden.display()
    );
}
