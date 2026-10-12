//! The view's own tests: what the ring keeps, who the `[peer]` prefix belongs
//! to, and what comes out of a dump.
//!
//! The rendering itself is `render`'s business and is tested there; here the
//! question is which records reach the sink and the ring at all, and what the
//! view remembers between them.

use std::path::PathBuf;

use super::*;
use crate::log::schema::{
    ClosedBy, Ctx, Event, Level, LogRecord, Peer, PoolHit, PoolMiss, SessionClosed, SessionOpened,
    StartupSummary, Tier,
};

/// A directory to write one text log into, removed when the test ends.
struct Scratch {
    dir: PathBuf,
    log: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("tgws-view-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Self {
            log: dir.join("text.log"),
            dir,
        }
    }

    /// A view that writes into this scratch directory.
    fn view(&self, text: Filter, ring: Filter, capacity: usize) -> View {
        let sink = TextSink::open(&TextTarget::File(self.log.clone())).expect("the file opens");
        View::with_sink(sink, text, ring, capacity)
    }

    /// A view that writes nowhere, for the tests that only look at the ring.
    fn silent(&self, ring: Filter, capacity: usize) -> View {
        View::with_sink(TextSink::Off, Filter::off(), ring, capacity)
    }

    fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stamp(seq: u64) -> u64 {
    1_791_804_196_612_026_000 + seq * 1_000_000
}

fn record(conn_id: u64, level: Level, event: Event) -> LogRecord {
    LogRecord {
        ts_ns: stamp(conn_id),
        conn_id,
        seq: conn_id as u32,
        level: level as i32,
        category: 0,
        event: Some(event),
    }
}

fn opened(conn_id: u64, port: u32) -> LogRecord {
    record(
        conn_id,
        Level::Info,
        Event::SessionOpened(SessionOpened {
            ctx: Some(Ctx::new(2, true, Tier::Unspecified)),
            peer: Some(Peer {
                addr: vec![192, 168, 1, 60],
                port,
                hashed: false,
                encrypted: false,
            }),
        }),
    )
}

fn closed(conn_id: u64) -> LogRecord {
    record(
        conn_id,
        Level::Info,
        Event::SessionClosed(SessionClosed {
            ctx: Some(Ctx::new(2, true, Tier::Ws)),
            closed_by: ClosedBy::Client as i32,
            bytes_up: 1,
            bytes_down: 2,
            dur_ms: 3,
            via: "kws2.web.telegram.org".into(),
        }),
    )
}

fn pool_miss(conn_id: u64, level: Level) -> LogRecord {
    record(
        conn_id,
        level,
        Event::PoolMiss(PoolMiss {
            ctx: Some(Ctx::new(2, true, Tier::Ws)),
        }),
    )
}

fn pool_hit(conn_id: u64) -> LogRecord {
    record(
        conn_id,
        Level::Debug,
        Event::PoolHit(PoolHit {
            ctx: Some(Ctx::new(2, true, Tier::Ws)),
            left: 1,
        }),
    )
}

// ── The ring ───────────────────────────────────────────────────────────────

#[test]
fn the_ring_keeps_the_last_records_and_no_more() {
    let scratch = Scratch::new("ring-limit");
    let mut view = scratch.silent(Filter::at(Level::Debug), 64);

    for conn_id in 1..=100 {
        view.show(&pool_miss(conn_id, Level::Debug));
    }

    let held: Vec<u64> = view.ring().map(|record| record.conn_id).collect();
    assert_eq!(held.len(), 64, "the ring is the size it was built with");
    assert_eq!(
        held.first(),
        Some(&37),
        "the oldest records are the ones lost"
    );
    assert_eq!(held.last(), Some(&100));
}

#[test]
fn a_capacity_outside_the_limits_is_clamped() {
    let scratch = Scratch::new("ring-clamp");

    let tiny = scratch.silent(Filter::at(Level::Debug), 4);
    assert_eq!(tiny.ring_capacity, TEXT_RING_MIN);

    let huge = scratch.silent(Filter::at(Level::Debug), usize::MAX);
    assert_eq!(huge.ring_capacity, TEXT_RING_MAX);

    assert_eq!(clamp_ring(512), 512);
}

#[test]
fn the_build_time_capacity_is_read_from_the_environment() {
    assert_eq!(ring_from_env("1024"), 1024);
    assert_eq!(ring_from_env("64"), TEXT_RING_MIN);
    assert!(
        (TEXT_RING_MIN..=TEXT_RING_MAX).contains(&TEXT_RING_DEFAULT),
        "a build-time value outside the limits would make the ring a lie"
    );
}

#[test]
#[should_panic(expected = "must be a decimal number")]
fn a_capacity_that_is_not_a_number_fails_the_build() {
    let _ = ring_from_env("512k");
}

#[test]
#[should_panic(expected = "between 64 and 4096")]
fn a_capacity_out_of_range_fails_the_build() {
    let _ = ring_from_env("8");
}

// ── The three floors ───────────────────────────────────────────────────────

#[test]
fn the_ring_has_a_floor_of_its_own() {
    let scratch = Scratch::new("ring-floor");
    let mut view = scratch.view(Filter::off(), Filter::at(Level::Debug), 64);

    view.show(&pool_miss(1, Level::Debug));
    view.show(&pool_miss(1, Level::Info));

    assert_eq!(
        view.ring().count(),
        2,
        "the ring asked for debug and got it"
    );
    assert!(
        scratch.lines().is_empty(),
        "a text floor of off writes nothing"
    );
}

#[test]
fn the_text_has_a_floor_of_its_own() {
    let scratch = Scratch::new("text-floor");
    let mut view = scratch.view(Filter::at(Level::Info), Filter::off(), 64);

    view.show(&pool_miss(1, Level::Debug));
    view.show(&pool_miss(1, Level::Info));

    assert_eq!(view.ring().count(), 0, "the ring asked for nothing");
    let lines = scratch.lines();
    assert_eq!(lines.len(), 1, "the debug record was below the text floor");
    assert!(lines[0].contains("pool miss"));
}

#[test]
fn a_level_this_build_does_not_know_is_kept_by_both() {
    let scratch = Scratch::new("unknown-level");
    let mut view = scratch.view(Filter::at(Level::Error), Filter::at(Level::Error), 64);
    let mut unknown = pool_miss(1, Level::Info);
    unknown.level = 99;

    view.show(&unknown);

    assert_eq!(view.ring().count(), 1);
    assert_eq!(scratch.lines().len(), 1);
    assert!(
        scratch.lines()[0].contains("???"),
        "and it says it does not"
    );
}

// ── The peer prefix ────────────────────────────────────────────────────────

#[test]
fn the_peer_prefix_comes_from_the_open_record_and_goes_when_the_session_does() {
    let scratch = Scratch::new("peer-map");
    let mut view = scratch.view(Filter::at(Level::Debug), Filter::off(), 64);

    view.show(&opened(7, 51719));
    view.show(&pool_miss(7, Level::Debug));
    view.show(&closed(7));
    view.show(&pool_miss(7, Level::Debug));

    let lines = scratch.lines();
    assert_eq!(lines.len(), 4);
    assert!(lines[0].contains("[192.168.1.60:51719] DC2m session opened"));
    assert!(lines[1].contains("[192.168.1.60:51719] DC2m WS pool miss"));
    assert!(lines[2].contains("[192.168.1.60:51719] DC2m WS session closed"));
    assert!(
        lines[3].contains("[?] DC2m WS pool miss"),
        "a session that closed is a session nobody remembers: {}",
        lines[3]
    );
}

#[test]
fn a_new_run_forgets_the_previous_run_s_peers() {
    let scratch = Scratch::new("peer-reset");
    let mut view = scratch.view(Filter::at(Level::Debug), Filter::off(), 64);

    view.show(&opened(1, 1111));
    view.show(&record(
        0,
        Level::Info,
        Event::StartupSummary(StartupSummary {
            version: "2.5.4-struct-logging".into(),
            listen: "0.0.0.0:1443".into(),
            dc_ips: Vec::new(),
            tiers: Vec::new(),
            categories: Vec::new(),
        }),
    ));
    // A second run numbers its connections from one again; the same id must not
    // pick up the first run's client address.
    view.show(&pool_miss(1, Level::Debug));

    let lines = scratch.lines();
    assert_eq!(lines.len(), 2, "the banner is not a line");
    assert!(lines[1].contains("[?]"), "{}", lines[1]);
}

#[test]
fn the_peer_map_is_bounded() {
    let scratch = Scratch::new("peer-bound");
    let mut view = scratch.silent(Filter::off(), 64);

    for conn_id in 1..=(PEER_MAP_MAX as u64 + 8) {
        view.show(&opened(conn_id, 1000 + conn_id as u32));
    }

    assert!(
        view.peers.len() <= PEER_MAP_MAX,
        "the map grew to {} entries",
        view.peers.len()
    );
}

// ── The dump ───────────────────────────────────────────────────────────────

#[test]
fn a_dump_writes_the_ring_oldest_first_with_the_prefixes_the_ring_knows() {
    let scratch = Scratch::new("dump");
    let mut view = scratch.view(Filter::off(), Filter::at(Level::Debug), 64);

    view.show(&opened(7, 51719));
    view.show(&pool_hit(7));
    view.show(&closed(7));
    view.dump();

    let lines = scratch.lines();
    assert_eq!(lines.len(), 4, "a header and three records: {lines:?}");
    assert_eq!(lines[0], "tg-ws-proxy: ring dump, 3 records");
    // The session closed before the dump, so the live map no longer has it and
    // the prefix comes from the ring's own open record.
    assert!(lines[1].contains("[192.168.1.60:51719] DC2m session opened"));
    assert!(lines[2].contains("[192.168.1.60:51719] DC2m WS pool hit (1 left)"));
    assert!(lines[3].contains("[192.168.1.60:51719] DC2m WS session closed"));
}

/// A dump is a request, not a state: asking twice prints the ring twice.
#[test]
fn a_dump_can_be_asked_for_twice() {
    let scratch = Scratch::new("dump-kept");
    let mut view = scratch.view(Filter::off(), Filter::at(Level::Debug), 64);

    view.show(&pool_miss(1, Level::Debug));
    view.dump();
    view.dump();

    let lines = scratch.lines();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("pool miss"))
            .count(),
        2,
        "a second dump is a second dump, not an empty one"
    );
}

#[test]
fn an_empty_ring_dumps_its_header_and_nothing_else() {
    let scratch = Scratch::new("dump-empty");
    let mut view = scratch.view(Filter::off(), Filter::at(Level::Debug), 64);

    view.dump();

    assert_eq!(scratch.lines(), ["tg-ws-proxy: ring dump, 0 records"]);
}

#[test]
fn a_ring_of_one_record_is_not_a_ring_of_one_records() {
    let scratch = Scratch::new("dump-singular");
    let mut view = scratch.view(Filter::off(), Filter::at(Level::Info), 64);

    view.show(&pool_miss(1, Level::Info));
    view.dump();

    assert_eq!(scratch.lines()[0], "tg-ws-proxy: ring dump, 1 record");
}

// ── The sink ───────────────────────────────────────────────────────────────

#[test]
fn a_file_sink_appends_rather_than_truncating() {
    let scratch = Scratch::new("append");
    std::fs::write(&scratch.log, "a line from the previous run\n").expect("a seed file");

    let mut view = scratch.view(Filter::at(Level::Info), Filter::off(), 64);
    view.show(&pool_miss(1, Level::Info));

    let lines = scratch.lines();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "a line from the previous run");
}

#[test]
fn the_target_spec_reads_like_the_flag_it_comes_from() {
    assert_eq!(TextTarget::from_spec("off"), TextTarget::Off);
    assert_eq!(TextTarget::from_spec("stderr"), TextTarget::Stderr);
    assert_eq!(TextTarget::from_spec("stdout"), TextTarget::Stdout);
    assert_eq!(
        TextTarget::from_spec("/var/log/tg-ws-proxy.log"),
        TextTarget::File(PathBuf::from("/var/log/tg-ws-proxy.log"))
    );
    assert_eq!(
        TextTarget::from_spec("stderr.log"),
        TextTarget::File(PathBuf::from("stderr.log")),
        "a misspelling is a path, not a silently disabled view"
    );
    assert!(TextTarget::Off.is_off());
    assert!(!TextTarget::Stderr.is_off());
    assert_eq!(TextTarget::Stderr.to_string(), "stderr");
    assert_eq!(
        TextTarget::File(PathBuf::from("/tmp/x")).to_string(),
        "/tmp/x"
    );
}

/// A sink that fails on every write costs the text and nothing else: the view
/// keeps taking records, the ring keeps filling, and the failure is counted
/// rather than panicked on.
#[test]
fn a_failing_sink_costs_the_text_and_nothing_else() {
    let scratch = Scratch::new("sink-failure");
    // Opened read-only on purpose: writing to it fails with `EBADF`, which is
    // an ordinary sink failure and needs no privileges to arrange.
    std::fs::write(&scratch.log, "").expect("a scratch file");
    let file = std::fs::File::open(&scratch.log).expect("the scratch file exists");
    let mut view = View::with_sink(
        TextSink::File {
            file,
            path: scratch.log.clone(),
        },
        Filter::at(Level::Info),
        Filter::at(Level::Info),
        64,
    );

    for conn_id in 1..=3 {
        view.show(&pool_miss(conn_id, Level::Info));
    }

    assert_eq!(view.failures, 3, "every write failed and was counted");
    assert_eq!(
        view.ring().count(),
        3,
        "the ring does not depend on the sink"
    );
}

#[test]
fn a_sink_that_writes_nothing_is_still_a_view() {
    let view = View::with_sink(TextSink::Off, Filter::at(Level::Info), Filter::off(), 64);
    assert!(view.sink.is_off());
    assert_eq!(view.sink_name(), "off");
}
