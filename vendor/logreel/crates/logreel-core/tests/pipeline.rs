//! Pipeline behaviour: filtering, drop counting, batching, shutdown, ring.

mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use logreel_core::{Level, RingSettings, Settings, SharedSink, init};
use support::{BlockingSink, TestEvent, render};

fn base() -> logreel_core::SettingsBuilder {
    Settings::builder()
        .min_level(Level::Trace)
        .flush_interval(Duration::from_secs(60))
        .flush_on_warn(false)
}

#[test]
fn filtered_records_are_not_emitted() {
    let sink = SharedSink::new();
    let batches = sink.batches();
    let logger = init::<TestEvent>(
        Settings::builder()
            .min_level(Level::Warn)
            .batch_max(64)
            .build(),
        Some(render),
        Box::new(sink),
    )
    .expect("init");
    let handle = Arc::clone(logger.handle());
    assert!(!handle.emit(Level::Info, 0, 1, TestEvent::Ping(1)));
    assert!(handle.emit(Level::Warn, 0, 1, TestEvent::Ping(2)));
    assert!(!handle.emit(Level::Debug, 0, 1, TestEvent::Ping(3)));
    assert_eq!(handle.sequence(), 2);
    let report = logger.shutdown();
    assert_eq!(report.records, 1);
    let batches = batches.lock().expect("batches");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].record_count, 1);
}

#[test]
fn full_channel_drops_and_counts() {
    let sink = BlockingSink::new();
    let controller = sink.clone();
    let entered = Arc::clone(&sink.entered);
    let logger = init::<TestEvent>(
        base().channel_capacity(1).batch_max(1).build(),
        Some(render),
        Box::new(sink),
    )
    .expect("init");
    let handle = Arc::clone(logger.handle());

    assert!(handle.emit(Level::Info, 0, 3, TestEvent::Ping(1)));
    let deadline = Instant::now() + Duration::from_secs(5);
    while entered.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "writer did not reach the sink");
        std::thread::sleep(Duration::from_millis(1));
    }
    // One slot is free: the second record queues, the third is dropped.
    assert!(handle.emit(Level::Info, 0, 3, TestEvent::Ping(2)));
    assert!(!handle.emit(Level::Info, 0, 3, TestEvent::Ping(3)));
    assert_eq!(handle.dropped(), 1);

    controller.release();
    let report = logger.shutdown();
    assert_eq!(report.dropped, 1);
    assert_eq!(report.records, 2);
    assert_eq!(report.batches, 2);
    assert_eq!(controller.batches.lock().expect("batches").len(), 2);
    let _ = handle;
}

#[test]
fn shutdown_drains_and_flushes() {
    let sink = SharedSink::new();
    let batches = sink.batches();
    let logger = init::<TestEvent>(
        base().channel_capacity(256).batch_max(1000).build(),
        Some(render),
        Box::new(sink),
    )
    .expect("init");
    let handle = Arc::clone(logger.handle());
    for value in 0..100 {
        assert!(handle.emit(Level::Info, 0, 0, TestEvent::Ping(value)));
    }
    let report = logger.shutdown();
    assert_eq!(report.records, 100);
    assert_eq!(report.batches, 1);
    let batches = batches.lock().expect("batches");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].record_count, 100);
}

#[test]
fn batches_split_at_batch_max() {
    let sink = SharedSink::new();
    let batches = sink.batches();
    let logger = init::<TestEvent>(
        base().channel_capacity(64).batch_max(2).build(),
        Some(render),
        Box::new(sink),
    )
    .expect("init");
    let handle = Arc::clone(logger.handle());
    for value in 0..5 {
        assert!(handle.emit(Level::Info, 0, 0, TestEvent::Ping(value)));
    }
    let report = logger.shutdown();
    assert_eq!(report.records, 5);
    let batches = batches.lock().expect("batches");
    let counts: Vec<u32> = batches.iter().map(|batch| batch.record_count).collect();
    assert_eq!(counts, vec![2, 2, 1]);
}

#[test]
fn sequence_is_monotonic_and_filtered_calls_do_not_consume_it() {
    let sink = SharedSink::new();
    let logger = init::<TestEvent>(
        base().min_level(Level::Warn).batch_max(64).build(),
        Some(render),
        Box::new(sink),
    )
    .expect("init");
    let handle = Arc::clone(logger.handle());
    for value in 0..3 {
        assert!(handle.emit(Level::Warn, 0, 0, TestEvent::Ping(value)));
    }
    assert_eq!(handle.sequence(), 4);
    assert!(!handle.emit(Level::Info, 0, 0, TestEvent::Ping(9)));
    assert_eq!(handle.sequence(), 4);
    assert_eq!(handle.dropped(), 0);
    let _ = logger.shutdown();
}

#[test]
fn live_filter_changes_apply_to_the_handle() {
    let sink = SharedSink::new();
    let logger = init::<TestEvent>(base().batch_max(64).build(), Some(render), Box::new(sink))
        .expect("init");
    let handle = Arc::clone(logger.handle());
    assert!(handle.emit(Level::Info, 0, 0, TestEvent::Empty));
    handle.filters().set(0, None);
    assert!(!handle.emit(Level::Info, 0, 0, TestEvent::Empty));
    assert!(handle.emit(Level::Info, 1, 0, TestEvent::Empty));
    let _ = logger.shutdown();
}

#[test]
fn ring_retains_rendered_lines() {
    let sink = SharedSink::new();
    let logger = init::<TestEvent>(
        base()
            .batch_max(1)
            .flush_interval(Duration::from_millis(5))
            .ring(RingSettings {
                capacity: 8,
                max_bytes: 4096,
                floor: Level::Trace,
            })
            .build(),
        Some(render),
        Box::new(sink),
    )
    .expect("init");
    let handle = Arc::clone(logger.handle());
    assert!(handle.emit(Level::Info, 0, 42, TestEvent::Ping(7)));
    assert!(handle.emit(Level::Info, 0, 0, TestEvent::Empty));
    let deadline = Instant::now() + Duration::from_secs(5);
    while handle.dump_ring().len() < 2 {
        assert!(Instant::now() < deadline, "ring did not receive lines");
        std::thread::sleep(Duration::from_millis(2));
    }
    let lines = handle.dump_ring();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("ping 7"));
    assert!(lines[0].contains("[conn=42]"));
    assert!(lines[1].contains("empty"));
    let _ = logger.shutdown();
}
