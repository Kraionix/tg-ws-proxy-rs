//! Retention: where the window starts, what it may delete, and the clock guard.

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use logreel_file::{FileStore, FileStoreConfig, RetentionAnchor, WarningSink, segments};
use logreel_store::{EncodedBatch, Store};
use support::{ManualClock, TempDir, batch, rec};

type Warnings = Arc<Mutex<Vec<String>>>;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v1/F08_clock_jump")
}

fn seed(dir: &Path, days: &[&str]) {
    let source = fixtures().join("2026-10-01.seg");
    for day in days {
        fs::copy(&source, dir.join(format!("{day}.seg"))).expect("seed segment");
    }
}

fn names(dir: &Path) -> Vec<String> {
    segments(dir)
        .expect("segments")
        .into_iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect()
}

fn one() -> EncodedBatch {
    batch(&[rec(2, 0, 0, 1_700_000_000_000_000_000, 1, 7, b"x")], b"")
}

fn warnings() -> (Warnings, Option<WarningSink>) {
    let log: Warnings = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    let callback: Arc<dyn Fn(&str) + Send + Sync> =
        Arc::new(move |message: &str| sink.lock().expect("warnings").push(message.to_owned()));
    (log, Some(callback))
}

fn open(
    dir: &Path,
    clock: Arc<ManualClock>,
    keep_days: usize,
    anchor: RetentionAnchor,
    on_warning: Option<WarningSink>,
) -> FileStore {
    let config = FileStoreConfig {
        directory: dir.to_path_buf(),
        producer_id: 7,
        session_nonce: 0x1234_5678,
        keep_days,
        max_total_bytes: 0,
        compress: false,
        zstd_level: 3,
        retention_anchor: anchor,
        on_warning,
    };
    FileStore::with_clock(config, clock).expect("open store")
}

#[test]
fn the_newest_segment_anchor_counts_the_window_from_the_archive() {
    let dir = TempDir::new("anchor-newest");
    seed(dir.path(), &["2026-09-01", "2026-09-05", "2026-09-10"]);
    let clock = Arc::new(ManualClock::at(2026, 10, 20));
    let (log, on_warning) = warnings();
    let mut store = open(
        dir.path(),
        clock,
        3,
        RetentionAnchor::NewestSegment,
        on_warning,
    );
    store.append(&one()).expect("append");
    // The archive says "now" is the day after its newest segment, so a
    // three-day window ends at 2026-09-09 and keeps 09-10.
    assert_eq!(names(dir.path()), vec!["2026-09-10.seg", "2026-10-20.seg"]);
    let log = log.lock().expect("warnings");
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(
        log[0].contains("the clock says 2026-10-20 but the newest segment is 2026-09-10"),
        "{log:?}"
    );
}

#[test]
fn the_clock_anchor_counts_from_today() {
    let dir = TempDir::new("anchor-clock");
    seed(dir.path(), &["2026-09-01", "2026-09-05", "2026-09-10"]);
    let clock = Arc::new(ManualClock::at(2026, 10, 20));
    let (log, on_warning) = warnings();
    let mut store = open(dir.path(), clock, 3, RetentionAnchor::Clock, on_warning);
    store.append(&one()).expect("append");
    // Same archive, but the clock is the anchor: everything before 09-18 goes.
    assert_eq!(names(dir.path()), vec!["2026-10-20.seg"]);
    assert!(log.lock().expect("warnings").is_empty());
}

#[test]
fn a_clock_jump_keeps_the_days_this_run_wrote() {
    let dir = TempDir::new("written");
    let clock = Arc::new(ManualClock::at(2026, 9, 1));
    let (log, on_warning) = warnings();
    let mut store = open(
        dir.path(),
        Arc::clone(&clock),
        1,
        RetentionAnchor::NewestSegment,
        on_warning,
    );
    store.append(&one()).expect("september");
    clock.set(2026, 11, 1);
    store.append(&one()).expect("november");
    // The September file is outside a one-day window, but this run wrote it --
    // and a run that boots reading 1970 writes nothing but that kind of file.
    assert_eq!(names(dir.path()), vec!["2026-09-01.seg", "2026-11-01.seg"]);
    assert!(log.lock().expect("warnings").is_empty());
}

#[test]
fn an_empty_directory_is_not_a_warning() {
    let dir = TempDir::new("empty");
    let clock = Arc::new(ManualClock::at(2026, 10, 20));
    let (log, on_warning) = warnings();
    let mut store = open(
        dir.path(),
        clock,
        1,
        RetentionAnchor::NewestSegment,
        on_warning,
    );
    store.append(&one()).expect("append");
    assert_eq!(names(dir.path()), vec!["2026-10-20.seg"]);
    assert!(log.lock().expect("warnings").is_empty());
}

#[test]
fn keep_days_zero_keeps_every_segment() {
    let dir = TempDir::new("keep-zero");
    seed(dir.path(), &["2026-09-01", "2026-09-05", "2026-09-10"]);
    let clock = Arc::new(ManualClock::at(2026, 10, 20));
    let (log, on_warning) = warnings();
    let mut store = open(
        dir.path(),
        clock,
        0,
        RetentionAnchor::NewestSegment,
        on_warning,
    );
    store.append(&one()).expect("append");
    assert_eq!(
        names(dir.path()),
        vec![
            "2026-09-01.seg",
            "2026-09-05.seg",
            "2026-09-10.seg",
            "2026-10-20.seg"
        ]
    );
    assert!(log.lock().expect("warnings").is_empty());
}
