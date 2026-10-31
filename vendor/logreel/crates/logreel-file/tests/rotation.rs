//! Day rotation, retention, byte cap and the clock guard.

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use logreel_file::{probe, segments};
use logreel_store::Store;
use support::{ManualClock, TempDir, batch, rec};

fn one(ts: u64) -> logreel_store::EncodedBatch {
    batch(&[rec(2, 0, 0, ts, 1, 7, b"x")], b"")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v1/F08_clock_jump")
}

fn seed(dir: &Path) {
    for name in ["2026-10-01.seg", "2026-10-02.seg"] {
        fs::copy(fixtures().join(name), dir.join(name)).expect("copy fixture");
    }
}

fn names(dir: &Path) -> Vec<String> {
    segments(dir)
        .expect("segments")
        .into_iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn day_boundary_rotates() {
    let dir = TempDir::new("rotate");
    let clock = Arc::new(ManualClock::at(2026, 10, 30));
    let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
    store.append(&one(1)).expect("day 1");
    assert!(store.active_path().unwrap().ends_with("2026-10-30.seg"));
    clock.set(2026, 10, 31);
    store.append(&one(2)).expect("day 2");
    assert!(store.active_path().unwrap().ends_with("2026-10-31.seg"));
    assert_eq!(names(dir.path()), vec!["2026-10-30.seg", "2026-10-31.seg"]);
    assert_eq!(store.rotations(), 2);
}

#[test]
fn keep_days_deletes_the_oldest() {
    let dir = TempDir::new("keep");
    let clock = Arc::new(ManualClock::at(2026, 10, 30));
    let mut store = support::store(dir.path(), Arc::clone(&clock), 1, 0, false);
    store.append(&one(1)).expect("day 1");
    clock.set(2026, 10, 31);
    store.append(&one(2)).expect("day 2");
    assert_eq!(names(dir.path()), vec!["2026-10-31.seg"]);
    clock.set(2026, 11, 1);
    store.append(&one(3)).expect("day 3");
    assert_eq!(names(dir.path()), vec!["2026-11-01.seg"]);
}

#[test]
fn byte_cap_bounds_the_directory() {
    let dir = TempDir::new("cap");
    let clock = Arc::new(ManualClock::at(2026, 10, 30));
    let mut store = support::store(dir.path(), Arc::clone(&clock), 0, 0, false);
    store.append(&one(1)).expect("day 1");
    drop(store);
    let size = fs::metadata(dir.path().join("2026-10-30.seg"))
        .expect("metadata")
        .len();
    clock.set(2026, 10, 31);
    let mut store = support::store(dir.path(), Arc::clone(&clock), 0, size + 10, false);
    store.append(&one(2)).expect("day 2");
    assert_eq!(names(dir.path()), vec!["2026-10-31.seg"]);
    clock.set(2026, 11, 1);
    store.append(&one(3)).expect("day 3");
    assert_eq!(names(dir.path()), vec!["2026-11-01.seg"]);
}

#[test]
fn active_file_is_never_deleted() {
    let dir = TempDir::new("active");
    let clock = Arc::new(ManualClock::at(2026, 10, 30));
    let mut store = support::store(dir.path(), Arc::clone(&clock), 1, 1, false);
    store.append(&one(1)).expect("day 1");
    clock.set(2026, 10, 31);
    store.append(&one(2)).expect("day 2");
    let files = names(dir.path());
    assert!(files.iter().any(|name| name == "2026-10-31.seg"));
    assert_eq!(
        store.active_path().unwrap().file_name().unwrap(),
        "2026-10-31.seg"
    );
}

#[test]
fn forward_retention_ignores_created_ns() {
    let dir = TempDir::new("f08-forward");
    seed(dir.path());
    let clock = Arc::new(ManualClock::at(2026, 10, 2));
    let mut store = support::store(dir.path(), clock, 1, 0, false);
    store.append(&one(1)).expect("append");
    assert_eq!(names(dir.path()), vec!["2026-10-02.seg"]);
}

#[test]
fn byte_cap_case_matches_the_fixture() {
    let dir = TempDir::new("f08-cap");
    seed(dir.path());
    let first = fs::metadata(dir.path().join("2026-10-01.seg"))
        .expect("metadata")
        .len();
    let clock = Arc::new(ManualClock::at(2026, 10, 2));
    let mut store = support::store(dir.path(), clock, 10, first + 10, false);
    store.append(&one(1)).expect("append");
    assert_eq!(names(dir.path()), vec!["2026-10-02.seg"]);
}

#[test]
fn backwards_clock_deletes_nothing() {
    let dir = TempDir::new("f08-back");
    seed(dir.path());
    let clock = Arc::new(ManualClock::at(2026, 9, 30));
    let mut store = support::store(dir.path(), clock, 1, 0, false);
    store.append(&one(1)).expect("append");
    let files = names(dir.path());
    assert!(files.contains(&"2026-10-01.seg".to_owned()), "{files:?}");
    assert!(files.contains(&"2026-10-02.seg".to_owned()), "{files:?}");
    assert!(files.contains(&"2026-09-30.seg".to_owned()), "{files:?}");
}

#[test]
fn simulated_hours_rotate_at_midnight() {
    let dir = TempDir::new("simulated-day");
    let start = support::day_ns(2026, 10, 30) + 23 * 3_600_000_000_000;
    let clock = Arc::new(ManualClock::at(2026, 10, 30));
    clock.set_ns(start);
    let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
    for hour in 0..24u64 {
        clock.set_ns(start + hour * 3_600_000_000_000);
        store.append(&one(hour)).expect("append");
    }
    assert_eq!(names(dir.path()), vec!["2026-10-30.seg", "2026-10-31.seg"]);
    let total: u64 = segments(dir.path())
        .expect("segments")
        .iter()
        .map(|path| probe(path).expect("probe").records)
        .sum();
    assert_eq!(total, 24);
}

#[test]
fn a_seeded_segment_is_probeable_before_rotation() {
    let dir = TempDir::new("seed-probe");
    seed(dir.path());
    let probe_value = probe(&dir.path().join("2026-10-02.seg")).expect("probe");
    assert_eq!(probe_value.records, 1);
    assert_eq!(probe_value.frames, 1);
}
