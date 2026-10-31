//! Crash recovery: torn tails are repaired, corruption is refused, locks work.

mod support;

use std::fs;
use std::io::Write as _;
use std::sync::Arc;

use logreel_file::{Scan, probe, segments};
use logreel_store::{ErrorKind, Store};
use support::{ManualClock, TempDir, batch, rec};

fn one(ts: u64) -> logreel_store::EncodedBatch {
    batch(&[rec(2, 0, 0, ts, 1, 5, b"payload")], b"")
}

#[test]
fn torn_tail_is_repaired_on_open() {
    let dir = TempDir::new("recover");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    {
        let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
        store.append(&one(1)).expect("append");
    }
    let file = segments(dir.path()).expect("segments").remove(0);
    let mut bytes = fs::read(&file).expect("read");
    bytes.extend_from_slice(&[0xAA; 6]);
    fs::write(&file, bytes).expect("write");

    let mut store = support::store(dir.path(), clock, 7, 0, false);
    store.append(&one(2)).expect("append after torn tail");
    drop(store);
    let probe_value = probe(&file).expect("probe");
    assert_eq!(probe_value.frames, 2);
    assert_eq!(probe_value.records, 2);
    assert_eq!(probe_value.tail, logreel_file::TailState::Clean);
}

#[test]
fn corruption_is_refused_by_the_writer() {
    let dir = TempDir::new("corrupt");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    {
        let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
        store.append(&one(1)).expect("append");
    }
    let file = segments(dir.path()).expect("segments").remove(0);
    let mut bytes = fs::read(&file).expect("read");
    bytes[70] ^= 0xFF;
    fs::write(&file, bytes).expect("write");

    let mut store = support::store(dir.path(), clock, 7, 0, false);
    let error = store.append(&one(2)).expect_err("corruption must refuse");
    assert_eq!(error.kind(), ErrorKind::Corrupt);
}

#[test]
fn a_live_lock_is_reported() {
    let dir = TempDir::new("lock");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    let mut first = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
    first.append(&one(1)).expect("first append");
    let mut second = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
    let error = second.append(&one(2)).expect_err("locked");
    assert_eq!(error.kind(), ErrorKind::Locked);
    drop(first);
    second.append(&one(3)).expect("lock released");
}

#[test]
fn a_stale_lock_is_reclaimed() {
    let dir = TempDir::new("stale");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    {
        let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
        store.append(&one(1)).expect("append");
    }
    let lock = dir.path().join("2026-10-31.seg.lock");
    let mut file = fs::File::create(&lock).expect("lock");
    write!(file, "999999").expect("pid");
    drop(file);
    let mut store = support::store(dir.path(), clock, 7, 0, false);
    store.append(&one(2)).expect("stale lock reclaimed");
    drop(store);
    assert!(!lock.exists());
}

#[test]
fn every_truncation_is_safe() {
    let dir = TempDir::new("matrix");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    {
        let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
        store.append(&one(1)).expect("append 1");
        store.append(&one(2)).expect("append 2");
    }
    let file = segments(dir.path()).expect("segments").remove(0);
    let bytes = fs::read(&file).expect("read");
    assert!(bytes.len() > 56);
    let cut = dir.path().join("cut.seg");
    for length in 0..=bytes.len() {
        fs::write(&cut, &bytes[..length]).expect("write prefix");
        let _ = probe(&cut);
        if let Ok(mut scan) = Scan::open(&cut) {
            let mut records = 0;
            loop {
                match scan.next_record() {
                    None => break,
                    Some(Ok(_)) => {
                        records += 1;
                        assert!(records < 10_000, "scan did not terminate");
                    }
                    Some(Err(_)) => break,
                }
            }
        }
    }
}
