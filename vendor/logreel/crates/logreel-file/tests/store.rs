//! Store roundtrip: append, reopen, scan and probe.

mod support;

use std::sync::Arc;

use logreel_file::{Scan, probe, segments};
use logreel_store::{Durability, Store};
use support::{ManualClock, TempDir, batch, rec};

fn sample_batch(ts: u64) -> logreel_store::EncodedBatch {
    batch(
        &[
            rec(2, 0, 0, ts, 1, 42, b"opened"),
            rec(3, 1, 1, ts + 1, 2, 42, b"closed"),
        ],
        b"dc=1",
    )
}

fn collect_records(path: &std::path::Path) -> Vec<(u8, u16, u64, u32, u64, Vec<u8>)> {
    let mut scan = Scan::open(path).expect("scan");
    let mut out = Vec::new();
    loop {
        match scan.next_record() {
            None => break,
            Some(Ok(record)) => out.push((
                record.level,
                record.kind,
                record.ts_ns,
                record.seq,
                record.conn_id,
                record.payload.to_vec(),
            )),
            Some(Err(error)) => panic!("{error}"),
        }
    }
    out
}

#[test]
fn append_reopen_scan_roundtrip() {
    let dir = TempDir::new("roundtrip");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    {
        let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
        store.append(&sample_batch(1_000)).expect("append 1");
        store.append(&sample_batch(2_000)).expect("append 2");
        store.sync(Durability::Immediate).expect("sync");
        assert!(store.active_path().is_some());
    }
    let files = segments(dir.path()).expect("segments");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].file_name().unwrap(), "2026-10-31.seg");
    let probe_value = probe(&files[0]).expect("probe");
    assert_eq!(probe_value.frames, 2);
    assert_eq!(probe_value.records, 4);
    assert_eq!(probe_value.sha256_hex().len(), 64);
    assert_eq!(probe_value.conn_ids, vec![42]);

    {
        let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
        store.append(&sample_batch(3_000)).expect("append 3");
        let scanned: Vec<_> = store
            .scan()
            .expect("scan")
            .collect::<Result<Vec<_>, _>>()
            .expect("batches");
        assert_eq!(scanned.len(), 3);
        assert_eq!(
            scanned.iter().map(|batch| batch.record_count).sum::<u32>(),
            6
        );
    }

    let records = collect_records(&files[0]);
    assert_eq!(records.len(), 6);
    assert_eq!(records[0].0, 2);
    assert_eq!(records[0].5, b"opened");
    assert_eq!(records[4].2, 3_000);
}

#[test]
fn empty_batch_is_allowed() {
    let dir = TempDir::new("empty-batch");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    let mut store = support::store(dir.path(), clock, 7, 0, false);
    store.append(&batch(&[], b"")).expect("empty append");
    store.sync(Durability::Immediate).expect("sync");
    let file = segments(dir.path()).expect("segments").remove(0);
    let probe_value = probe(&file).expect("probe");
    assert_eq!(probe_value.frames, 1);
    assert_eq!(probe_value.records, 0);
}

#[test]
fn durability_modes_do_not_fail() {
    let dir = TempDir::new("durability");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    let mut store = support::store(dir.path(), clock, 7, 0, false);
    store.append(&sample_batch(1)).expect("append");
    store.sync(Durability::Eventual).expect("eventual");
    store.sync(Durability::OnWarn).expect("on warn");
    store.sync(Durability::Immediate).expect("immediate");
}

#[cfg(feature = "zstd")]
#[test]
fn compressed_frames_roundtrip() {
    let dir = TempDir::new("zstd");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    let mut store = support::store(dir.path(), clock, 7, 0, true);
    let batch = sample_batch(5_000);
    store.append(&batch).expect("append");
    store.sync(Durability::Immediate).expect("sync");
    let file = segments(dir.path()).expect("segments").remove(0);
    let probe_value = probe(&file).expect("probe");
    assert!(probe_value.header.contains_zstd());
    assert_eq!(probe_value.records, 2);
    let records = collect_records(&file);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].5, b"opened");
}

#[test]
fn scan_stops_at_a_torn_tail() {
    let dir = TempDir::new("torn-store");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    let mut store = support::store(dir.path(), clock, 7, 0, false);
    store.append(&sample_batch(1)).expect("append");
    store.append(&sample_batch(2)).expect("append");
    store.sync(Durability::Immediate).expect("sync");
    let file = segments(dir.path()).expect("segments").remove(0);
    let len = std::fs::metadata(&file).expect("metadata").len();
    let mut bytes = std::fs::read(&file).expect("read");
    bytes.truncate((len - 3) as usize);
    std::fs::write(&file, bytes).expect("write");
    let mut count = 0;
    let mut scan = Scan::open(&file).expect("scan");
    loop {
        match scan.next_record() {
            None => break,
            Some(Ok(_)) => count += 1,
            Some(Err(error)) => panic!("{error}"),
        }
    }
    assert_eq!(count, 2);
}

#[test]
fn multiple_days_are_scanned_in_order() {
    let dir = TempDir::new("multi-day");
    let clock = Arc::new(ManualClock::at(2026, 10, 30));
    let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
    store.append(&sample_batch(1)).expect("day 1");
    clock.set(2026, 10, 31);
    store.append(&sample_batch(2)).expect("day 2");
    let files = segments(dir.path()).expect("segments");
    assert_eq!(files.len(), 2);
    assert!(files[0].ends_with("2026-10-30.seg"));
    assert!(files[1].ends_with("2026-10-31.seg"));
    let batches: Vec<_> = store
        .scan()
        .expect("scan")
        .collect::<Result<Vec<_>, _>>()
        .expect("batches");
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].first_ts_ns, 1);
    assert_eq!(batches[1].first_ts_ns, 2);
}

#[test]
fn an_uncompressed_file_refuses_compressed_frames() {
    let dir = TempDir::new("compress-mismatch");
    let clock: Arc<dyn logreel_file::Clock> = Arc::new(ManualClock::at(2026, 10, 31));
    {
        let config = logreel_file::FileStoreConfig {
            directory: dir.path().to_path_buf(),
            producer_id: 1,
            session_nonce: 0,
            keep_days: 7,
            max_total_bytes: 0,
            compress: false,
            zstd_level: 3,
            retention_anchor: logreel_file::RetentionAnchor::Clock,
            on_warning: None,
        };
        let mut store = logreel_file::FileStore::with_clock(config, Arc::clone(&clock))
            .expect("open plain store");
        store.append(&sample_batch(1_000)).expect("append");
        store.sync(Durability::Immediate).expect("sync");
    }

    let config = logreel_file::FileStoreConfig {
        directory: dir.path().to_path_buf(),
        producer_id: 1,
        session_nonce: 0,
        keep_days: 7,
        max_total_bytes: 0,
        compress: true,
        zstd_level: 1,
        retention_anchor: logreel_file::RetentionAnchor::Clock,
        on_warning: None,
    };
    let mut store =
        logreel_file::FileStore::with_clock(config, clock).expect("open compressed store");
    // The header is written by the first append, so that is where the mismatch
    // surfaces: a file whose header says "not compressed" must not start
    // receiving frames the reader has no reason to expect.
    let error = store
        .append(&sample_batch(2_000))
        .expect_err("the existing file cannot take compressed frames");
    assert_eq!(error.kind(), logreel_store::ErrorKind::Refused);
}

#[test]
fn an_out_of_range_zstd_level_is_refused_at_open() {
    let dir = TempDir::new("zstd-level");
    let config = logreel_file::FileStoreConfig {
        directory: dir.path().to_path_buf(),
        producer_id: 1,
        session_nonce: 0,
        keep_days: 7,
        max_total_bytes: 0,
        compress: false,
        zstd_level: 0,
        retention_anchor: logreel_file::RetentionAnchor::Clock,
        on_warning: None,
    };
    let error = logreel_file::FileStore::open(config).expect_err("level 0 is refused");
    assert_eq!(error.kind(), logreel_store::ErrorKind::Refused);
}

#[cfg(feature = "zstd")]
#[test]
fn the_compression_level_is_taken_from_the_config() {
    let dir = TempDir::new("zstd-roundtrip");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    let config = logreel_file::FileStoreConfig {
        directory: dir.path().to_path_buf(),
        producer_id: 1,
        session_nonce: 0,
        keep_days: 7,
        max_total_bytes: 0,
        compress: true,
        zstd_level: 1,
        retention_anchor: logreel_file::RetentionAnchor::Clock,
        on_warning: None,
    };
    let mut store = logreel_file::FileStore::with_clock(config, clock).expect("open");
    store.append(&sample_batch(1_000)).expect("append");
    store.sync(Durability::Immediate).expect("sync");
    drop(store);

    let files = segments(dir.path()).expect("segments");
    assert_eq!(files.len(), 1);
    let value = probe(&files[0]).expect("probe");
    assert_eq!(value.frames, 1);
    assert_eq!(value.records, 2);
    let records = collect_records(&files[0]);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].5, b"opened");
}

#[test]
fn prime_creates_the_day_file_and_takes_its_lock() {
    let dir = TempDir::new("prime");
    let clock: Arc<dyn logreel_file::Clock> = Arc::new(ManualClock::at(2026, 10, 31));
    let config = logreel_file::FileStoreConfig {
        directory: dir.path().to_path_buf(),
        producer_id: 1,
        session_nonce: 0,
        keep_days: 7,
        max_total_bytes: 0,
        compress: false,
        zstd_level: 3,
        retention_anchor: logreel_file::RetentionAnchor::Clock,
        on_warning: None,
    };
    let mut first =
        logreel_file::FileStore::with_clock(config.clone(), Arc::clone(&clock)).expect("open");
    let path = first
        .prime(1, 22, [0x42; 16])
        .expect("the day file is created");
    assert_eq!(path.file_name().unwrap(), "2026-10-31.seg");
    assert_eq!(std::fs::metadata(&path).expect("exists").len(), 56);
    assert_eq!(first.active_path(), Some(path.as_path()));

    let mut second =
        logreel_file::FileStore::with_clock(config, clock).expect("the second store opens");
    let error = second.prime(1, 22, [0x42; 16]).expect_err("locked");
    assert_eq!(error.kind(), logreel_store::ErrorKind::Locked);
}

#[test]
fn a_batch_reads_back_with_its_records() {
    let dir = TempDir::new("decoded");
    let clock = Arc::new(ManualClock::at(2026, 10, 31));
    {
        let mut store = support::store(dir.path(), Arc::clone(&clock), 7, 0, false);
        store.append(&sample_batch(1_000)).expect("append 1");
        store.append(&sample_batch(2_000)).expect("append 2");
        store.sync(Durability::Immediate).expect("sync");
    }

    let files = segments(dir.path()).expect("segments");
    let mut reader = logreel_file::SegmentReader::open(&files[0]).expect("reader");
    let first = reader
        .next_decoded_batch()
        .expect("first batch")
        .expect("valid");
    assert_eq!(first.batch.record_count, 2);
    assert_eq!(first.records.len(), 2);
    assert_eq!(first.records[0].seq, 1);
    assert_eq!(first.records[0].kind, 0);
    assert_eq!(first.records[0].payload, b"opened");
    assert_eq!(first.records[1].conn_id, 42);

    let second = reader
        .next_decoded_batch()
        .expect("second batch")
        .expect("valid");
    assert_eq!(second.batch.first_ts_ns, 2_000);
    assert!(reader.next_decoded_batch().is_none(), "end of file");
}
