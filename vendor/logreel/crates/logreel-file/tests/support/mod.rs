//! Shared helpers for the file backend tests.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use logreel_file::{Clock, FileStore, FileStoreConfig};
use logreel_store::EncodedBatch;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "logreel-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp dir");
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    pub(crate) fn at(y: i64, m: u32, d: u32) -> Self {
        Self {
            now: AtomicU64::new(day_ns(y, m, d) + 1),
        }
    }

    pub(crate) fn set(&self, y: i64, m: u32, d: u32) {
        self.now.store(day_ns(y, m, d) + 1, Ordering::Relaxed);
    }

    pub(crate) fn set_ns(&self, ns: u64) {
        self.now.store(ns, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now_ns(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

pub(crate) fn day_ns(y: i64, m: u32, d: u32) -> u64 {
    (days_from_civil(y, m, d) * 86_400_000_000_000) as u64
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

pub(crate) struct Rec<'a> {
    pub(crate) level: u8,
    pub(crate) category: u8,
    pub(crate) kind: u16,
    pub(crate) ts: u64,
    pub(crate) seq: u32,
    pub(crate) conn: u64,
    pub(crate) payload: &'a [u8],
}

pub(crate) fn rec<'a>(
    level: u8,
    category: u8,
    kind: u16,
    ts: u64,
    seq: u32,
    conn: u64,
    payload: &'a [u8],
) -> Rec<'a> {
    Rec {
        level,
        category,
        kind,
        ts,
        seq,
        conn,
        payload,
    }
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

pub(crate) fn batch(records: &[Rec<'_>], domain: &[u8]) -> EncodedBatch {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(records.len() as u32).to_le_bytes());
    let first = records.iter().map(|record| record.ts).min().unwrap_or(0);
    let last = records.iter().map(|record| record.ts).max().unwrap_or(0);
    payload.extend_from_slice(&first.to_le_bytes());
    payload.extend_from_slice(&last.to_le_bytes());
    payload.extend_from_slice(&1u16.to_le_bytes());
    let mut mask = 0u8;
    for record in records {
        if record.kind < 8 {
            mask |= 1 << record.kind;
        }
    }
    payload.push(mask);
    payload.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    payload.extend_from_slice(domain);
    for record in records {
        payload.push(record.level);
        payload.push(record.category);
        payload.extend_from_slice(&record.kind.to_le_bytes());
        payload.extend_from_slice(&record.ts.to_le_bytes());
        put_varint(&mut payload, u64::from(record.seq));
        put_varint(&mut payload, record.conn);
        put_varint(&mut payload, record.payload.len() as u64);
        payload.extend_from_slice(record.payload);
    }
    EncodedBatch::new(
        1,
        [0x11; 16],
        8,
        records.len() as u32,
        first,
        last,
        domain.to_vec().into_boxed_slice(),
        payload.into_boxed_slice(),
    )
}

pub(crate) fn store(
    directory: &Path,
    clock: Arc<ManualClock>,
    keep_days: usize,
    max_total_bytes: u64,
    compress: bool,
) -> FileStore {
    let config = FileStoreConfig {
        directory: directory.to_path_buf(),
        producer_id: 7,
        session_nonce: 0x1234_5678,
        keep_days,
        max_total_bytes,
        compress,
        zstd_level: 3,
        retention_anchor: logreel_file::RetentionAnchor::Clock,
        on_warning: None,
    };
    FileStore::with_clock(config, clock).expect("open store")
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
