//! Day-segment storage: one redb file per UTC day, behind the `BatchSink` seam.
//!
//! # Why a file per day
//!
//! A day is the unit an operator reasons in ("what happened yesterday"), it is
//! what retention counts, and it is the cheapest thing to delete. Rotation is
//! then a file boundary rather than a compaction pass, and the file name
//! (`2026-10-11.redb`) is the index over the whole directory — both for the
//! reader and for the sweep that removes old ones.
//!
//! # Why redb
//!
//! It is pure Rust, which matters more than anything else here: the same crate
//! has to cross-build for `aarch64-unknown-linux-musl`, `armv7`, `mipsel` and
//! the macOS targets, and a C storage engine would drag a cross toolchain into
//! every one of them on top of the one `ring` and `zstd` already need. It also
//! gives typed keys (so `(conn_id, ts)` is a key, not a hand-rolled big-endian
//! byte layout) and per-transaction durability, which is what `--log-durability`
//! is.
//!
//! # What a value is
//!
//! One byte of framing followed by an encoded `LogBatch`. The framing byte says
//! whether the rest is raw or a zstd frame, which is worth a byte per batch: it
//! lets `--log-compress` change between runs without making the previous
//! segment unreadable, and it means the reader never has to guess from the
//! first byte of a protobuf message.
//!
//! # Durability, honestly
//!
//! redb has two levels, `Immediate` (fsync before commit returns) and `None` (a
//! commit that lives in this process's memory). A `None` commit becomes
//! persistent when a later `Immediate` commit follows it — so `eventual` here
//! is not "never fsync", it is "fsync every [`EVENTUAL_SYNC_INTERVAL`] instead
//! of on every flush", and a clean close always syncs. The loss window under
//! sudden power loss is therefore the sync interval, not a flush.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, Instant};

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::warn;

use super::LogError;
use super::schema::{LogBatch, fingerprint};
use super::writer::{BatchSink, WriterError};

/// All batches of the segment, ordered by time.
///
/// `(ts_first_ns, seq)` — the batch's earliest timestamp, with the sequence
/// number of its first record as the tie-break, so lexicographic order is
/// temporal order and no two batches ever share a key.
const MAIN: TableDefinition<(u64, u32), &[u8]> = TableDefinition::new("STOR:main");

/// Per-session index: `(conn_id, ts_first_ns)` → the `STOR:main` key. A prefix
/// scan on `conn_id` answers "everything that happened to this connection"
/// without decoding the segment.
const BY_CONN: TableDefinition<(u64, u64), (u64, u32)> = TableDefinition::new("STOR:by_conn");

/// Segment metadata, written once at open and never updated.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("STOR:meta");

const META_SCHEMA_HASH: &str = "schema_hash";
const META_APP_VERSION: &str = "app_version";
const META_CREATED_NS: &str = "created_ns";
const META_WRITER_PROTOCOL: &str = "writer_protocol";

/// Value framing: the payload is a `LogBatch` as encoded, or a zstd frame of one.
const VALUE_RAW: u8 = 0;
const VALUE_ZSTD: u8 = 1;

/// Container version: the value framing, the table names and the key layout.
/// Independent of `schema::SCHEMA_VERSION`, which is about the records inside.
pub const WRITER_PROTOCOL: u32 = 1;

/// Segments kept by default, counting today.
pub const DEFAULT_RETENTION_DAYS: u32 = 7;

/// zstd level 1 — the artifact's `CONST:ZSTD_LEVEL_L1`, chosen for a router's
/// CPU rather than for the last few percent of ratio.
#[cfg(feature = "log-zstd")]
const ZSTD_LEVEL: i32 = 1;

/// redb defaults to a 1 GiB cache. This ships on devices with 64 MB of RAM.
const CACHE_SIZE: usize = 4 * 1024 * 1024;

/// How often `eventual` durability turns its in-memory commits into a real
/// fsync. The trade is the loss window under power loss against flash wear:
/// 2 880 fsyncs a day here, against 43 200 for `immediate` at the default flush
/// interval.
const EVENTUAL_SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// Backoff after a failed write, capped: 1, 2, 4, 8, 16, 60, 60, … seconds.
const BACKOFF_STEPS: [Duration; 6] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(60),
];

const SEGMENT_SUFFIX: &str = ".redb";
const NANOS_PER_DAY: u64 = 86_400_000_000_000;

/// Whether a batch is compressed before it is stored.
///
/// Applied per batch, so a segment can hold both; see the module docs. `ZstdL1`
/// exists only in a build with the `log-zstd` feature: without it the mode is
/// not offered at all rather than offered and silently ignored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compression {
    #[default]
    None,
    #[cfg(feature = "log-zstd")]
    ZstdL1,
}

/// How much a commit is worth.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DurabilityMode {
    /// fsync every [`EVENTUAL_SYNC_INTERVAL`] rather than every flush.
    #[default]
    Eventual,
    /// fsync before every commit returns.
    Immediate,
}

/// Storage configuration, built by the wiring stage from the `--log-*` flags.
#[derive(Clone, Debug)]
pub struct Options {
    pub compress: Compression,
    pub durability: DurabilityMode,
    /// Segments to keep, counting today. `0` keeps every segment.
    pub retention_days: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            compress: Compression::None,
            durability: DurabilityMode::Eventual,
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

/// Writes batches into `<dir>/<today>.redb`, rotating at the UTC date change.
pub(crate) struct FileSink {
    dir: PathBuf,
    options: Options,
    segment: Option<Segment>,
    day: Option<i64>,
    backoff: usize,
    retry_at: Option<Instant>,
}

impl FileSink {
    /// Opens (or creates) today's segment. Startup failures are fatal and
    /// reported to the operator; once running, the sink degrades instead.
    pub(crate) fn open(dir: &Path, options: Options) -> Result<Self, LogError> {
        check_filesystem(dir)?;
        create_dir(dir)?;

        let mut sink = Self {
            dir: dir.to_path_buf(),
            options,
            segment: None,
            day: None,
            backoff: 0,
            retry_at: None,
        };

        let day = today();
        let path = sink.segment_path(day);
        sink.segment = Some(Segment::open(&path).map_err(|error| start_error(error, &path))?);
        sink.day = Some(day);
        sink.sweep_retention(day);
        Ok(sink)
    }

    fn segment_path(&self, day: i64) -> PathBuf {
        self.dir.join(format!("{}{SEGMENT_SUFFIX}", day_name(day)))
    }

    /// Closes the current segment and opens the one for `day`.
    pub(super) fn rotate(&mut self, day: i64) -> Result<(), WriterError> {
        // Dropping the old segment commits and fsyncs it.
        drop(self.segment.take());
        let path = self.segment_path(day);
        self.segment = Some(Segment::open(&path)?);
        self.day = Some(day);
        self.sweep_retention(day);
        Ok(())
    }

    /// Deletes segments older than the retention window.
    ///
    /// Names, not modification times: the date in the file name is the date the
    /// records belong to, and an `mtime` moves whenever a file is copied or a
    /// clock is wrong. Anything whose name is not a `YYYY-MM-DD.redb` date is
    /// left alone — this directory may not be ours exclusively.
    fn sweep_retention(&self, day: i64) {
        if self.options.retention_days == 0 {
            return;
        }
        let keep_from = day - i64::from(self.options.retention_days) + 1;
        let cutoff = day_name(keep_from);

        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) => {
                warn!(dir = %self.dir.display(), %error, "cannot sweep log retention");
                return;
            }
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if segment_day(name).is_some_and(|segment| segment < cutoff.as_str())
                && let Err(error) = fs::remove_file(entry.path())
            {
                warn!(file = %entry.path().display(), %error, "cannot delete an expired segment");
            }
        }
    }

    fn on_failure(&mut self, error: WriterError) -> WriterError {
        // A segment that cannot be written to is not necessarily a segment that
        // cannot be reopened: a removed USB stick becomes writable again when it
        // is plugged back in. Dropping the handle makes the next attempt go
        // through `Segment::open`, which is what that recovery needs.
        if matches!(error, WriterError::Io(_)) {
            self.segment = None;
        }
        let delay = BACKOFF_STEPS[self.backoff.min(BACKOFF_STEPS.len() - 1)];
        self.backoff = (self.backoff + 1).min(BACKOFF_STEPS.len() - 1);
        self.retry_at = Some(Instant::now() + delay);
        error
    }

    fn on_success(&mut self) {
        self.backoff = 0;
        self.retry_at = None;
    }
}

impl BatchSink for FileSink {
    fn write(&mut self, batch: &LogBatch) -> Result<(), WriterError> {
        if batch.records.is_empty() {
            return Ok(());
        }

        // While backing off, the batch is dropped without another attempt and
        // without another warning: the failure that started the backoff was
        // reported once, and a sink that warns every two seconds about the same
        // unplugged disk is worse than one that is quiet about it.
        if self
            .retry_at
            .is_some_and(|retry_at| Instant::now() < retry_at)
        {
            return Ok(());
        }

        // A segment is rotated forward when the date moves, and never back: a
        // clock correction that lands in the previous day must not split the
        // file, and a segment lost to a failure is reopened for the day it was
        // on rather than for whatever the clock says now.
        let today = today();
        let day = match self.day {
            Some(open) if open >= today => open,
            _ => today,
        };
        if (self.segment.is_none() || self.day != Some(day))
            && let Err(error) = self.rotate(day)
        {
            return Err(self.on_failure(error));
        }

        let durability = durability_of(self.options.durability);
        let result = self
            .segment
            .as_mut()
            .expect("a segment was opened above")
            .write(batch, self.options.compress, durability);

        match result {
            Ok(()) => {
                self.on_success();
                Ok(())
            }
            Err(error) => Err(self.on_failure(error)),
        }
    }
}

/// One open day-segment.
struct Segment {
    db: Database,
    unsynced: bool,
    last_sync: Instant,
}

impl Segment {
    fn open(path: &Path) -> Result<Self, WriterError> {
        pre_create(path)?;

        let db = Database::builder()
            .set_cache_size(CACHE_SIZE)
            // `create` opens an existing segment as it is: a restart inside the
            // same UTC day appends to the day's file instead of starting a new
            // one.
            .create(path)
            .map_err(|error| match error {
                redb::DatabaseError::DatabaseAlreadyOpen => WriterError::Conflict,
                other => WriterError::Segment(other.to_string()),
            })?;

        let mut segment = Self {
            db,
            unsynced: false,
            last_sync: Instant::now(),
        };
        segment.write_meta()?;
        Ok(segment)
    }

    /// Writes the segment's provenance, once, at creation.
    fn write_meta(&mut self) -> Result<(), WriterError> {
        let mut transaction = self.db.begin_write().map_err(segment_error)?;
        let exists = {
            let table = transaction.open_table(META).map_err(segment_error)?;
            table
                .get(META_SCHEMA_HASH)
                .map_err(segment_error)?
                .is_some()
        };
        if !exists {
            let created_ns = super::now_ns();
            let mut table = transaction.open_table(META).map_err(segment_error)?;
            table
                .insert(META_SCHEMA_HASH, fingerprint().to_le_bytes().as_slice())
                .map_err(segment_error)?;
            table
                .insert(META_APP_VERSION, env!("CARGO_PKG_VERSION").as_bytes())
                .map_err(segment_error)?;
            table
                .insert(META_CREATED_NS, created_ns.to_le_bytes().as_slice())
                .map_err(segment_error)?;
            table
                .insert(
                    META_WRITER_PROTOCOL,
                    WRITER_PROTOCOL.to_le_bytes().as_slice(),
                )
                .map_err(segment_error)?;
        }

        // Metadata is the one thing that has to be on disk immediately: every
        // other commit can be re-derived from the segments around it, but a
        // segment without its provenance is one a reader has to guess about.
        // redb refuses to lower durability after a persistent change, and this
        // transaction has none, so this is the "keep the default" branch too.
        if !exists {
            let _ = transaction.set_durability(Durability::Immediate);
        }
        transaction.commit().map_err(|error| {
            WriterError::Segment(format!("cannot write segment metadata: {error}"))
        })?;
        self.unsynced = false;
        self.last_sync = Instant::now();
        Ok(())
    }

    fn write(
        &mut self,
        batch: &LogBatch,
        compress: Compression,
        durability: Durability,
    ) -> Result<(), WriterError> {
        let header = batch
            .header
            .as_ref()
            .ok_or_else(|| WriterError::Segment("a batch without a header".to_string()))?;
        let key = (header.ts_first_ns, batch.records[0].seq);
        let value = encode(batch, compress)?;

        let mut transaction = self.db.begin_write().map_err(segment_error)?;
        // Unreachable in practice: it fails only for a transaction that created
        // or deleted a persistent savepoint, and this writer uses none.
        let _ = transaction.set_durability(durability);

        {
            let mut main = transaction.open_table(MAIN).map_err(segment_error)?;
            main.insert(key, value.as_slice()).map_err(segment_error)?;

            let mut by_conn = transaction.open_table(BY_CONN).map_err(segment_error)?;
            for conn_id in &header.conn_ids {
                by_conn
                    .insert((*conn_id, header.ts_first_ns), key)
                    .map_err(segment_error)?;
            }
        }

        transaction
            .commit()
            .map_err(|error| WriterError::Segment(format!("commit failed: {error}")))?;

        self.unsynced = matches!(durability, Durability::None);
        if !self.unsynced {
            self.last_sync = Instant::now();
        } else if self.last_sync.elapsed() >= EVENTUAL_SYNC_INTERVAL {
            self.sync()?;
        }
        Ok(())
    }

    /// Turns the commits held in memory into a durable state: an empty
    /// `Immediate` commit persists everything before it.
    fn sync(&mut self) -> Result<(), WriterError> {
        if !self.unsynced {
            return Ok(());
        }
        let mut transaction = self.db.begin_write().map_err(segment_error)?;
        let _ = transaction.set_durability(Durability::Immediate);
        transaction
            .commit()
            .map_err(|error| WriterError::Segment(format!("sync failed: {error}")))?;
        self.unsynced = false;
        self.last_sync = Instant::now();
        Ok(())
    }
}

impl Drop for Segment {
    /// Last chance to persist: rotation, a dropped sink and the end of the
    /// process all arrive here, and a clean stop is supposed to lose nothing.
    fn drop(&mut self) {
        if let Err(error) = self.sync() {
            warn!(error = %error, "could not flush the log segment on close");
        }
    }
}

// ── Reading back ───────────────────────────────────────────────────────────
//
// Nothing in the binary reads a segment: `--log-dir` only writes, and the
// reader that would consume these is a later iteration (S1). Their callers are
// the tests that check a segment decodes record-for-record, so the allow is per
// item — anything else that goes unused in here is still a warning.

/// Reads a whole day back, in time order.
///
/// Loads the day into memory, which is the right shape for a post-mortem of one
/// segment and the wrong one for a reader that scans a month — the reading
/// iteration is where that gets fixed.
#[allow(dead_code)]
pub(crate) fn iter_batches(dir: &Path, date: &str) -> Result<Vec<LogBatch>, LogError> {
    let (db, transaction) = open_for_read(dir, date)?;
    let table = match transaction.open_table(MAIN) {
        Ok(table) => table,
        // redb creates a table on its first write, so a segment that recorded
        // nothing has no `STOR:main` at all — a run whose every event was
        // filtered out, which is what `--log-level error` over a healthy proxy
        // leaves behind. An empty day, not a corrupt file.
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(error) => return Err(LogError::Segment(error.to_string())),
    };

    let mut batches = Vec::new();
    for entry in table
        .iter()
        .map_err(|error| LogError::Segment(error.to_string()))?
    {
        let (_, value) = entry.map_err(|error| LogError::Segment(error.to_string()))?;
        batches.push(decode(value.value())?);
    }
    drop(db);
    Ok(batches)
}

/// Reads back the batches that mention one connection, via `STOR:by_conn`.
#[allow(dead_code)]
pub(crate) fn iter_conn_batches(
    dir: &Path,
    date: &str,
    conn_id: u64,
) -> Result<Vec<LogBatch>, LogError> {
    let (db, transaction) = open_for_read(dir, date)?;
    let index = match transaction.open_table(BY_CONN) {
        Ok(index) => index,
        // No index means no batch was ever indexed, which means no records
        // (see `iter_batches` for why the table can be absent at all).
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(error) => return Err(LogError::Segment(error.to_string())),
    };

    let mut keys = Vec::new();
    for entry in index
        .range((conn_id, 0)..=(conn_id, u64::MAX))
        .map_err(|error| LogError::Segment(error.to_string()))?
    {
        let (_, value) = entry.map_err(|error| LogError::Segment(error.to_string()))?;
        keys.push(value.value());
    }

    let table = transaction
        .open_table(MAIN)
        .map_err(|error| LogError::Segment(error.to_string()))?;
    let mut batches = Vec::new();
    for key in keys {
        if let Some(value) = table
            .get(key)
            .map_err(|error| LogError::Segment(error.to_string()))?
        {
            batches.push(decode(value.value())?);
        }
    }
    drop(db);
    Ok(batches)
}

/// One `STOR:meta` slot. The reader stage compares `schema_hash` against its
/// own before trusting anything else in the file.
#[allow(dead_code)]
pub(super) fn meta(dir: &Path, date: &str, key: &str) -> Result<Option<Vec<u8>>, LogError> {
    let (db, transaction) = open_for_read(dir, date)?;
    let table = transaction
        .open_table(META)
        .map_err(|error| LogError::Segment(error.to_string()))?;
    let value = table
        .get(key)
        .map_err(|error| LogError::Segment(error.to_string()))?
        .map(|guard| guard.value().to_vec());
    drop(db);
    Ok(value)
}

#[allow(dead_code)]
fn open_for_read(dir: &Path, date: &str) -> Result<(Database, redb::ReadTransaction), LogError> {
    let path = dir.join(format!("{date}{SEGMENT_SUFFIX}"));
    let db = Database::builder()
        .set_cache_size(CACHE_SIZE)
        .open(&path)
        .map_err(|error| LogError::Segment(format!("{}: {error}", path.display())))?;
    let transaction = db
        .begin_read()
        .map_err(|error| LogError::Segment(error.to_string()))?;
    Ok((db, transaction))
}

pub(super) fn encode(batch: &LogBatch, compress: Compression) -> Result<Vec<u8>, WriterError> {
    use prost::Message as _;

    let mut encoded = batch.encode_to_vec();
    match compress {
        Compression::None => encoded.insert(0, VALUE_RAW),
        #[cfg(feature = "log-zstd")]
        Compression::ZstdL1 => {
            let compressed = zstd::encode_all(encoded.as_slice(), ZSTD_LEVEL)
                .map_err(|error| WriterError::Segment(format!("cannot compress: {error}")))?;
            encoded.clear();
            encoded.push(VALUE_ZSTD);
            encoded.extend_from_slice(&compressed);
        }
    }
    Ok(encoded)
}

#[allow(dead_code)]
pub(super) fn decode(value: &[u8]) -> Result<LogBatch, LogError> {
    use prost::Message as _;

    let (framing, payload) = value
        .split_first()
        .ok_or_else(|| LogError::Segment("an empty segment value".to_string()))?;

    let encoded = match *framing {
        VALUE_RAW => payload.to_vec(),
        #[cfg(feature = "log-zstd")]
        VALUE_ZSTD => zstd::decode_all(payload)
            .map_err(|error| LogError::Segment(format!("cannot decompress: {error}")))?,
        // A compressed batch and a framing byte from the future are different
        // problems with different answers: one needs a different build, the
        // other a newer one.
        #[cfg(not(feature = "log-zstd"))]
        VALUE_ZSTD => {
            return Err(LogError::Segment(format!(
                "this segment holds compressed batches; rebuild with --features log-zstd \
                 to read it ({} was built without zstd)",
                env!("CARGO_PKG_NAME")
            )));
        }
        other => {
            return Err(LogError::Segment(format!(
                "unknown value framing {other}; this segment was written by a newer {}",
                env!("CARGO_PKG_NAME")
            )));
        }
    };

    LogBatch::decode(encoded.as_slice()).map_err(|error| LogError::Segment(error.to_string()))
}

fn durability_of(mode: DurabilityMode) -> Durability {
    match mode {
        DurabilityMode::Eventual => Durability::None,
        DurabilityMode::Immediate => Durability::Immediate,
    }
}

/// `redb::DatabaseError` and friends, flattened: the write path reports them
/// through `tracing` and backs off, and nothing above matches on them.
fn segment_error(error: impl std::fmt::Display) -> WriterError {
    WriterError::Segment(error.to_string())
}

/// The startup path reports to the operator, so the sink's own error type is
/// widened back into something with a file name and an exit code attached.
fn start_error(error: WriterError, path: &Path) -> LogError {
    match error {
        WriterError::Io(error) => LogError::Io(error),
        WriterError::Conflict => LogError::WriterConflict(path.to_path_buf()),
        WriterError::Segment(reason) => LogError::Segment(reason),
    }
}

/// Creates the segment file with the owner-only mode it will keep.
///
/// redb opens the file itself, so the mode has to be set before it gets there —
/// otherwise the file exists, briefly, with whatever the umask allows for a
/// database that holds every session's metadata.
fn pre_create(path: &Path) -> Result<(), WriterError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => Ok(()),
            // An existing segment for today: the restart case, by design.
            Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(WriterError::Io(error)),
        }
    }
    #[cfg(not(unix))]
    {
        // Windows has no umask to race with; the inherited ACL is the policy.
        let _ = path;
        Ok(())
    }
}

fn create_dir(dir: &Path) -> Result<(), LogError> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o755);
    }
    builder.create(dir).map_err(LogError::Io)
}

// ── Filesystem gate ────────────────────────────────────────────────────────

/// Refuses a log directory on a filesystem this build does not support.
///
/// The list is a support decision, not a claim about what the kernel can do.
/// redb takes `fcntl` open-file-description locks, and Linux implements those in
/// the VFS for every local filesystem — a `vfat` stick would very probably
/// work. It is refused anyway, because "very probably" is not a promise to make
/// about the one file that holds every session's metadata, and because the fix
/// for a stick is one `mkfs` away: `f2fs` is built for flash, keeps the file
/// sparse, and is what the message asks for.
///
/// The FAT family is named rather than derived, and the network filesystems —
/// where a lock really does depend on the server and on mount options such as
/// `nolock` — are deliberately *not* on it: refusing the wrong names would cost
/// a working deployment to cover a case that does not fail this way.
///
/// Whatever the answer, the check runs once at startup, where it is still a
/// configuration error with an exit code.
pub(crate) fn check_filesystem(dir: &Path) -> Result<(), LogError> {
    match filesystem_name(dir).as_deref() {
        Some(name) if !carries_locks(name) => Err(LogError::FsUnsupported(format!(
            "{} is on {name}, which --log-dir does not support: format the stick as f2fs \
             (or ext4, xfs, btrfs) and mount that, or point --log-dir at tmpfs \
             such as /tmp to keep the log in RAM",
            dir.display()
        ))),
        Some(_) => Ok(()),
        None => {
            // Unknown is not refused: a filesystem this code has never heard of
            // is more likely to be a new Linux one than a FAT variant.
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                warn!(
                    dir = %dir.display(),
                    "cannot determine the log directory's filesystem; assuming it is usable"
                );
            });
            Ok(())
        }
    }
}

/// Whether a filesystem can hold a redb segment.
pub(super) fn carries_locks(fstype: &str) -> bool {
    !matches!(
        fstype,
        "vfat" | "msdos" | "umsdos" | "exfat" | "ntfs" | "ntfs3" | "fuseblk" | "hpfs"
    )
}

#[cfg(target_os = "linux")]
fn filesystem_of(path: &Path) -> Option<String> {
    // `/proc/self/mountinfo` names the filesystem in a field of its own, which
    // `statfs` cannot do for FUSE: a `fuseblk` mount reports its own magic
    // number whatever the underlying filesystem is, and a `fuse2fs`-mounted
    // ext4 image would be refused for the wrong reason.
    let canonical = path.canonicalize().ok()?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok()?;

    let mut best: Option<(usize, String)> = None;
    for line in mountinfo.lines() {
        // `36 1 8:1 / /mnt rw,relatime - ext4 /dev/sda1 rw`
        let (before, after) = line.split_once(" - ")?;
        let mount_point = before.split_whitespace().nth(4)?;
        let fstype = after.split_whitespace().next()?;
        let unescaped = unescape_mount(mount_point);
        let mount_point = Path::new(&unescaped);

        if canonical.starts_with(mount_point) {
            let depth = mount_point.components().count();
            // Longest matching mount point wins: it is the one that actually
            // carries this path.
            if best.as_ref().is_none_or(|(best, _)| depth >= *best) {
                best = Some((depth, fstype.to_string()));
            }
        }
    }
    best.map(|(_, fstype)| fstype)
}

/// `/proc/self/mountinfo` escapes space, tab, newline and backslash as octal.
#[cfg(target_os = "linux")]
fn unescape_mount(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = String::with_capacity(field.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &field[i + 1..i + 4];
            if let Ok(byte) = u8::from_str_radix(octal, 8) {
                out.push(byte as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(target_os = "macos")]
fn filesystem_of(path: &Path) -> Option<String> {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt as _;

    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statfs` initialises the whole struct and only writes to it; the
    // path is a valid NUL-terminated C string for the duration of the call.
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stats) } != 0 {
        return None;
    }
    // `f_fstypename` is a NUL-terminated fixed-size array.
    let name = unsafe { CStr::from_ptr(stats.f_fstypename.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn filesystem_of(_path: &Path) -> Option<String> {
    // Windows: NTFS and exFAT both carry the file locks redb needs, so there is
    // nothing to gate on.
    None
}

// ── Calendar ───────────────────────────────────────────────────────────────

pub(super) fn today() -> i64 {
    (super::now_ns() / NANOS_PER_DAY) as i64
}

/// The filesystem `dir` lands on, as the kernel names it, or `None` when it
/// cannot be determined.
///
/// The banner prints this because the deployment questions this file exists for
/// are filesystem questions: a stick that came formatted as `vfat` has to be
/// re-formatted, and `/tmp` works but is RAM.
pub(crate) fn filesystem_name(dir: &Path) -> Option<String> {
    // The directory may not exist yet, so resolve the nearest ancestor that
    // does: it is the filesystem the directory is about to be created on.
    let mut probe = dir;
    while !probe.exists() {
        probe = probe.parent()?;
    }

    filesystem_of(probe)
}

/// `YYYY-MM-DD` for a day number since the unix epoch — Howard Hinnant's
/// `civil_from_days`, shifted to the 1970 epoch.
pub(super) fn day_name(day: i64) -> String {
    let shifted = day + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day_of_month = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day_of_month:02}")
}

/// The date part of a segment file name, if it has one. Deliberately not a date
/// parser: `YYYY-MM-DD` sorts lexicographically, which is all retention needs.
fn segment_day(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(SEGMENT_SUFFIX)?;
    let bytes = stem.as_bytes();
    if bytes.len() != 10 {
        return None;
    }
    let shaped = bytes.iter().enumerate().all(|(i, byte)| {
        if i == 4 || i == 7 {
            *byte == b'-'
        } else {
            byte.is_ascii_digit()
        }
    });
    shaped.then_some(stem)
}
