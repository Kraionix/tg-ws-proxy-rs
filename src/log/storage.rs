//! Day-segment storage: one append-only `.seg` file per UTC day, behind the
//! writer's sink seam.
//!
//! # Why a file per day
//!
//! A day is the unit an operator reasons in ("what happened yesterday"), it is
//! what retention counts, and it is the cheapest thing to delete. Rotation is
//! then a file boundary rather than a compaction pass, and the file name
//! (`2026-10-11.seg`) is the index over the whole directory — both for the
//! reader and for the sweep that removes old ones.
//!
//! # What a file is
//!
//! logreel's segment format v1: a 56-byte header, then frames of
//! `u32 length`, `u32 crc32c` and payload. A payload is a batch of records,
//! each with a 17–19 byte envelope around the event's `prost` encoding; a frame
//! may be zstd-compressed and the header says whether the file may carry any.
//! None of that is written here: [`logreel_file::FileStore`] owns the file,
//! while this module converts a [`LogBatch`] into the records the library
//! encodes and appends. The point of the split is that the proxy no longer has
//! a storage engine to reason about, only a sink to configure.
//!
//! # Durability, honestly
//!
//! `eventual` is an fsync at most every 30 seconds; `immediate` fsyncs before
//! the batch returns. A clean stop always syncs, so the loss window under a
//! power cut is the sync interval, not a flush.

use std::fs::{self, DirBuilder};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, Instant};

use logreel::file::{
    FileStore, FileStoreConfig, RetentionAnchor, SEGMENT_SUFFIX, SegmentReader, day_name, today,
};
use logreel::{Durability, ErrorKind, Store as _};

use super::LogError;
use super::schema::{self, Event, LogBatch, LogRecord};

/// Segments kept by default, counting today.
pub const DEFAULT_RETENTION_DAYS: u32 = 7;

/// zstd level 1 — chosen for a router's CPU rather than for the last few
/// percent of ratio.
const ZSTD_LEVEL: i32 = 1;

/// Backoff after a failed write, capped: 1, 2, 4, 8, 16, 60, 60, … seconds.
const BACKOFF_STEPS: [Duration; 6] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(60),
];

/// Whether a batch is compressed before it is stored.
///
/// `ZstdL1` exists only in a build with the `log-zstd` feature: without it the
/// mode is not offered at all rather than offered and silently ignored. The
/// default follows the build, because the flag's own default is "whatever this
/// binary can do" — a build with the codec defaults to `zstd-l1`, one without
/// it to `none`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    #[cfg(feature = "log-zstd")]
    ZstdL1,
}

// `#[default]` on a variant cannot be made conditional on a feature, and the
// default is the point: a build with the codec compresses.
#[allow(clippy::derivable_impls)]
impl Default for Compression {
    fn default() -> Self {
        #[cfg(feature = "log-zstd")]
        {
            Self::ZstdL1
        }
        #[cfg(not(feature = "log-zstd"))]
        {
            Self::None
        }
    }
}

/// How much a commit is worth.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DurabilityMode {
    /// fsync every 30 seconds rather than every flush.
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
            compress: Compression::default(),
            durability: DurabilityMode::Eventual,
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

/// Writes batches into `<dir>/<today>.seg`, rotating at the UTC date change.
pub(crate) struct FileSink {
    dir: PathBuf,
    options: Options,
    store: Option<FileStore>,
    backoff: usize,
    retry_at: Option<Instant>,
    /// Set only by the tests, which move the day the store writes to.
    clock: Option<std::sync::Arc<dyn logreel::file::Clock>>,
}

impl FileSink {
    /// Opens (or creates) today's segment. Startup failures are fatal and
    /// reported to the operator; once running, the sink degrades instead.
    pub(crate) fn open(dir: &Path, options: Options) -> Result<Self, LogError> {
        Self::open_inner(dir, options, None)
    }

    /// [`FileSink::open`] with the clock the tests move.
    #[cfg(test)]
    pub(crate) fn open_with_clock(
        dir: &Path,
        options: Options,
        clock: std::sync::Arc<dyn logreel::file::Clock>,
    ) -> Result<Self, LogError> {
        Self::open_inner(dir, options, Some(clock))
    }

    fn open_inner(
        dir: &Path,
        options: Options,
        clock: Option<std::sync::Arc<dyn logreel::file::Clock>>,
    ) -> Result<Self, LogError> {
        check_filesystem(dir)?;
        create_dir(dir)?;

        let mut sink = Self {
            dir: dir.to_path_buf(),
            options,
            store: None,
            backoff: 0,
            retry_at: None,
            clock,
        };

        let store = sink
            .connect()
            .map_err(|error| start_error(error, dir, today()))?;
        sink.store = Some(store);
        Ok(sink)
    }

    /// Builds and opens the store, creating (or validating) today's file.
    fn connect(&self) -> Result<FileStore, logreel::StoreError> {
        let mut config = FileStoreConfig::new(&self.dir);
        // A router has no RTC: count the window from the archive, not from a
        // clock that may boot at 1970 or next year. The store itself never
        // deletes a day this run wrote, so a wrong clock costs an old segment
        // one run longer, never the records of the boot that is running.
        config.keep_days = self.options.retention_days as usize;
        config.max_total_bytes = 0;
        config.retention_anchor = RetentionAnchor::NewestSegment;
        config.on_warning = Some(std::sync::Arc::new(|line: &str| crate::direct!("{line}")));
        config.compress = compressed(self.options.compress);
        config.zstd_level = ZSTD_LEVEL;

        let mut store = match &self.clock {
            Some(clock) => FileStore::with_clock(config, std::sync::Arc::clone(clock)),
            None => FileStore::open(config),
        }?;
        store.prime(
            <Event as logreel::Event>::CODEC_ID,
            <Event as logreel::Event>::KINDS,
            <Event as logreel::Event>::SCHEMA_HASH,
        )?;

        // The file holds every session's metadata, so it keeps the owner-only
        // mode the redb sink used to set before opening: the library creates it
        // with the umask, and this is the one place that knows it should not.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Some(path) = store.active_path() {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            }
        }

        Ok(store)
    }

    fn on_failure(&mut self, error: logreel::StoreError) -> logreel::StoreError {
        // A file that cannot be written to is not necessarily one that cannot be
        // reopened: a removed USB stick becomes writable again when it is
        // plugged back in. Dropping the handle makes the next attempt go through
        // the full open, which is what that recovery needs.
        if matches!(error.kind(), ErrorKind::Io) {
            self.store = None;
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

impl logreel::BatchSink for FileSink {
    fn write_batch(&mut self, batch: &logreel::EncodedBatch) -> Result<(), logreel::StoreError> {
        if batch.is_empty() {
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

        if self.store.is_none() {
            match self.connect() {
                Ok(store) => self.store = Some(store),
                Err(error) => return Err(self.on_failure(error)),
            }
        }

        let store = self.store.as_mut().expect("a store was opened above");
        let result = store.append(batch);
        match result {
            Ok(()) => {
                self.on_success();
                Ok(())
            }
            Err(error) => Err(self.on_failure(error)),
        }
    }

    fn sync(&mut self, mode: Durability) -> Result<(), logreel::StoreError> {
        let result = match self.store.as_mut() {
            Some(store) => logreel::Store::sync(store, mode),
            None => Ok(()),
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(self.on_failure(error)),
        }
    }
}

/// Reads one day's segment back as the batches the dump verb prints.
///
/// The records are decoded into the proxy's own [`LogRecord`] and the batch
/// header is rebuilt with [`schema::header_for`], so `dump-segment` prints the
/// same bytes for a `.seg` as it did for the redb file it replaced — including
/// the `kind_mask`, `dc_mask` and connection list, which are derived from the
/// records rather than stored.
pub fn iter_batches(dir: &Path, date: &str) -> Result<Vec<LogBatch>, LogError> {
    let path = dir.join(format!("{date}{SEGMENT_SUFFIX}"));
    if !path.exists() {
        return Err(LogError::Segment(format!(
            "no such segment: {}",
            path.display()
        )));
    }
    let mut reader = SegmentReader::open(&path)
        .map_err(|error| LogError::Segment(format!("{}: {error}", path.display())))?;
    let mut batches = Vec::new();
    while let Some(decoded) = reader.next_decoded_batch() {
        let decoded =
            decoded.map_err(|error| LogError::Segment(format!("{}: {error}", path.display())))?;
        let mut records = Vec::with_capacity(decoded.records.len());
        for owned in &decoded.records {
            let event = <Event as logreel::Event>::decode(owned.kind, &owned.payload)
                .map_err(|error| LogError::Segment(format!("{}: {error}", path.display())))?;
            records.push(LogRecord {
                ts_ns: owned.ts_ns,
                conn_id: owned.conn_id,
                seq: owned.seq,
                level: i32::from(owned.level),
                category: i32::from(owned.category),
                event: Some(event),
            });
        }
        batches.push(LogBatch {
            header: Some(schema::header_for(&records)),
            records,
        });
    }
    Ok(batches)
}

fn compressed(mode: Compression) -> bool {
    #[cfg(feature = "log-zstd")]
    {
        matches!(mode, Compression::ZstdL1)
    }
    #[cfg(not(feature = "log-zstd"))]
    {
        let _ = mode;
        false
    }
}

pub(crate) fn durability_of(mode: DurabilityMode) -> Durability {
    match mode {
        DurabilityMode::Eventual => Durability::Eventual,
        DurabilityMode::Immediate => Durability::Immediate,
    }
}

/// The startup path reports to the operator, so the library's error is widened
/// back into something with a file name and an exit code attached.
fn start_error(error: logreel::StoreError, dir: &Path, day: i64) -> LogError {
    match error.kind() {
        ErrorKind::Locked => {
            LogError::WriterConflict(dir.join(format!("{}{SEGMENT_SUFFIX}", day_name(day))))
        }
        ErrorKind::Io => LogError::Io(std::io::Error::other(error.to_string())),
        _ => LogError::Segment(error.to_string()),
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
/// the segment takes `fcntl` open-file-description locks, and Linux implements those in
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
                crate::direct!(
                    "cannot determine the filesystem of {}; assuming it is usable",
                    dir.display()
                );
            });
            Ok(())
        }
    }
}

/// Whether a filesystem can hold a the segment segment.
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
    // Windows: NTFS and exFAT both carry the file locks the segment needs, so there is
    // nothing to gate on.
    None
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
