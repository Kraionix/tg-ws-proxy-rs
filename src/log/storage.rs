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

use logreel::file::{FileStore, FileStoreConfig, SegmentReader};
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

const SEGMENT_SUFFIX: &str = ".seg";
const NANOS_PER_DAY: u64 = 86_400_000_000_000;

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
    /// Days this run has written a segment for; the sweep never deletes one.
    written: Vec<i64>,
    /// Day of the file currently open, so a rotation is noticed once.
    observed_day: Option<i64>,
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
            written: Vec::new(),
            observed_day: None,
            backoff: 0,
            retry_at: None,
            clock,
        };

        let day = sink.today();
        let store = sink
            .connect()
            .map_err(|error| start_error(error, dir, day))?;
        sink.store = Some(store);
        sink.written.push(day);
        sink.observed_day = sink.active_day();
        sink.sweep_retention(day);
        Ok(sink)
    }

    /// Builds and opens the store, creating (or validating) today's file.
    fn connect(&self) -> Result<FileStore, logreel::StoreError> {
        let mut config = FileStoreConfig::new(&self.dir);
        // The proxy sweeps with its own window, which counts from the archive
        // rather than from the clock; two windows would disagree.
        config.keep_days = 0;
        config.max_total_bytes = 0;
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

    fn today(&self) -> i64 {
        today()
    }

    /// The day of the file the store has open, when it has one.
    fn active_day(&self) -> Option<i64> {
        let path = self.store.as_ref()?.active_path()?;
        let stem = path.file_stem()?.to_str()?;
        day_of_name(stem)
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

    /// Notices a rotation and sweeps once per day, not once per batch.
    fn after_write(&mut self) {
        let day = match self.active_day() {
            Some(day) => day,
            None => return,
        };
        if self.observed_day == Some(day) {
            return;
        }
        self.observed_day = Some(day);
        if !self.written.contains(&day) {
            self.written.push(day);
        }
        self.sweep_retention(day);
    }

    /// Deletes the segments that have fallen out of the retention window.
    fn sweep_retention(&self, day: i64) {
        sweep_retention(&self.dir, self.options.retention_days, day, &self.written);
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
                self.after_write();
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
/// header is rebuilt with [`schema::build_batch`], so `dump-segment` prints the
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

/// The date part of a segment file name, if it has one.
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

/// The day number a `YYYY-MM-DD` name spells, or `None` when it is not one.
///
/// The inverse of [`day_name`], needed where retention does arithmetic on what
/// a file is called: the cutoff is a name, and it is a number of days behind the
/// newest segment in the directory.
pub(super) fn day_of_name(name: &str) -> Option<i64> {
    let bytes = name.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let mut value = 0i64;
        for byte in &bytes[range] {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + i64::from(byte - b'0');
        }
        Some(value)
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

/// `YYYY-MM-DD` to days since the unix epoch — Howard Hinnant's
/// `days_from_civil`, the arithmetic [`day_name`] undoes.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_position = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_position + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Deletes the segments that have fallen out of the retention window.
///
/// The window is counted from whichever is earlier: the day the clock says, or
/// the day after the newest segment in `dir` that this run did not write. And
/// nothing this run wrote is deleted, whatever its name says.
///
/// Both rules are there because the clock is the least reliable thing on the
/// devices this ships to. A router has no RTC: `sysfixtime` sets the time from
/// the newest file in `/etc` and `ntpd` corrects it later, measured on the
/// reference router at +4 h 55 m, +8 h 18 m and +10 h 30 m. Counted from the
/// clock alone, a run that boots reading 1970 deletes the segment it just wrote
/// on the first rotation — the records of that very boot — and a run that boots
/// reading next year sweeps the whole directory at startup, before it has
/// recorded anything. Counted this way, the worst a wrong clock can do is keep
/// an old segment one run longer. The other half of the same reasoning is that
/// a *correct* clock after a long outage does not delete the archive either: the
/// window moves with the data, one run behind.
///
/// Names, not modification times: the date in the file name is the date the
/// records belong to, and an `mtime` moves whenever a file is copied or a clock
/// is wrong. Anything whose name is not a `YYYY-MM-DD.seg` date is left alone —
/// this directory may not be ours exclusively.
pub(super) fn sweep_retention(dir: &Path, retention_days: u32, clock_day: i64, written: &[i64]) {
    if retention_days == 0 {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            crate::direct!("cannot sweep log retention in {}: {error}", dir.display());
            return;
        }
    };

    // One pass over the directory: the segments this run did not write, and the
    // newest day among them — the archive's own idea of "now".
    let mut foreign: Vec<(String, i64)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str().map(str::to_string) else {
            continue;
        };
        let Some(segment) = segment_day(&name) else {
            continue;
        };
        if written.iter().any(|day| day_name(*day) == segment) {
            continue;
        }
        if let Some(day) = day_of_name(segment) {
            foreign.push((name, day));
        }
    }
    let Some(newest) = foreign.iter().map(|(_, day)| *day).max() else {
        // Nothing here that this run did not write, so there is nothing older
        // than it to delete either.
        return;
    };

    // A segment dated `d` means the log knows about day `d`, and the day after
    // it is where "now" is as far as the archive is concerned; the window ends
    // on whichever of that and the clock's day comes first.
    let base = (newest + 1).min(clock_day);
    if (clock_day - newest).abs() > i64::from(retention_days) {
        crate::direct!(
            "log retention: the clock says {} but the newest segment is {}; \
             counting the window from the segment",
            day_name(clock_day),
            day_name(newest)
        );
    }

    let cutoff = base - i64::from(retention_days) + 1;
    for (name, day) in foreign {
        if day < cutoff
            && let Err(error) = fs::remove_file(dir.join(&name))
        {
            crate::direct!("cannot delete the expired segment {name}: {error}");
        }
    }
}
