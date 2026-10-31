//! FileStore: day rotation, retention, durability and recovery.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use logreel_store::{BatchScan, Durability, EncodedBatch, ErrorKind, Store, StoreError};

use crate::crc32c::crc32c;
use crate::header::{Header, MAX_PAYLOAD};
use crate::reader::{FrameReader, SegmentReader};
use crate::time::{SEGMENT_SUFFIX, day_from_ns, day_name, day_of_name, segment_day};

/// Time source for rotation and header creation.
pub trait Clock: Send + Sync {
    /// Current Unix time in nanoseconds.
    fn now_ns(&self) -> u64;
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ns(&self) -> u64 {
        crate::time::now_ns()
    }
}

/// Receives one line from the store when it has something to say.
pub type WarningSink = Arc<dyn Fn(&str) + Send + Sync>;

/// Where the retention window starts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RetentionAnchor {
    /// Count from what the clock says is today. A run that boots with a wrong
    /// clock trusts it, for better and for worse.
    #[default]
    Clock,
    /// Count from the day after the newest segment in the directory, capped
    /// at the clock's day. A wrong clock can then keep an old segment one run
    /// longer, but can never delete the archive or the segment just written.
    NewestSegment,
}

/// File backend configuration.
#[derive(Clone)]
pub struct FileStoreConfig {
    /// Directory that holds YYYY-MM-DD.seg files.
    pub directory: PathBuf,
    /// Producer identity written into new headers; 0 means unspecified.
    pub producer_id: u32,
    /// Per-session nonce written into new headers.
    pub session_nonce: u32,
    /// Width of the retention window in days, including the window's last
    /// day; 0 disables the day based rule.
    pub keep_days: usize,
    /// Total byte cap for the directory; 0 disables the cap.
    pub max_total_bytes: u64,
    /// Compress every frame with zstd; requires the zstd feature.
    pub compress: bool,
    /// zstd compression level used when [FileStoreConfig::compress] is set.
    /// The default, 3, is zstd's own; an application on a slow CPU passes 1
    /// and pays for fewer bytes rather than fewer instructions.
    pub zstd_level: i32,
    /// Where the retention window starts; see [RetentionAnchor].
    pub retention_anchor: RetentionAnchor,
    /// Receives one line when the clock and the archive disagree enough to
    /// matter. The store never logs by itself: the application owns the
    /// wording of its own diagnostics.
    pub on_warning: Option<WarningSink>,
}

impl std::fmt::Debug for FileStoreConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileStoreConfig")
            .field("directory", &self.directory)
            .field("producer_id", &self.producer_id)
            .field("session_nonce", &self.session_nonce)
            .field("keep_days", &self.keep_days)
            .field("max_total_bytes", &self.max_total_bytes)
            .field("compress", &self.compress)
            .field("zstd_level", &self.zstd_level)
            .field("retention_anchor", &self.retention_anchor)
            .field("on_warning", &self.on_warning.as_ref().map(|_| "callback"))
            .finish()
    }
}

impl FileStoreConfig {
    /// Defaults: keep 7 days, cap 256 MiB, no compression.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        let nonce = (crate::time::now_ns() & 0xFFFF_FFFF) as u32;
        Self {
            directory: directory.into(),
            producer_id: 0,
            session_nonce: nonce,
            keep_days: 7,
            max_total_bytes: 256 * 1024 * 1024,
            compress: false,
            zstd_level: 3,
            retention_anchor: RetentionAnchor::Clock,
            on_warning: None,
        }
    }
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

fn process_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true
    }
}

fn acquire_lock(path: &Path) -> Result<LockGuard, StoreError> {
    let lock = lock_path(path);
    for attempt in 0..2 {
        match OpenOptions::new().write(true).create_new(true).open(&lock) {
            Ok(mut file) => {
                let _ = write!(file, "{}", std::process::id());
                return Ok(LockGuard { path: lock });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                let stale = fs::read_to_string(&lock)
                    .ok()
                    .and_then(|text| text.trim().parse::<u32>().ok())
                    .is_some_and(|pid| pid != std::process::id() && !process_alive(pid));
                if stale {
                    let _ = fs::remove_file(&lock);
                    continue;
                }
                return Err(StoreError::new(
                    ErrorKind::Locked,
                    format!("{} is locked by another writer", path.display()),
                ));
            }
            Err(error) => return Err(StoreError::io(error)),
        }
    }
    Err(StoreError::new(
        ErrorKind::Locked,
        format!("{} is locked", path.display()),
    ))
}

struct Active {
    file: File,
    path: PathBuf,
    day: i64,
    _lock: LockGuard,
}

/// Append-only segment backend.
pub struct FileStore {
    config: FileStoreConfig,
    clock: Arc<dyn Clock>,
    active: Option<Active>,
    last_sync: Instant,
    rotations: u64,
    /// Days this run wrote, and therefore must never delete. A wrong clock
    /// makes the day name meaningless, but it does not make the records in
    /// that file less ours.
    written: Vec<i64>,
}

impl FileStore {
    /// Open a store; the first append creates the day file.
    pub fn open(config: FileStoreConfig) -> Result<Self, StoreError> {
        Self::with_clock(config, Arc::new(SystemClock))
    }

    /// Open a store with an injected clock.
    pub fn with_clock(config: FileStoreConfig, clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        fs::create_dir_all(&config.directory).map_err(StoreError::io)?;
        if config.compress && !cfg!(feature = "zstd") {
            return Err(StoreError::new(
                ErrorKind::Unsupported,
                "compression requested but the zstd feature is off",
            ));
        }
        if !(1..=22).contains(&config.zstd_level) {
            return Err(StoreError::new(
                ErrorKind::Refused,
                format!("zstd level {} is outside 1..=22", config.zstd_level),
            ));
        }
        Ok(Self {
            config,
            clock,
            active: None,
            last_sync: Instant::now(),
            rotations: 0,
            written: Vec::new(),
        })
    }

    /// Create or validate today's file and take its lock, without a frame.
    ///
    /// [FileStore::open] touches nothing: the day file is created by the first
    /// append, which is too late for a startup that has to refuse a directory
    /// another writer holds. Priming performs the same rotation the first
    /// append would -- header, lock, retention sweep -- and leaves the file
    /// empty, so a second writer fails where the operator is still listening.
    pub fn prime(
        &mut self,
        codec_id: u16,
        kind_count: u16,
        schema_hash: [u8; 16],
    ) -> Result<PathBuf, StoreError> {
        let day = day_from_ns(self.clock.now_ns());
        let empty = EncodedBatch::new(
            codec_id,
            schema_hash,
            kind_count,
            0,
            0,
            0,
            Box::new([]),
            Box::new([]),
        );
        self.ensure_active(day, &empty)?;
        Ok(self
            .active_path()
            .expect("ensure_active left a file open")
            .to_path_buf())
    }

    /// Currently written segment, if any.
    #[must_use]
    pub fn active_path(&self) -> Option<&Path> {
        self.active.as_ref().map(|active| active.path.as_path())
    }

    /// Number of files opened by rotation.
    #[must_use]
    pub const fn rotations(&self) -> u64 {
        self.rotations
    }

    fn ensure_active(&mut self, day: i64, batch: &EncodedBatch) -> Result<(), StoreError> {
        if self.active.as_ref().is_some_and(|active| active.day == day) {
            return Ok(());
        }
        self.sync(Durability::Immediate)?;
        self.active = None;
        let path = self
            .config
            .directory
            .join(format!("{}{SEGMENT_SUFFIX}", day_name(day)));
        let lock = acquire_lock(&path)?;
        let file = self.open_segment(&path, batch)?;
        self.active = Some(Active {
            file,
            path,
            day,
            _lock: lock,
        });
        if !self.written.contains(&day) {
            self.written.push(day);
        }
        self.rotations += 1;
        self.retention(day)?;
        Ok(())
    }

    fn open_segment(&self, path: &Path, batch: &EncodedBatch) -> Result<File, StoreError> {
        if path.exists() {
            let mut header_bytes = [0u8; crate::header::HEADER_LEN];
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(StoreError::io)?;
            use std::io::Read as _;
            file.read_exact(&mut header_bytes)
                .map_err(|error| StoreError::io(error).at(0))?;
            let header = Header::parse(&header_bytes)?;
            if header.codec_id != batch.codec_id {
                return Err(StoreError::new(
                    ErrorKind::Refused,
                    format!(
                        "{}: existing file has codec {} but the batch has {}",
                        path.display(),
                        header.codec_id,
                        batch.codec_id
                    ),
                ));
            }
            if self.config.compress && !header.contains_zstd() {
                return Err(StoreError::new(
                    ErrorKind::Refused,
                    format!(
                        "{}: file was created without compression and cannot take compressed frames",
                        path.display()
                    ),
                ));
            }
            if header.schema_hash != batch.schema_hash {
                return Err(StoreError::new(
                    ErrorKind::Refused,
                    format!(
                        "{}: schema hash differs from the existing file",
                        path.display()
                    ),
                ));
            }
            drop(file);
            let valid_end = recover(path, &header)?;
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(StoreError::io)?;
            file.set_len(valid_end).map_err(StoreError::io)?;
            file.seek(SeekFrom::End(0)).map_err(StoreError::io)?;
            Ok(file)
        } else {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(StoreError::io)?;
            let header = Header::new(
                batch.codec_id,
                batch.kind_count,
                batch.schema_hash,
                self.clock.now_ns(),
                self.config.producer_id,
                self.config.session_nonce,
                self.config.compress,
            );
            file.write_all(&header.encode()).map_err(StoreError::io)?;
            file.seek(SeekFrom::End(0)).map_err(StoreError::io)?;
            Ok(file)
        }
    }

    fn write_frame(&mut self, payload: &[u8]) -> Result<(), StoreError> {
        let compress = self.config.compress;
        #[cfg(feature = "zstd")]
        let body: Option<Vec<u8>> = if compress {
            Some(
                zstd::bulk::compress(payload, self.config.zstd_level)
                    .map_err(|error| StoreError::new(ErrorKind::Io, error.to_string()))?,
            )
        } else {
            None
        };
        #[cfg(not(feature = "zstd"))]
        let body: Option<Vec<u8>> = if compress {
            return Err(StoreError::new(
                ErrorKind::Unsupported,
                "compression requested without the zstd feature",
            ));
        } else {
            None
        };
        let frame_len = match &body {
            Some(stored) => (stored.len() as u32) | (1 << 31),
            None => payload.len() as u32,
        };
        let stored: &[u8] = body.as_deref().unwrap_or(payload);
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| StoreError::new(ErrorKind::Io, "no active segment"))?;
        let mut frame = Vec::with_capacity(8 + stored.len());
        frame.extend_from_slice(&frame_len.to_le_bytes());
        frame.extend_from_slice(&crc32c(payload).to_le_bytes());
        frame.extend_from_slice(stored);
        active.file.write_all(&frame).map_err(StoreError::io)
    }

    /// Delete what fell out of the retention window.
    ///
    /// Only files this run did not write are candidates: the day name of a
    /// file says which records it holds, not whether they are still wanted,
    /// and a clock that boots at 1970 would otherwise delete the segment the
    /// current boot just wrote.
    ///
    /// The window ends at the clock's day or, with
    /// [`RetentionAnchor::NewestSegment`], at the day after the newest
    /// segment that was already there -- whichever is earlier. Counting from
    /// the archive means a late or early clock cannot shrink the archive to
    /// nothing; counting from the clock means a correct clock after a long
    /// outage still keeps everything the window covers.
    fn retention(&mut self, today: i64) -> Result<(), StoreError> {
        if self.config.keep_days == 0 && self.config.max_total_bytes == 0 {
            return Ok(());
        }
        let entries = read_segments(&self.config.directory)?;
        if entries.is_empty() {
            return Ok(());
        }
        let mut total: u64 = entries.iter().map(|entry| entry.2).sum();
        let active_path = self.active.as_ref().map(|active| active.path.clone());
        let mut foreign: Vec<(PathBuf, i64, u64)> = entries
            .into_iter()
            .filter(|(path, day, _)| {
                Some(path) != active_path.as_ref() && !self.written.contains(day)
            })
            .collect();
        if foreign.is_empty() {
            return Ok(());
        }
        let newest = foreign.iter().map(|(_, day, _)| *day).max();
        if self.config.keep_days > 0
            && self.config.retention_anchor == RetentionAnchor::NewestSegment
            && let Some(newest) = newest
            && (today - newest).abs() > self.config.keep_days as i64
        {
            self.warn(format!(
                "log retention: the clock says {} but the newest segment is {}; \
                 counting the window from the segment",
                day_name(today),
                day_name(newest)
            ));
        }
        let base = match self.config.retention_anchor {
            RetentionAnchor::Clock => today,
            RetentionAnchor::NewestSegment => match newest {
                // The day after the newest segment is where "now" is as far
                // as the archive is concerned; the clock only caps it.
                Some(newest) => (newest.saturating_add(1)).min(today),
                None => return Ok(()),
            },
        };
        if self.config.keep_days > 0 {
            let cutoff = base - self.config.keep_days as i64 + 1;
            let mut index = 0;
            while index < foreign.len() {
                if foreign[index].1 < cutoff {
                    let (path, _, len) = foreign.remove(index);
                    total = total.saturating_sub(len);
                    remove_segment(&path)?;
                } else {
                    index += 1;
                }
            }
        }
        while self.config.max_total_bytes > 0 && total > self.config.max_total_bytes {
            let Some(index) = foreign.iter().position(|entry| entry.1 < base) else {
                break;
            };
            let (path, _, len) = foreign.remove(index);
            total = total.saturating_sub(len);
            remove_segment(&path)?;
        }
        Ok(())
    }

    fn warn(&self, message: String) {
        if let Some(sink) = &self.config.on_warning {
            sink(&message);
        }
    }
}

fn remove_segment(path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(StoreError::io(error)),
    }
    let _ = fs::remove_file(lock_path(path));
    Ok(())
}

fn read_segments(directory: &Path) -> Result<Vec<(PathBuf, i64, u64)>, StoreError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(StoreError::io)? {
        let entry = entry.map_err(StoreError::io)?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(day) = segment_day(name).and_then(day_of_name) else {
            continue;
        };
        let len = entry.metadata().map_err(StoreError::io)?.len();
        entries.push((path, day, len));
    }
    entries.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    Ok(entries)
}

fn recover(path: &Path, expected: &Header) -> Result<u64, StoreError> {
    let mut reader = FrameReader::open(path)?;
    if reader.header().codec_id != expected.codec_id
        || reader.header().schema_hash != expected.schema_hash
    {
        return Err(StoreError::new(
            ErrorKind::Refused,
            format!("{}: header changed while opening", path.display()),
        ));
    }
    let mut buffer = Vec::new();
    loop {
        match reader.next_frame_into(&mut buffer) {
            None => return Ok(reader.offset()),
            Some(Err(error)) if error.kind() == ErrorKind::Truncated => {
                let end = error.offset().unwrap_or(0);
                let file = OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(StoreError::io)?;
                file.set_len(end).map_err(StoreError::io)?;
                return Ok(end);
            }
            Some(Err(error)) => return Err(error),
            Some(Ok(_)) => {}
        }
    }
}

impl Store for FileStore {
    fn append(&mut self, batch: &EncodedBatch) -> Result<(), StoreError> {
        if batch.payload.len() > MAX_PAYLOAD {
            return Err(StoreError::new(
                ErrorKind::Format,
                "batch payload exceeds 64 MiB",
            ));
        }
        let day = day_from_ns(self.clock.now_ns());
        self.ensure_active(day, batch)?;
        self.write_frame(&batch.payload)
    }

    fn sync(&mut self, mode: Durability) -> Result<(), StoreError> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        let want = match mode {
            Durability::Immediate | Durability::OnWarn => true,
            Durability::Eventual => self.last_sync.elapsed() >= Duration::from_secs(30),
        };
        if want {
            active.file.sync_data().map_err(StoreError::io)?;
            self.last_sync = Instant::now();
        }
        Ok(())
    }

    fn scan(&self) -> Result<BatchScan<'_>, StoreError> {
        Ok(Box::new(ScanAll::new(&self.config.directory)?))
    }
}

impl Drop for FileStore {
    fn drop(&mut self) {
        if let Some(active) = self.active.as_mut() {
            let _ = active.file.sync_data();
        }
    }
}

impl std::fmt::Debug for FileStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileStore")
            .field("directory", &self.config.directory)
            .field("active", &self.active.as_ref().map(|active| &active.path))
            .finish()
    }
}

/// List segment files in a directory, oldest first.
pub fn segments(directory: &Path) -> Result<Vec<PathBuf>, StoreError> {
    Ok(read_segments(directory)?
        .into_iter()
        .map(|entry| entry.0)
        .collect())
}

struct ScanAll {
    paths: std::vec::IntoIter<PathBuf>,
    current: Option<SegmentReader>,
    done: bool,
}

impl ScanAll {
    fn new(directory: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            paths: segments(directory)?.into_iter(),
            current: None,
            done: false,
        })
    }
}

impl Iterator for ScanAll {
    type Item = Result<EncodedBatch, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            if let Some(reader) = &mut self.current {
                match reader.next_batch() {
                    Some(Ok(batch)) => return Some(Ok(batch)),
                    Some(Err(error)) => {
                        self.done = true;
                        return Some(Err(error));
                    }
                    None => self.current = None,
                }
            }
            let path = self.paths.next()?;
            match SegmentReader::open(&path) {
                Ok(reader) => self.current = Some(reader),
                Err(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lock_path;
    use std::path::Path;

    #[test]
    fn lock_path_appends_suffix() {
        assert_eq!(
            lock_path(Path::new("/tmp/a.seg")),
            Path::new("/tmp/a.seg.lock")
        );
    }
}
