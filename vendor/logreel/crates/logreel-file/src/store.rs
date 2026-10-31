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
use crate::time::{day_from_ns, day_name};

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

/// File backend configuration.
#[derive(Clone, Debug)]
pub struct FileStoreConfig {
    /// Directory that holds YYYY-MM-DD.seg files.
    pub directory: PathBuf,
    /// Producer identity written into new headers; 0 means unspecified.
    pub producer_id: u32,
    /// Per-session nonce written into new headers.
    pub session_nonce: u32,
    /// Number of day files to keep, including the active one; 0 disables the
    /// day based rule.
    pub keep_days: usize,
    /// Total byte cap for the directory; 0 disables the cap.
    pub max_total_bytes: u64,
    /// Compress every frame with zstd; requires the zstd feature.
    pub compress: bool,
    /// zstd compression level used when [FileStoreConfig::compress] is set.
    /// The default, 3, is zstd's own; an application on a slow CPU passes 1
    /// and pays for fewer bytes rather than fewer instructions.
    pub zstd_level: i32,
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
        })
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
        let path = self.config.directory.join(format!("{}.seg", day_name(day)));
        let lock = acquire_lock(&path)?;
        let file = self.open_segment(&path, batch)?;
        self.active = Some(Active {
            file,
            path,
            day,
            _lock: lock,
        });
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

    fn retention(&mut self, today: i64) -> Result<(), StoreError> {
        let mut entries = read_segments(&self.config.directory)?;
        if entries.is_empty() {
            return Ok(());
        }
        let newest = entries.last().map(|entry| entry.1).unwrap_or(today);
        let window_end = today.min(newest.saturating_add(1));
        let active_path = self.active.as_ref().map(|active| active.path.clone());
        loop {
            let count = entries.len();
            let total: u64 = entries.iter().map(|entry| entry.2).sum();
            let over_count = self.config.keep_days > 0 && count > self.config.keep_days;
            let over_cap = self.config.max_total_bytes > 0 && total > self.config.max_total_bytes;
            if !over_count && !over_cap {
                break;
            }
            let Some(index) = entries
                .iter()
                .position(|entry| entry.1 < window_end && Some(&entry.0) != active_path.as_ref())
            else {
                break;
            };
            let (path, _, _) = entries.remove(index);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(StoreError::io(error)),
            }
            let _ = fs::remove_file(lock_path(&path));
        }
        Ok(())
    }
}

fn read_segments(directory: &Path) -> Result<Vec<(PathBuf, i64, u64)>, StoreError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(StoreError::io)? {
        let entry = entry.map_err(StoreError::io)?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("seg") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(day) = crate::time::day_from_name(stem) else {
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
