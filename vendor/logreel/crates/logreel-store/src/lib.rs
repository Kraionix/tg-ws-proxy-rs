//! Storage contract for logreel.
//!
//! This crate is deliberately dependency free: it defines the encoded batch,
//! the durability policy, the [Store] trait and the error taxonomy shared by
//! every backend. The envelope itself is built by logreel-core; a backend
//! only moves opaque bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::io;

/// Maximum stored or uncompressed frame payload, 64 MiB.
pub const MAX_PAYLOAD: usize = 64 * 1024 * 1024;

/// Current segment format version.
pub const FORMAT_VERSION: u16 = 1;

/// When a backend should push bytes to stable storage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Durability {
    /// Sync at most once every 30 seconds.
    #[default]
    Eventual,
    /// Sync before the flush returns.
    Immediate,
    /// Sync when the batch contains a record at Warn or above.
    OnWarn,
}

/// One encoded batch, ready to be framed by a backend.
///
/// The payload is the batch payload of the specification: batch header,
/// kind mask, domain and records. The envelope is already inside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedBatch {
    /// Payload codec id; one per file.
    pub codec_id: u16,
    /// Fingerprint of the producing event schema.
    pub schema_hash: [u8; 16],
    /// Number of kinds in the producing domain.
    pub kind_count: u16,
    /// Number of records in the batch.
    pub record_count: u32,
    /// Smallest record timestamp in the batch.
    pub first_ts_ns: u64,
    /// Largest record timestamp in the batch.
    pub last_ts_ns: u64,
    /// Opaque domain bytes.
    pub domain: Box<[u8]>,
    /// Encoded batch payload.
    pub payload: Box<[u8]>,
}

impl EncodedBatch {
    /// Build a batch from its wire payload.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        codec_id: u16,
        schema_hash: [u8; 16],
        kind_count: u16,
        record_count: u32,
        first_ts_ns: u64,
        last_ts_ns: u64,
        domain: Box<[u8]>,
        payload: Box<[u8]>,
    ) -> Self {
        Self {
            codec_id,
            schema_hash,
            kind_count,
            record_count,
            first_ts_ns,
            last_ts_ns,
            domain,
            payload,
        }
    }

    /// Number of payload bytes, excluding the 8-byte frame header.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// True when the batch carries no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.record_count == 0
    }
}

/// Broad category of a storage failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Operating system error.
    Io,
    /// Structure violates the specification.
    Format,
    /// Checksum or length mismatch inside the valid range.
    Corrupt,
    /// End of file in the middle of a frame or record.
    Truncated,
    /// A newer format or a compression feature that is not compiled in.
    Unsupported,
    /// Header invalid, or a decoder was requested for unknown data.
    Refused,
    /// Another writer holds the lock.
    Locked,
}

impl ErrorKind {
    /// Short stable name used in messages and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Format => "format",
            Self::Corrupt => "corrupt",
            Self::Truncated => "truncated",
            Self::Unsupported => "unsupported",
            Self::Refused => "refused",
            Self::Locked => "locked",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error type shared by every backend.
#[derive(Debug)]
pub struct StoreError {
    kind: ErrorKind,
    message: String,
    offset: Option<u64>,
    source: Option<io::Error>,
}

impl StoreError {
    /// Build an error with a kind and a message.
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            offset: None,
            source: None,
        }
    }

    /// Wrap an operating system error.
    #[must_use]
    pub fn io(error: io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            message: error.to_string(),
            offset: None,
            source: Some(error),
        }
    }

    /// Attach a byte offset to this error.
    #[must_use]
    pub fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Attach an underlying source to this error.
    #[must_use]
    pub fn with_source(mut self, error: io::Error) -> Self {
        self.source = Some(error);
        self
    }

    /// Failure category.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Byte offset the failure refers to, when known.
    #[must_use]
    pub const fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Human readable message without the kind prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// True when the failure is a normal torn tail rather than corruption.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(self.kind, ErrorKind::Truncated)
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.message)?;
        if let Some(offset) = self.offset {
            write!(formatter, " (offset {offset})")?;
        }
        Ok(())
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::io(error)
    }
}

/// Stream of decoded batches produced by a store.
pub type BatchScan<'a> = Box<dyn Iterator<Item = Result<EncodedBatch, StoreError>> + Send + 'a>;

/// Append-only batch storage.
///
/// Implementations are object safe: the pipeline holds a backend behind a
/// trait object and pays one virtual call per batch, never per record.
pub trait Store: Send {
    /// Append one encoded batch.
    ///
    /// The batch is visible to a concurrent reader as soon as this returns,
    /// subject to the backend's durability policy.
    fn append(&mut self, batch: &EncodedBatch) -> Result<(), StoreError>;

    /// Apply the durability policy after a flush.
    fn sync(&mut self, mode: Durability) -> Result<(), StoreError>;

    /// Stream every batch that the backend can prove valid.
    fn scan(&self) -> Result<BatchScan<'_>, StoreError>;
}

/// Sink used by the writer pipeline; one call per batch.
pub trait BatchSink: Send {
    /// Write one batch.
    fn write_batch(&mut self, batch: &EncodedBatch) -> Result<(), StoreError>;

    /// Apply the durability policy.
    fn sync(&mut self, mode: Durability) -> Result<(), StoreError> {
        let _ = mode;
        Ok(())
    }

    /// Flush buffered state at shutdown.
    fn flush(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
}

impl<S: Store + ?Sized> BatchSink for S {
    fn write_batch(&mut self, batch: &EncodedBatch) -> Result<(), StoreError> {
        self.append(batch)
    }

    fn sync(&mut self, mode: Durability) -> Result<(), StoreError> {
        Store::sync(self, mode)
    }
}

/// In-memory store used by tests and by callers that only need a dry run.
#[derive(Debug, Default)]
pub struct MemoryStore {
    batches: Vec<EncodedBatch>,
    appends: u64,
    syncs: Vec<Durability>,
}

impl MemoryStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Batches appended so far, in order.
    #[must_use]
    pub fn batches(&self) -> &[EncodedBatch] {
        &self.batches
    }

    /// Number of append calls.
    #[must_use]
    pub const fn appends(&self) -> u64 {
        self.appends
    }

    /// Durability modes seen by sync, in order.
    #[must_use]
    pub fn syncs(&self) -> &[Durability] {
        &self.syncs
    }

    /// Remove every batch.
    pub fn clear(&mut self) {
        self.batches.clear();
    }
}

impl Store for MemoryStore {
    fn append(&mut self, batch: &EncodedBatch) -> Result<(), StoreError> {
        self.batches.push(batch.clone());
        self.appends += 1;
        Ok(())
    }

    fn sync(&mut self, mode: Durability) -> Result<(), StoreError> {
        self.syncs.push(mode);
        Ok(())
    }

    fn scan(&self) -> Result<BatchScan<'_>, StoreError> {
        Ok(Box::new(self.batches.iter().cloned().map(Ok)))
    }
}

/// A sink that is useful in tests: it pushes every batch into a shared vector.
#[derive(Clone, Debug, Default)]
pub struct SharedSink {
    batches: std::sync::Arc<std::sync::Mutex<Vec<EncodedBatch>>>,
    syncs: std::sync::Arc<std::sync::Mutex<Vec<Durability>>>,
}

impl SharedSink {
    /// Create an empty shared sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clone of the batch vector for assertions.
    #[must_use]
    pub fn batches(&self) -> std::sync::Arc<std::sync::Mutex<Vec<EncodedBatch>>> {
        std::sync::Arc::clone(&self.batches)
    }

    /// Clone of the sync log for assertions.
    #[must_use]
    pub fn syncs(&self) -> std::sync::Arc<std::sync::Mutex<Vec<Durability>>> {
        std::sync::Arc::clone(&self.syncs)
    }
}

impl BatchSink for SharedSink {
    fn write_batch(&mut self, batch: &EncodedBatch) -> Result<(), StoreError> {
        self.batches
            .lock()
            .expect("shared sink lock")
            .push(batch.clone());
        Ok(())
    }

    fn sync(&mut self, mode: Durability) -> Result<(), StoreError> {
        self.syncs.lock().expect("shared sink lock").push(mode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BatchSink, Durability, EncodedBatch, ErrorKind, MemoryStore, Store, StoreError};

    fn batch(count: u32) -> EncodedBatch {
        EncodedBatch::new(
            1,
            [0x11; 16],
            8,
            count,
            10,
            20,
            b"dc=1".to_vec().into_boxed_slice(),
            vec![0u8; 32].into_boxed_slice(),
        )
    }

    #[test]
    fn memory_store_roundtrip() {
        let mut store = MemoryStore::new();
        store.append(&batch(3)).expect("append");
        Store::sync(&mut store, Durability::Immediate).expect("sync");
        assert_eq!(store.appends(), 1);
        assert_eq!(store.syncs(), &[Durability::Immediate]);
        let scanned: Vec<_> = store
            .scan()
            .expect("scan")
            .collect::<Result<_, _>>()
            .expect("batches");
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].record_count, 3);
        assert!(!scanned[0].is_empty());
    }

    #[test]
    fn store_is_a_batch_sink() {
        let mut store = MemoryStore::new();
        BatchSink::write_batch(&mut store, &batch(1)).expect("write");
        BatchSink::sync(&mut store, Durability::OnWarn).expect("sync");
        assert_eq!(store.batches().len(), 1);
        assert_eq!(store.syncs(), &[Durability::OnWarn]);
    }

    #[test]
    fn errors_carry_kind_offset_and_display() {
        let error = StoreError::new(ErrorKind::Corrupt, "bad crc").at(117);
        assert_eq!(error.kind(), ErrorKind::Corrupt);
        assert_eq!(error.offset(), Some(117));
        assert_eq!(error.to_string(), "corrupt: bad crc (offset 117)");
        assert!(!error.is_recoverable());
        let truncated = StoreError::new(ErrorKind::Truncated, "eof").at(9);
        assert!(truncated.is_recoverable());
    }

    #[test]
    fn io_errors_keep_the_source() {
        let error = StoreError::io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        assert_eq!(error.kind(), ErrorKind::Io);
        assert!(std::error::Error::source(&error).is_some());
    }
}
