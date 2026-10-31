//! Segment reader, streaming scan, probe and raw dump.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use logreel_store::{EncodedBatch, ErrorKind, StoreError};

use crate::batch::{RecordView, parse_batch, parse_record, validate_batch};
use crate::crc32c::crc32c;
use crate::header::{HEADER_LEN, Header, MAX_PAYLOAD};
use crate::sha256::Sha256;

/// Maximum distinct connection ids tracked by probe.
pub(crate) const PROBE_CONNECTION_CAP: usize = 4096;

pub(crate) struct FrameMeta {
    offset: u64,
    stored_len: u32,
}

fn read_up_to(file: &mut File, buffer: &mut [u8]) -> Result<usize, StoreError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(StoreError::io(error)),
        }
    }
    Ok(filled)
}

fn with_path(error: StoreError, path: &Path) -> StoreError {
    let message = format!("{}: {}", path.display(), error.message());
    let mut wrapped = StoreError::new(error.kind(), message);
    if let Some(offset) = error.offset() {
        wrapped = wrapped.at(offset);
    }
    wrapped
}

fn corrupt_at(message: impl Into<String>, offset: u64) -> StoreError {
    StoreError::new(ErrorKind::Corrupt, message).at(offset)
}

pub(crate) struct FrameReader {
    file: File,
    path: PathBuf,
    header: Header,
    offset: u64,
    len: u64,
    raw: Vec<u8>,
    #[allow(dead_code)]
    decompressed: Vec<u8>,
}

impl FrameReader {
    pub(crate) fn open(path: &Path) -> Result<Self, StoreError> {
        let mut file = File::open(path).map_err(|error| with_path(StoreError::io(error), path))?;
        let len = file
            .metadata()
            .map_err(|error| with_path(StoreError::io(error), path))?
            .len();
        let mut header_bytes = [0u8; HEADER_LEN];
        let read = read_up_to(&mut file, &mut header_bytes)?;
        let header =
            Header::parse(&header_bytes[..read]).map_err(|error| with_path(error, path))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            header,
            offset: HEADER_LEN as u64,
            len,
            raw: Vec::new(),
            decompressed: Vec::new(),
        })
    }

    pub(crate) fn header(&self) -> &Header {
        &self.header
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn offset(&self) -> u64 {
        self.offset
    }

    pub(crate) fn next_frame_into(
        &mut self,
        out: &mut Vec<u8>,
    ) -> Option<Result<FrameMeta, StoreError>> {
        if self.offset >= self.len {
            return None;
        }
        let start = self.offset;
        let mut head = [0u8; 8];
        let filled = match read_up_to(&mut self.file, &mut head) {
            Ok(filled) => filled,
            Err(error) => return Some(Err(with_path(error, &self.path))),
        };
        if filled < 8 {
            return Some(Err(StoreError::new(
                ErrorKind::Truncated,
                "partial frame header",
            )
            .at(start)));
        }
        let frame_len = u32::from_le_bytes(head[0..4].try_into().expect("4 bytes"));
        let stored = (frame_len & 0x7FFF_FFFF) as usize;
        let compressed = frame_len & 0x8000_0000 != 0;
        let crc = u32::from_le_bytes(head[4..8].try_into().expect("4 bytes"));
        if stored == 0 || stored > MAX_PAYLOAD {
            return Some(Err(corrupt_at(
                format!("frame length {stored} is invalid"),
                start,
            )));
        }
        if start + 8 + stored as u64 > self.len {
            return Some(Err(StoreError::new(
                ErrorKind::Truncated,
                format!("frame of {stored} bytes extends past the end of the file"),
            )
            .at(start)));
        }
        self.raw.resize(stored, 0);
        let filled = match read_up_to(&mut self.file, &mut self.raw) {
            Ok(filled) => filled,
            Err(error) => return Some(Err(with_path(error, &self.path))),
        };
        if filled < stored {
            return Some(Err(StoreError::new(
                ErrorKind::Truncated,
                "partial frame payload",
            )
            .at(start)));
        }
        let payload: &[u8] = if compressed {
            if !self.header.contains_zstd() {
                return Some(Err(StoreError::new(
                    ErrorKind::Corrupt,
                    "compressed frame in a file without the zstd flag",
                )
                .at(start)));
            }
            #[cfg(feature = "zstd")]
            {
                match zstd::bulk::decompress(&self.raw, MAX_PAYLOAD) {
                    Ok(bytes) => {
                        self.decompressed = bytes;
                        &self.decompressed
                    }
                    Err(error) => {
                        return Some(Err(corrupt_at(
                            format!("zstd decompression failed: {error}"),
                            start,
                        )));
                    }
                }
            }
            #[cfg(not(feature = "zstd"))]
            {
                return Some(Err(StoreError::new(
                    ErrorKind::Unsupported,
                    "compressed frame but the zstd feature is off",
                )
                .at(start)));
            }
        } else {
            &self.raw
        };
        if crc32c(payload) != crc {
            return Some(Err(corrupt_at("frame CRC does not match", start)));
        }
        out.clear();
        out.extend_from_slice(payload);
        self.offset = start + 8 + stored as u64;
        Some(Ok(FrameMeta {
            offset: start,
            stored_len: stored as u32,
        }))
    }
}

/// Streaming reader over one segment.
pub struct SegmentReader {
    reader: FrameReader,
}

impl SegmentReader {
    /// Open a segment and validate its header.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            reader: FrameReader::open(path)?,
        })
    }

    /// Validated header.
    #[must_use]
    pub fn header(&self) -> &Header {
        self.reader.header()
    }

    /// Byte offset just past the last fully read frame.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.reader.offset()
    }

    /// Read the next validated batch.
    pub fn next_batch(&mut self) -> Option<Result<EncodedBatch, StoreError>> {
        let mut payload = Vec::new();
        match self.reader.next_frame_into(&mut payload) {
            None => None,
            // A torn tail is normal for a live file: stop at the last good
            // frame without reporting corruption.
            Some(Err(error)) if error.kind() == ErrorKind::Truncated => None,
            Some(Err(error)) => Some(Err(error)),
            Some(Ok(meta)) => {
                let info = match validate_batch(&payload, meta.offset) {
                    Ok(info) => info,
                    Err(error) => return Some(Err(error)),
                };
                let batch = EncodedBatch::new(
                    self.reader.header().codec_id,
                    self.reader.header().schema_hash,
                    self.reader.header().kind_count,
                    info.record_count,
                    info.first_ts,
                    info.last_ts,
                    info.domain.to_vec().into_boxed_slice(),
                    payload.into_boxed_slice(),
                );
                Some(Ok(batch))
            }
        }
    }

    /// Read the next batch and decode its records.
    ///
    /// [SegmentReader::next_batch] hands back the payload opaque because a
    /// backend only moves bytes. A reader that wants the records as well -- the
    /// proxy's dump verb, which prints one JSON object per record inside the
    /// batch that carried it -- would otherwise have to parse the envelope
    /// itself, duplicating the one format this crate exists to own. Payloads are
    /// copied out of the frame; the scan above stays the zero-copy path.
    pub fn next_decoded_batch(&mut self) -> Option<Result<DecodedBatch, StoreError>> {
        let batch = match self.next_batch()? {
            Ok(batch) => batch,
            Err(error) => return Some(Err(error)),
        };
        match decode_records(&batch.payload, batch.record_count) {
            Ok(records) => Some(Ok(DecodedBatch { batch, records })),
            Err(error) => Some(Err(error)),
        }
    }

    /// Turn the reader into a record stream.
    #[must_use]
    pub fn into_scan(self) -> Scan {
        Scan {
            reader: self,
            frame: Vec::new(),
            frame_offset: 0,
            pos: 0,
            remaining: 0,
            done: false,
        }
    }
}

impl std::fmt::Debug for SegmentReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SegmentReader")
            .field("path", &self.reader.path)
            .field("offset", &self.reader.offset)
            .finish()
    }
}

/// One record copied out of a frame, with its payload owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedRecord {
    /// Level byte, 0..=4.
    pub level: u8,
    /// Category index.
    pub category: u8,
    /// Absolute kind.
    pub kind: u16,
    /// Unix nanoseconds.
    pub ts_ns: u64,
    /// Per-process sequence.
    pub seq: u32,
    /// Connection id, 0 for none.
    pub conn_id: u64,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// A validated batch together with its records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBatch {
    /// The batch as the file stores it.
    pub batch: EncodedBatch,
    /// Its records, in file order.
    pub records: Vec<OwnedRecord>,
}

/// Decode a batch that is already in memory.
///
/// The same envelope a segment frame carries, without a file around it: a
/// converter, a test sink or a tool that holds an [EncodedBatch] can read its
/// records without writing it out first.
pub fn decode_batch(batch: &EncodedBatch) -> Result<DecodedBatch, StoreError> {
    Ok(DecodedBatch {
        batch: batch.clone(),
        records: decode_records(&batch.payload, batch.record_count)?,
    })
}

fn decode_records(payload: &[u8], count: u32) -> Result<Vec<OwnedRecord>, StoreError> {
    let info = parse_batch(payload, 0)?;
    let mut position = info.header_len;
    let mut records = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let record = parse_record(payload, &mut position, 0)?;
        records.push(OwnedRecord {
            level: record.level,
            category: record.category,
            kind: record.kind,
            ts_ns: record.ts_ns,
            seq: record.seq,
            conn_id: record.conn_id,
            payload: record.payload.to_vec(),
        });
    }
    Ok(records)
}

/// Zero-copy record stream over one segment.
///
/// The iterator is lending: each record borrows the frame buffer until the
/// next call. That keeps the scan allocation free per record; copy the
/// payload if it must outlive the call.
pub struct Scan {
    reader: SegmentReader,
    frame: Vec<u8>,
    frame_offset: u64,
    pos: usize,
    remaining: u32,
    done: bool,
}

impl Scan {
    /// Open a segment for scanning.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Ok(SegmentReader::open(path)?.into_scan())
    }

    /// Validated header.
    #[must_use]
    pub fn header(&self) -> &Header {
        self.reader.header()
    }

    /// Next record, or an error at the first invalid frame.
    pub fn next_record(&mut self) -> Option<Result<RecordView<'_>, StoreError>> {
        if self.done {
            return None;
        }
        loop {
            if self.remaining == 0 {
                let mut frame = std::mem::take(&mut self.frame);
                match self.reader.reader.next_frame_into(&mut frame) {
                    None => {
                        self.done = true;
                        self.frame = frame;
                        return None;
                    }
                    Some(Err(error)) if error.kind() == ErrorKind::Truncated => {
                        self.done = true;
                        self.frame = frame;
                        return None;
                    }
                    Some(Err(error)) => {
                        self.done = true;
                        self.frame = frame;
                        return Some(Err(error));
                    }
                    Some(Ok(meta)) => {
                        let (header_len, record_count) = match parse_batch(&frame, meta.offset) {
                            Ok(info) => (info.header_len, info.record_count),
                            Err(error) => {
                                self.done = true;
                                self.frame = frame;
                                return Some(Err(error));
                            }
                        };
                        self.frame = frame;
                        self.frame_offset = meta.offset;
                        self.pos = header_len;
                        self.remaining = record_count;
                        if self.remaining == 0 {
                            continue;
                        }
                    }
                }
            }
            match parse_record(&self.frame, &mut self.pos, self.frame_offset) {
                Ok(record) => {
                    self.remaining -= 1;
                    return Some(Ok(record));
                }
                Err(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

impl std::fmt::Debug for Scan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scan")
            .field("path", &self.reader.reader.path)
            .field("frame_offset", &self.frame_offset)
            .field("done", &self.done)
            .finish()
    }
}

/// How a segment ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailState {
    /// The file ends exactly after a valid frame.
    Clean,
    /// The file ends in the middle of a frame; normal for a live writer.
    Truncated {
        /// Byte offset of the incomplete frame.
        offset: u64,
    },
    /// A frame or a batch is invalid.
    Corrupt {
        /// Byte offset of the invalid frame.
        offset: u64,
    },
    /// A compressed frame was found without the zstd feature.
    Unsupported {
        /// Byte offset of the frame.
        offset: u64,
    },
}

impl TailState {
    /// Stable short name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Truncated { .. } => "truncated",
            Self::Corrupt { .. } => "corrupt",
            Self::Unsupported { .. } => "unsupported",
        }
    }
}

/// Result of probing a segment without a codec.
#[derive(Clone, Debug)]
pub struct Probe {
    /// File that was probed.
    pub path: PathBuf,
    /// Validated header.
    pub header: Header,
    /// Number of valid frames.
    pub frames: u64,
    /// Number of valid records.
    pub records: u64,
    /// Smallest record timestamp.
    pub first_ts_ns: Option<u64>,
    /// Largest record timestamp.
    pub last_ts_ns: Option<u64>,
    /// Distinct connection ids, up to the cap.
    pub conn_ids: Vec<u64>,
    /// True when more distinct ids existed than the cap.
    pub conn_ids_truncated: bool,
    /// Records per absolute kind.
    pub kinds: BTreeMap<u16, u64>,
    /// Records whose kind is at or above the header kind count.
    pub unknown_records: u64,
    /// Byte offset just past the last valid frame.
    pub valid_end: u64,
    /// File length minus the valid end.
    pub truncated_bytes: u64,
    /// How the valid prefix ended.
    pub tail: TailState,
    /// SHA-256 of bytes 0..valid_end.
    pub sha256: [u8; 32],
}

impl Probe {
    /// Lower-case hex of the prefix hash.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex(&self.sha256)
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

fn hash_prefix(path: &Path, valid_end: u64) -> Result<[u8; 32], StoreError> {
    let file = File::open(path).map_err(|error| with_path(StoreError::io(error), path))?;
    let mut file = file.take(valid_end);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(StoreError::io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finish())
}

/// Probe a segment without any codec.
pub fn probe(path: &Path) -> Result<Probe, StoreError> {
    let mut reader = FrameReader::open(path)?;
    let header = reader.header().clone();
    let mut buffer = Vec::new();
    let mut frames = 0u64;
    let mut records = 0u64;
    let mut first_ts: Option<u64> = None;
    let mut last_ts: Option<u64> = None;
    let mut conns = BTreeSet::new();
    let mut conn_ids_truncated = false;
    let mut kinds: BTreeMap<u16, u64> = BTreeMap::new();
    let mut unknown_records = 0u64;
    let mut valid_end = reader.offset();
    let mut tail = TailState::Clean;

    'frames: loop {
        match reader.next_frame_into(&mut buffer) {
            None => break,
            Some(Err(error)) => {
                let offset = error.offset().unwrap_or_else(|| reader.offset());
                valid_end = offset;
                tail = match error.kind() {
                    ErrorKind::Truncated => TailState::Truncated { offset },
                    ErrorKind::Unsupported => TailState::Unsupported { offset },
                    ErrorKind::Corrupt | ErrorKind::Format | ErrorKind::Refused => {
                        TailState::Corrupt { offset }
                    }
                    _ => return Err(with_path(error, path)),
                };
                break;
            }
            Some(Ok(meta)) => {
                let info = match validate_batch(&buffer, meta.offset) {
                    Ok(info) => info,
                    Err(_) => {
                        valid_end = meta.offset;
                        tail = TailState::Corrupt {
                            offset: meta.offset,
                        };
                        break;
                    }
                };
                frames += 1;
                records += u64::from(info.record_count);
                first_ts = Some(first_ts.map_or(info.first_ts, |value| value.min(info.first_ts)));
                last_ts = Some(last_ts.map_or(info.last_ts, |value| value.max(info.last_ts)));
                let mut pos = info.header_len;
                for _ in 0..info.record_count {
                    let record = match parse_record(&buffer, &mut pos, meta.offset) {
                        Ok(record) => record,
                        Err(_) => {
                            valid_end = meta.offset;
                            tail = TailState::Corrupt {
                                offset: meta.offset,
                            };
                            break 'frames;
                        }
                    };
                    if conns.len() < PROBE_CONNECTION_CAP {
                        conns.insert(record.conn_id);
                    } else if !conns.contains(&record.conn_id) {
                        conn_ids_truncated = true;
                    }
                    *kinds.entry(record.kind).or_insert(0) += 1;
                    if record.kind >= header.kind_count {
                        unknown_records += 1;
                    }
                }
                valid_end = meta.offset + 8 + u64::from(meta.stored_len);
            }
        }
    }

    let len = reader.len();
    let sha256 = hash_prefix(path, valid_end)?;
    Ok(Probe {
        path: path.to_path_buf(),
        header,
        frames,
        records,
        first_ts_ns: first_ts,
        last_ts_ns: last_ts,
        conn_ids: conns.into_iter().collect(),
        conn_ids_truncated,
        kinds,
        unknown_records,
        valid_end,
        truncated_bytes: len.saturating_sub(valid_end),
        tail,
        sha256,
    })
}

/// Write a raw envelope dump: no codec, payload as hex.
pub fn dump_raw(path: &Path, out: &mut impl Write) -> Result<(), StoreError> {
    let mut scan = Scan::open(path)?;
    let header = scan.header().clone();
    let _ = writeln!(
        out,
        "header format={} codec={} kind_count={} flags=0x{:04x} producer={} session={:08x}",
        header.format,
        header.codec_id,
        header.kind_count,
        header.flags,
        header.producer_id,
        header.session_nonce
    );
    loop {
        match scan.next_record() {
            None => break,
            Some(Ok(record)) => {
                let _ = writeln!(
                    out,
                    "frame={} level={} category={} kind=0x{:04x} ts_ns={} seq={} conn={} payload={}",
                    record.frame_offset,
                    record.level,
                    record.category,
                    record.kind,
                    record.ts_ns,
                    record.seq,
                    record.conn_id,
                    hex(record.payload)
                );
            }
            Some(Err(error)) => {
                let _ = writeln!(out, "stop: {error}");
                break;
            }
        }
    }
    out.flush().map_err(StoreError::io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn hex_is_lower_case() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}
