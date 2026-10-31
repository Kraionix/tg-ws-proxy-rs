//! Batch and record parsing.

use logreel_store::{ErrorKind, StoreError};

use crate::header::MAX_PAYLOAD;
use crate::varint;

/// One record borrowed from a validated frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordView<'a> {
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
    pub payload: &'a [u8],
    /// Byte offset of the frame that contains this record.
    pub frame_offset: u64,
}

#[derive(Debug)]
pub(crate) struct BatchInfo<'a> {
    pub(crate) record_count: u32,
    pub(crate) first_ts: u64,
    pub(crate) last_ts: u64,
    pub(crate) domain: &'a [u8],
    pub(crate) header_len: usize,
}

fn corrupt(message: impl Into<String>, offset: u64) -> StoreError {
    StoreError::new(ErrorKind::Corrupt, message).at(offset)
}

fn take<'a>(
    payload: &'a [u8],
    pos: &mut usize,
    len: usize,
    offset: u64,
) -> Result<&'a [u8], StoreError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| corrupt("length overflow", offset))?;
    let slice = payload
        .get(*pos..end)
        .ok_or_else(|| corrupt("unexpected end of batch", offset))?;
    *pos = end;
    Ok(slice)
}

pub(crate) fn parse_batch<'a>(
    payload: &'a [u8],
    frame_offset: u64,
) -> Result<BatchInfo<'a>, StoreError> {
    let mut pos = 0usize;
    let record_count = u32::from_le_bytes(
        take(payload, &mut pos, 4, frame_offset)?
            .try_into()
            .expect("4 bytes"),
    );
    let first_ts = u64::from_le_bytes(
        take(payload, &mut pos, 8, frame_offset)?
            .try_into()
            .expect("8 bytes"),
    );
    let last_ts = u64::from_le_bytes(
        take(payload, &mut pos, 8, frame_offset)?
            .try_into()
            .expect("8 bytes"),
    );
    if first_ts > last_ts {
        return Err(corrupt("batch timestamps are inverted", frame_offset));
    }
    let mask_len = usize::from(u16::from_le_bytes(
        take(payload, &mut pos, 2, frame_offset)?
            .try_into()
            .expect("2 bytes"),
    ));
    take(payload, &mut pos, mask_len, frame_offset)?;
    let domain_len = usize::from(u16::from_le_bytes(
        take(payload, &mut pos, 2, frame_offset)?
            .try_into()
            .expect("2 bytes"),
    ));
    let domain = take(payload, &mut pos, domain_len, frame_offset)?;
    Ok(BatchInfo {
        record_count,
        first_ts,
        last_ts,
        domain,
        header_len: pos,
    })
}

pub(crate) fn parse_record<'a>(
    payload: &'a [u8],
    pos: &mut usize,
    frame_offset: u64,
) -> Result<RecordView<'a>, StoreError> {
    let level = *take(payload, pos, 1, frame_offset)?
        .first()
        .expect("one byte");
    if level > 4 {
        return Err(corrupt(
            format!("level {level} is out of range"),
            frame_offset,
        ));
    }
    let category = *take(payload, pos, 1, frame_offset)?
        .first()
        .expect("one byte");
    let kind = u16::from_le_bytes(
        take(payload, pos, 2, frame_offset)?
            .try_into()
            .expect("2 bytes"),
    );
    let ts_ns = u64::from_le_bytes(
        take(payload, pos, 8, frame_offset)?
            .try_into()
            .expect("8 bytes"),
    );
    if ts_ns >= 1 << 63 {
        return Err(corrupt(
            "timestamp is outside the supported range",
            frame_offset,
        ));
    }
    let seq = varint::read(payload, pos, 5).map_err(|reason| corrupt(reason, frame_offset))?;
    if seq > u64::from(u32::MAX) {
        return Err(corrupt("sequence overflows u32", frame_offset));
    }
    let conn_id = varint::read(payload, pos, 10).map_err(|reason| corrupt(reason, frame_offset))?;
    let payload_len =
        varint::read(payload, pos, 5).map_err(|reason| corrupt(reason, frame_offset))?;
    if payload_len > MAX_PAYLOAD as u64 {
        return Err(corrupt("record payload exceeds 64 MiB", frame_offset));
    }
    let payload = take(payload, pos, payload_len as usize, frame_offset)?;
    Ok(RecordView {
        level,
        category,
        kind,
        ts_ns,
        seq: seq as u32,
        conn_id,
        payload,
        frame_offset,
    })
}

/// Validate every record and that the batch ends exactly.
pub(crate) fn validate_batch<'a>(
    payload: &'a [u8],
    frame_offset: u64,
) -> Result<BatchInfo<'a>, StoreError> {
    let info = parse_batch(payload, frame_offset)?;
    let mut pos = info.header_len;
    for _ in 0..info.record_count {
        parse_record(payload, &mut pos, frame_offset)?;
    }
    if pos != payload.len() {
        return Err(corrupt(
            format!(
                "{} trailing bytes after the last record",
                payload.len() - pos
            ),
            frame_offset,
        ));
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::{parse_batch, parse_record, validate_batch};
    use logreel_store::ErrorKind;

    #[allow(clippy::type_complexity)]
    fn batch_bytes(count: u32, records: &[(u8, u8, u16, u64, u64, u64, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&7u64.to_le_bytes());
        out.extend_from_slice(&9u64.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(0b0000_0011);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(b"dc");
        for (level, category, kind, ts, seq, conn, payload) in records {
            out.push(*level);
            out.push(*category);
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&ts.to_le_bytes());
            crate::varint::put(&mut out, *seq);
            crate::varint::put(&mut out, *conn);
            crate::varint::put(&mut out, payload.len() as u64);
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn batch_header_and_records_parse() {
        let bytes = batch_bytes(2, &[(2, 0, 0, 10, 1, 42, b"a"), (4, 1, 1, 11, 2, 0, b"bb")]);
        let info = validate_batch(&bytes, 56).expect("validate");
        assert_eq!(info.record_count, 2);
        assert_eq!(info.domain, b"dc");
        let mut pos = info.header_len;
        let first = parse_record(&bytes, &mut pos, 56).expect("record");
        assert_eq!(first.kind, 0);
        assert_eq!(first.payload, b"a");
        assert_eq!(first.conn_id, 42);
        let second = parse_record(&bytes, &mut pos, 56).expect("record");
        assert_eq!(second.payload, b"bb");
        assert_eq!(pos, bytes.len());
    }

    #[test]
    fn trailing_bytes_are_corrupt() {
        let mut bytes = batch_bytes(1, &[(2, 0, 0, 10, 1, 0, b"a")]);
        bytes.push(0);
        let error = validate_batch(&bytes, 0).expect_err("trailing");
        assert_eq!(error.kind(), ErrorKind::Corrupt);
    }

    #[test]
    fn bad_level_is_corrupt() {
        let bytes = batch_bytes(1, &[(9, 0, 0, 10, 1, 0, b"a")]);
        let error = validate_batch(&bytes, 0).expect_err("level");
        assert_eq!(error.kind(), ErrorKind::Corrupt);
    }

    #[test]
    fn truncated_record_is_corrupt() {
        let mut bytes = batch_bytes(1, &[(2, 0, 0, 10, 1, 0, b"payload")]);
        bytes.truncate(bytes.len() - 2);
        let error = validate_batch(&bytes, 0).expect_err("truncated");
        assert_eq!(error.kind(), ErrorKind::Corrupt);
    }

    #[test]
    fn inverted_timestamps_are_corrupt() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&10u64.to_le_bytes());
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let error = parse_batch(&bytes, 0).expect_err("timestamps");
        assert_eq!(error.kind(), ErrorKind::Corrupt);
    }
}
