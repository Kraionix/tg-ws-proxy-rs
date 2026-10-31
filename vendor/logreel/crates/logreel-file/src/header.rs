//! The 56-byte file header.

use logreel_store::{ErrorKind, StoreError};

/// Header size in bytes.
pub const HEADER_LEN: usize = 56;
/// Maximum stored or uncompressed frame payload.
pub const MAX_PAYLOAD: usize = 64 * 1024 * 1024;

pub(crate) const MAGIC: &[u8; 8] = b"TGSLOG01";
pub(crate) const FORMAT: u16 = 1;
pub(crate) const FLAG_ZSTD: u16 = 1;

/// Validated segment header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Format version; only 1 is accepted.
    pub format: u16,
    /// Payload codec id.
    pub codec_id: u16,
    /// File flags; only bit 0 is defined.
    pub flags: u16,
    /// Informational kind count.
    pub kind_count: u16,
    /// Schema fingerprint.
    pub schema_hash: [u8; 16],
    /// Creation time in Unix nanoseconds.
    pub created_ns: u64,
    /// Producer identity; 0 means unspecified.
    pub producer_id: u32,
    /// Per-session nonce.
    pub session_nonce: u32,
}

impl Header {
    /// Build a header for a new file.
    #[must_use]
    pub fn new(
        codec_id: u16,
        kind_count: u16,
        schema_hash: [u8; 16],
        created_ns: u64,
        producer_id: u32,
        session_nonce: u32,
        compressed: bool,
    ) -> Self {
        Self {
            format: FORMAT,
            codec_id,
            flags: if compressed { FLAG_ZSTD } else { 0 },
            kind_count,
            schema_hash,
            created_ns,
            producer_id,
            session_nonce,
        }
    }

    /// Encode the header, including its CRC.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&self.format.to_le_bytes());
        out[10..12].copy_from_slice(&self.codec_id.to_le_bytes());
        out[12..14].copy_from_slice(&self.flags.to_le_bytes());
        out[14..16].copy_from_slice(&self.kind_count.to_le_bytes());
        out[16..32].copy_from_slice(&self.schema_hash);
        out[32..40].copy_from_slice(&self.created_ns.to_le_bytes());
        out[40..44].copy_from_slice(&self.producer_id.to_le_bytes());
        out[44..48].copy_from_slice(&self.session_nonce.to_le_bytes());
        out[48..52].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        let crc = crate::crc32c::crc32c(&out[0..52]);
        out[52..56].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// Parse and validate a header.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < HEADER_LEN {
            return Err(StoreError::new(
                ErrorKind::Format,
                format!("file is {} bytes, shorter than 56", bytes.len()),
            ));
        }
        if &bytes[0..8] != MAGIC {
            return Err(StoreError::new(ErrorKind::Refused, "bad magic"));
        }
        let format = u16::from_le_bytes([bytes[8], bytes[9]]);
        if format != FORMAT {
            return Err(StoreError::new(
                ErrorKind::Unsupported,
                format!("unsupported format {format}"),
            ));
        }
        let header_len = u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]);
        if header_len != HEADER_LEN as u32 {
            return Err(StoreError::new(
                ErrorKind::Unsupported,
                format!("unsupported header length {header_len}"),
            ));
        }
        let crc = u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]);
        if crate::crc32c::crc32c(&bytes[0..52]) != crc {
            return Err(StoreError::new(
                ErrorKind::Format,
                "header CRC does not match",
            ));
        }
        let flags = u16::from_le_bytes([bytes[12], bytes[13]]);
        if flags & !FLAG_ZSTD != 0 {
            return Err(StoreError::new(
                ErrorKind::Format,
                format!("unknown header flags 0x{flags:04x}"),
            ));
        }
        let mut schema_hash = [0u8; 16];
        schema_hash.copy_from_slice(&bytes[16..32]);
        Ok(Self {
            format,
            codec_id: u16::from_le_bytes([bytes[10], bytes[11]]),
            flags,
            kind_count: u16::from_le_bytes([bytes[14], bytes[15]]),
            schema_hash,
            created_ns: u64::from_le_bytes(bytes[32..40].try_into().expect("8 bytes")),
            producer_id: u32::from_le_bytes(bytes[40..44].try_into().expect("4 bytes")),
            session_nonce: u32::from_le_bytes(bytes[44..48].try_into().expect("4 bytes")),
        })
    }

    /// True when the file may contain compressed frames.
    #[must_use]
    pub const fn contains_zstd(&self) -> bool {
        self.flags & FLAG_ZSTD != 0
    }
}

#[cfg(test)]
mod tests {
    use super::{FLAG_ZSTD, Header, MAGIC};

    #[test]
    fn encode_parse_roundtrip() {
        let header = Header::new(3, 9, [0x42; 16], 1_700_000_000, 7, 0x1234_5678, true);
        let bytes = header.encode();
        assert_eq!(&bytes[0..8], MAGIC);
        assert_eq!(bytes.len(), 56);
        assert_eq!(Header::parse(&bytes).expect("parse"), header);
        assert!(header.contains_zstd());
        assert_eq!(header.flags, FLAG_ZSTD);
    }

    #[test]
    fn corruption_is_rejected() {
        let mut bytes = Header::new(1, 1, [0; 16], 0, 0, 0, false).encode();
        bytes[20] ^= 0xFF;
        let error = Header::parse(&bytes).expect_err("crc");
        assert_eq!(error.kind(), logreel_store::ErrorKind::Format);
        assert!(Header::parse(&bytes[..10]).is_err());
    }
}
