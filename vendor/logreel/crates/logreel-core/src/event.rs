use std::fmt;
use std::ops::RangeInclusive;

/// Kind range reserved for domains the main event enum does not own.
///
/// An external consumer can emit in this range without editing the core
/// enum, while official events stay below it.
pub const FOREIGN_KIND_RANGE: RangeInclusive<u16> = 0x8000..=0x8FFF;

/// The typed value of one record.
///
/// One type parameter per process. Domains with disjoint kind ranges are
/// nested enums that delegate to this trait.
///
/// The associated constants describe the producing domain, not a record:
/// the file writer takes them from the first batch and pins them in the
/// header. Defaults exist so a hand written event needs only kind, encode
/// and decode.
pub trait Event: Sized {
    /// Payload codec id, fixed for the file.
    const CODEC_ID: u16 = 0;
    /// Fingerprint of the event schema, fixed for the file.
    const SCHEMA_HASH: [u8; 16] = [0; 16];
    /// Number of kinds in this domain, used for the batch kind mask.
    const KINDS: u16 = 0;
    /// Absolute offset of this domain, used to make kinds local again.
    const BASE: u16 = 0;

    /// Absolute kind of this value.
    fn kind(&self) -> u16;

    /// Encode the payload, without the envelope.
    fn encode(&self, out: &mut Vec<u8>);

    /// Decode one payload.
    ///
    /// The kind is passed because a domain enum dispatches on it. A single
    /// event may ignore it.
    fn decode(kind: u16, bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// Failure to decode a payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    kind: u16,
    message: String,
}

impl DecodeError {
    /// Build an error for a kind with a message.
    #[must_use]
    pub fn new(kind: u16, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The kind that failed.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        self.kind
    }

    /// Human readable reason.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "kind 0x{:04x}: {}", self.kind, self.message)
    }
}

impl std::error::Error for DecodeError {}
