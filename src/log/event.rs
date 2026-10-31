//! The bridge between the proxy's record schema and the library's event contract.
//!
//! The schema in [`super::schema`] is not replaced: it is what the 22 event
//! types and their field numbers are written in, what the artifact fixes, and
//! what `render.rs` and the reader verbs already speak. What the library needs
//! is an implementation of [`logreel::Event`]: the absolute kind of a value, a
//! payload encoder and a kind-dispatched decoder. That is all this module is —
//! one trait implementation over the existing `prost` types, so the event
//! definitions keep their derives and no field number moves.
//!
//! Two numbers are fixed for the life of the file and travel in its header:
//!
//! * [`CODEC_ID`], the payload codec. 1 is this field-only `prost` encoding;
//!   0 is reserved by the library for "no codec", and anything else is another
//!   producer's.
//! * [`SCHEMA_HASH`], which must move whenever a field number, a oneof tag or
//!   an enum value moves. It is the first half of the schema's own
//!   [`schema::fingerprint`], so the test below compares the two rather than
//!   trusting a number somebody remembered to update.
//!
//! Kind space: the oneof tags are 16..=37, and [`logreel::Event::BASE`] is 16,
//! so a record's local kind is 0..=21 and the batch kind mask has one bit per
//! event in the order the schema declares them — the same layout the redb batch
//! header used, which is what keeps a converted segment's `kind_mask` equal to
//! the one its source carried.

use super::schema::Event;

/// Payload codec: the schema's own field numbers, encoded by `prost`.
pub const CODEC_ID: u16 = 1;

/// Events in the schema, one per oneof variant.
pub const KIND_COUNT: u16 = 22;

/// Tag of the first event; kinds are absolute, the library subtracts the base.
pub const BASE_KIND: u16 = 16;

/// First 16 bytes of [`schema::fingerprint`]'s hash, as the file header stores it.
///
/// The schema's fingerprint is 64 bits and the header is 16 bytes wide, so the
/// second half carries the schema version and the event count: a build that
/// bumps one without the other still writes a different header, which is the
/// point of a tripwire.
pub const SCHEMA_HASH: [u8; 16] = [84, 213, 234, 51, 79, 95, 114, 106, 2, 0, 0, 0, 22, 0, 0, 0];

impl logreel::Event for Event {
    const CODEC_ID: u16 = CODEC_ID;
    const SCHEMA_HASH: [u8; 16] = SCHEMA_HASH;
    const KINDS: u16 = KIND_COUNT;
    const BASE: u16 = BASE_KIND;

    fn kind(&self) -> u16 {
        match self {
            Self::SessionOpened(_) => 16,
            Self::SessionClosed(_) => 17,
            Self::TierAttempt(_) => 18,
            Self::TierFallback(_) => 19,
            Self::CooldownArmed(_) => 20,
            Self::CooldownCleared(_) => 21,
            Self::CooldownSkipped(_) => 22,
            Self::PoolHit(_) => 23,
            Self::PoolMiss(_) => 24,
            Self::PoolRefill(_) => 25,
            Self::TlsHandshake(_) => 26,
            Self::RelayInitRetries(_) => 27,
            Self::AcceptError(_) => 28,
            Self::FdSnapshot(_) => 29,
            Self::ProbeResult(_) => 30,
            Self::LogOverflow(_) => 31,
            Self::StartupSummary(_) => 32,
            Self::PoolDiscard(_) => 33,
            Self::WarmupComplete(_) => 34,
            Self::AttemptSkipped(_) => 35,
            Self::DomainListFetched(_) => 36,
            Self::Shutdown(_) => 37,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::SessionOpened(message) => put(message, out),
            Self::SessionClosed(message) => put(message, out),
            Self::TierAttempt(message) => put(message, out),
            Self::TierFallback(message) => put(message, out),
            Self::CooldownArmed(message) => put(message, out),
            Self::CooldownCleared(message) => put(message, out),
            Self::CooldownSkipped(message) => put(message, out),
            Self::PoolHit(message) => put(message, out),
            Self::PoolMiss(message) => put(message, out),
            Self::PoolRefill(message) => put(message, out),
            Self::TlsHandshake(message) => put(message, out),
            Self::RelayInitRetries(message) => put(message, out),
            Self::AcceptError(message) => put(message, out),
            Self::FdSnapshot(message) => put(message, out),
            Self::ProbeResult(message) => put(message, out),
            Self::LogOverflow(message) => put(message, out),
            Self::StartupSummary(message) => put(message, out),
            Self::PoolDiscard(message) => put(message, out),
            Self::WarmupComplete(message) => put(message, out),
            Self::AttemptSkipped(message) => put(message, out),
            Self::DomainListFetched(message) => put(message, out),
            Self::Shutdown(message) => put(message, out),
        }
    }

    fn decode(kind: u16, bytes: &[u8]) -> Result<Self, logreel::DecodeError> {
        Ok(match kind {
            16 => Self::SessionOpened(get(bytes, kind)?),
            17 => Self::SessionClosed(get(bytes, kind)?),
            18 => Self::TierAttempt(get(bytes, kind)?),
            19 => Self::TierFallback(get(bytes, kind)?),
            20 => Self::CooldownArmed(get(bytes, kind)?),
            21 => Self::CooldownCleared(get(bytes, kind)?),
            22 => Self::CooldownSkipped(get(bytes, kind)?),
            23 => Self::PoolHit(get(bytes, kind)?),
            24 => Self::PoolMiss(get(bytes, kind)?),
            25 => Self::PoolRefill(get(bytes, kind)?),
            26 => Self::TlsHandshake(get(bytes, kind)?),
            27 => Self::RelayInitRetries(get(bytes, kind)?),
            28 => Self::AcceptError(get(bytes, kind)?),
            29 => Self::FdSnapshot(get(bytes, kind)?),
            30 => Self::ProbeResult(get(bytes, kind)?),
            31 => Self::LogOverflow(get(bytes, kind)?),
            32 => Self::StartupSummary(get(bytes, kind)?),
            33 => Self::PoolDiscard(get(bytes, kind)?),
            34 => Self::WarmupComplete(get(bytes, kind)?),
            35 => Self::AttemptSkipped(get(bytes, kind)?),
            36 => Self::DomainListFetched(get(bytes, kind)?),
            37 => Self::Shutdown(get(bytes, kind)?),
            other => {
                return Err(logreel::DecodeError::new(other, "no event has this kind"));
            }
        })
    }
}

/// Encode one message into the batch payload's scratch buffer.
fn put<M: prost::Message>(message: &M, out: &mut Vec<u8>) {
    message
        .encode(out)
        .expect("encoding into a Vec cannot run out of room");
}

/// Decode one message, naming the kind that failed.
fn get<M: prost::Message + Default>(bytes: &[u8], kind: u16) -> Result<M, logreel::DecodeError> {
    M::decode(bytes).map_err(|error| logreel::DecodeError::new(kind, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{KIND_COUNT, SCHEMA_HASH};
    use crate::log::schema;

    #[test]
    fn the_header_hash_carries_the_schema_fingerprint() {
        let mut first = [0u8; 8];
        first.copy_from_slice(&SCHEMA_HASH[..8]);
        assert_eq!(
            u64::from_le_bytes(first),
            schema::fingerprint(),
            "schema::fingerprint moved; update SCHEMA_HASH in src/log/event.rs"
        );
        assert_eq!(&SCHEMA_HASH[8..12], &schema::SCHEMA_VERSION.to_le_bytes());
        assert_eq!(&SCHEMA_HASH[12..14], &KIND_COUNT.to_le_bytes());
    }
}
