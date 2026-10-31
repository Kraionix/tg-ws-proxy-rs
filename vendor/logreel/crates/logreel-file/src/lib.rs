//! Append-only segment files for logreel.
//!
//! The binary layout is normative in docs/SPEC.md. This crate implements one
//! writer, day rotation with a byte cap, crash-safe recovery, probing and a
//! streaming reader. It never decodes payloads: the codec belongs to the
//! consumer.
//!
//! # Backend selection
//!
//! [FileStore] implements the logreel-store Store trait and is the default
//! backend. Enabling the zstd feature allows per-frame compression; without
//! it, a compressed frame is reported as Unsupported at its offset, never
//! guessed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod batch;
mod crc32c;
mod header;
mod reader;
mod sha256;
mod store;
mod time;
mod varint;

pub use batch::RecordView;
pub use header::{HEADER_LEN, Header, MAX_PAYLOAD};
pub use reader::{
    DecodedBatch, OwnedRecord, Probe, Scan, SegmentReader, TailState, decode_batch, dump_raw, probe,
};
pub use store::{Clock, FileStore, FileStoreConfig, SystemClock, segments};

pub use logreel_store;
