//! Structured event log: one small typed record per routing decision, written
//! to a redb file per UTC day so that "why did this session fall back to the
//! Cloudflare proxy at 14:03" is a query rather than a guess.
//!
//! The `tracing` output this sits beside is for a human reading a terminal: it
//! is unstructured, it is lost when the process exits, and on a router there is
//! usually nowhere for it to go. It stays as it is — the structured sink is
//! additive, and only runs when `--log-dir` is set.
//!
//! [`schema`] is the wire format, written by hand rather than generated: the
//! build has no `protoc` and no `build.rs`, and `prost`'s derives give a
//! complete encode/decode/`encoded_len` implementation without either. Field
//! numbers are the part of it that can never change once a segment exists, so
//! they are fixed by `artifacts/logging/10_SCHEMA.md` in the design set and this
//! module follows it rather than the other way round.
//!
//! Only the wire format is here so far; the emitter, the batching writer task
//! and the storage layer land in later commits on this branch.

pub mod schema;

#[cfg(test)]
mod tests;
