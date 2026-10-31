//! logreel facade.
//!
//! One import for applications: the event contract and pipeline from
//! logreel-core, the derive macro, and the optional segment file backend.
//!
//! The default feature set is empty. Enable text, ring, file or zstd
//! explicitly; a dependency that only needs records does not link a
//! formatting or storage stack.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use logreel_core::*;
pub use logreel_derive::Event;

/// Append-only segment file backend.
#[cfg(feature = "file")]
pub use logreel_file as file;
