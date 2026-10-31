//! logreel facade.
//!
//! One import for applications: the event contract and pipeline from
//! logreel-core and the optional segment file backend.
//!
//! The default feature set is empty. Enable file or zstd explicitly; a
//! dependency that only needs records does not link a storage stack.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use logreel_core::*;

/// Append-only segment file backend.
#[cfg(feature = "file")]
pub use logreel_file as file;
