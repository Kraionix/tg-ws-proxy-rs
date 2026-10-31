//! Core event pipeline for logreel.
//!
//! The crate owns the event contract, the record envelope, filters, the
//! writer pipeline and scopes. It performs no I/O itself: encoded batches
//! leave through a [BatchSink] supplied by the caller, and anything that
//! wants to look at a record as a line or keep one for a dump does so from
//! its own [Observer].
//!
//! # Pipeline
//!
//! A producer checks a filter, builds a payload, stamps a timestamp and a
//! sequence number, and pushes a record into a bounded channel. One writer
//! thread encodes batches and calls the sink. The emit path is static and
//! allocation free; every fallible or blocking operation happens on the
//! writer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod batch;
mod event;
mod filter;
mod level;
mod observer;
mod pipeline;
mod record;
mod scope;
mod settings;
mod time;

pub use batch::BatchEncoder;
pub use event::{DecodeError, Event, FOREIGN_KIND_RANGE};
pub use filter::{CATEGORY_COUNT, FilterSnapshot, Filters};
pub use level::Level;
pub use observer::Observer;
pub use pipeline::{Handle, InitError, Logger, ShutdownReport, init, init_with};
pub use record::Record;
pub use scope::{current, scope, try_emit, with_current};
pub use settings::{InternalError, InternalErrorKind, Settings, SettingsBuilder};
pub use time::{format_utc, now_ns};

pub use logreel_store::{
    BatchSink, Durability, EncodedBatch, ErrorKind, SharedSink, Store, StoreError,
};

/// Emit an event through the task-local scope.
///
/// The event type is inferred from the argument, so the macro works with the
/// one event type of the process. Outside a scope it does nothing and returns
/// false. Inside a scope it returns true when the record was queued and false
/// when the level was filtered out or the channel was full.
#[macro_export]
macro_rules! log_event {
    ($level:expr, $category:expr, $event:expr $(,)?) => {
        $crate::try_emit($level, $category, $event)
    };
}
