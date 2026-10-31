//! The second consumer the pipeline can carry.
//!
//! Every application that shows its records -- a text line with state, a
//! ring kept for a post-mortem dump, a protocol line a deployment depends on
//! -- owns exactly one of these. The library keeps no view of its own: what a
//! record means as text is the consumer's business. The writer thread is the
//! only caller, so the methods take `&mut self`: an observer needs no lock to
//! keep state between records.
//!
//! Ordering is the contract:
//!
//! * [Observer::record] runs for every record the writer takes off the
//!   channel, before the sink filter decides whether the segment keeps it.
//!   A view therefore sees records the disk may drop.
//! * [Observer::flush] runs once after the batch it belongs to was handed to
//!   the sink (or dropped by the sink filter), so a buffered consumer writes
//!   once per batch rather than once per record.
//! * [Observer::dump] runs after the channel was drained and the batch
//!   flushed, which is what makes a dump from a signal show the records that
//!   were queued when the signal arrived.
//! * [Observer::overflow] runs with the number of records dropped since the
//!   last report; the record it returns joins the batch like any other,
//!   which is how the log says its own channel was full.

use crate::{Event, Record};

/// A record consumer owned by the writer thread.
pub trait Observer<E: Event> {
    /// One record, in arrival order.
    fn record(&mut self, record: &Record<E>);

    /// End of a batch: commit what [Observer::record] buffered.
    fn flush(&mut self) {}

    /// The channel was drained; emit whatever a post-mortem dump should show.
    fn dump(&mut self) {}

    /// Records were dropped; return the record that reports it, if any.
    ///
    /// `dropped` is the number dropped since the previous call and
    /// `window_ns` is how long that took. Returning [None] keeps the log
    /// quiet, which is the right answer for a consumer that reports overflow
    /// some other way.
    fn overflow(&mut self, dropped: u64, window_ns: u64) -> Option<Record<E>> {
        let _ = (dropped, window_ns);
        None
    }
}
