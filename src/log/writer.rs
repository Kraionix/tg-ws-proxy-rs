//! The writer task: batching, flushing, and the seam storage plugs into.
//!
//! Records arrive on a bounded channel and leave as [`LogBatch`]es. The task
//! owns the only buffer, allocates it once at the configured batch size, and
//! clears it per flush — `INV:log.single_writer` in practice. Nothing here
//! touches the filesystem: [`BatchSink`] is the boundary, so the batching logic
//! is testable without a disk and the storage layer can fail on its own terms.
//!
//! Flushing is driven by three things, in the order the `select!` checks them:
//! a shutdown signal, an arriving record (which flushes when the batch is full,
//! or immediately on a warning when asked to), and the interval timer that
//! bounds how long a record can sit unwritten. Whichever ends the loop, the
//! final flush drains what is left, so a clean shutdown loses nothing that was
//! already queued.

// Nothing in the binary reaches this module until the wiring stage starts the
// subsystem from `main`; until then the only caller is the test module, whose
// target has `cfg(test)` set. Delete this with the last `#[allow(dead_code)]`
// in `log.rs`.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

use tokio::sync::{mpsc, watch};
use tracing::warn;

use super::schema::{Category, Event, Level, LogBatch, LogOverflow, LogRecord, build_batch};
use super::{Counters, Settings, now_ns};

/// Where a finished batch goes.
///
/// The writer's only dependency on storage, and the reason this stage has tests
/// at all: `write` may fail, and a failing sink must not stop the writer or
/// grow its buffer.
pub(crate) trait BatchSink: Send {
    fn write(&mut self, batch: &LogBatch) -> Result<(), WriterError>;
}

/// A sink refused a batch. The records in it are lost — the sink's own retry
/// and backoff policy belongs to the storage layer, which is the only thing
/// that knows whether waiting would help.
#[derive(Debug)]
pub(crate) enum WriterError {
    Io(std::io::Error),
}

impl std::fmt::Display for WriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "sink write failed: {error}"),
        }
    }
}

impl std::error::Error for WriterError {}

/// The batching buffer, separate from the task so that the parts worth testing
/// — batch boundaries, buffer reuse, sink failures — need no runtime.
pub(super) struct Writer<S> {
    sink: S,
    buf: Vec<LogRecord>,
    batch_max: usize,
}

impl<S: BatchSink> Writer<S> {
    pub(super) fn new(sink: S, batch_max: usize) -> Self {
        let batch_max = batch_max.clamp(super::MIN_BATCH_MAX, super::MAX_BATCH_MAX);
        Self {
            sink,
            // Once, at the configured size: this buffer is touched on every
            // record, and growing it under a burst is a reallocation per
            // connection on a device with very little memory to spare.
            buf: Vec::with_capacity(batch_max),
            batch_max,
        }
    }

    pub(super) fn push(&mut self, record: LogRecord) {
        self.buf.push(record);
    }

    pub(super) fn is_full(&self) -> bool {
        self.buf.len() >= self.batch_max
    }

    /// Writes everything buffered, returning how many records went out.
    ///
    /// The buffer is emptied even when the sink fails: retrying is the storage
    /// layer's decision, and a sink that stays broken must not turn this into
    /// an unbounded queue.
    pub(super) fn flush(&mut self) -> Result<usize, WriterError> {
        let count = self.buf.len();
        if count == 0 {
            return Ok(0);
        }

        let mut outcome = Ok(());
        for batch in build_batch(&self.buf) {
            if let Err(error) = self.sink.write(&batch) {
                outcome = Err(error);
                break;
            }
        }

        self.buf.clear();
        outcome.map(|()| count)
    }

    /// The buffer's capacity, which after the first flush is what it will be
    /// for the life of the process.
    pub(super) fn buffered_capacity(&self) -> usize {
        self.buf.capacity()
    }
}

/// The writer task's mutable state, so that the flush path — which reports
/// dropped records before it writes anything — is one call wide instead of five
/// arguments wide.
struct Task<S> {
    writer: Writer<S>,
    counters: Arc<Counters>,
    failures: u64,
    overflow_window: Instant,
}

impl<S: BatchSink> Task<S> {
    /// Reports any records the producers dropped, then writes what is
    /// buffered.
    fn flush(&mut self) {
        self.report_overflow();
        if let Err(error) = self.writer.flush() {
            self.failures += 1;
            warn!(
                failures = self.failures,
                error = %error,
                "log sink write failed, batch dropped"
            );
        }
    }

    /// Turns the producer-side drop counter into a record of its own.
    ///
    /// The count is taken rather than read, so each report covers the window
    /// since the previous one and a burst of drops becomes one line in the file
    /// instead of a line per dropped record — the channel being full is exactly
    /// when writing more records is the wrong answer.
    fn report_overflow(&mut self) {
        let dropped = self.counters.dropped.swap(0, Relaxed);
        if dropped == 0 {
            return;
        }

        let now = Instant::now();
        self.writer.push(LogRecord {
            ts_ns: now_ns(),
            conn_id: 0,
            seq: self.counters.next_seq(),
            level: Level::Warn as i32,
            category: Category::Overflow as i32,
            event: Some(Event::LogOverflow(LogOverflow {
                dropped,
                window_ns: now.duration_since(self.overflow_window).as_nanos() as u64,
            })),
        });
        self.overflow_window = now;
    }
}

/// The writer task. Runs until the handle asks it to stop or the channel
/// closes, then flushes what is left before returning.
pub(super) async fn run<S: BatchSink + 'static>(
    sink: S,
    mut rx: mpsc::Receiver<LogRecord>,
    counters: Arc<Counters>,
    settings: Settings,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut task = Task {
        writer: Writer::new(sink, settings.batch_max),
        counters,
        failures: 0,
        overflow_window: Instant::now(),
    };

    // Started one full interval out rather than immediately: the first tick of
    // a bare `interval` is ready at once, which would flush the buffer the
    // moment a record arrived and quietly turn the interval into a no-op.
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + settings.flush_interval,
        settings.flush_interval,
    );

    loop {
        tokio::select! {
            // Shutdown first: when the process is going away, the last thing it
            // wants is to keep draining a queue that is about to disappear.
            biased;

            _ = shutdown.changed() => break,

            received = rx.recv() => {
                let Some(record) = received else { break };
                let warn_now = settings.flush_on_warn && record.level >= Level::Warn as i32;
                task.writer.push(record);
                if warn_now || task.writer.is_full() {
                    task.flush();
                }
            }

            _ = ticker.tick() => task.flush(),
        }
    }

    // Whatever arrived between the last flush and the signal. Producers that
    // emit after this point are dropped, which is why shutdown happens after
    // the accept loop has stopped rather than before.
    while let Ok(record) = rx.try_recv() {
        task.writer.push(record);
        if task.writer.is_full() {
            task.flush();
        }
    }

    task.flush();
}
