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

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use super::schema::{Category, Event, Level, LogBatch, LogOverflow, LogRecord, build_batch};
use super::view::View;
#[cfg(feature = "log-disk")]
use super::{CATEGORY_COUNT, Filter};
use super::{Counters, Settings, now_ns};

/// Where a finished batch goes.
///
/// The writer's only dependency on storage, and the reason this stage has tests
/// at all: `write` may fail, and a failing sink must not stop the writer or
/// grow its buffer.
pub(crate) trait BatchSink: Send {
    fn write(&mut self, batch: &LogBatch) -> Result<(), WriterError>;
}

/// The sink a run without `--log-dir` gets: records reach the writer, the
/// text view and the ring, and stop there.
///
/// It is a sink rather than a second code path because everything above it —
/// batching, the flush timer, the overflow report — is the same work whatever
/// happens to the batch, and a run that switched those off would be a run whose
/// log behaves differently depending on where it is going.
pub(super) struct MemorySink;

impl BatchSink for MemorySink {
    fn write(&mut self, _batch: &LogBatch) -> Result<(), WriterError> {
        Ok(())
    }
}

/// A sink refused a batch. The records in it are lost — the sink's own retry
/// and backoff policy belongs to the storage layer, which is the only thing
/// that knows whether waiting would help.
///
/// Every variant but the one the tests raise is constructed by that storage
/// layer, so a build without the `log-disk` feature has no producer for them:
/// the type is still needed for [`BatchSink`]'s signature.
#[derive(Debug)]
#[cfg_attr(not(feature = "log-disk"), allow(dead_code))]
pub(crate) enum WriterError {
    /// Sink-side I/O: a directory that cannot be created, a volume that is gone.
    Io(std::io::Error),
    /// The segment file is held by another process.
    Conflict,
    /// The storage backend refused the batch. The message is the backend's own,
    /// because nothing above this layer matches on it — it is written to the
    /// operator and backed off on.
    Segment(String),
}

impl std::fmt::Display for WriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "sink write failed: {error}"),
            Self::Conflict => f.write_str("the segment is locked by another process"),
            Self::Segment(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for WriterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// What the writer task listens to besides the record channel.
///
/// Both are `watch` receivers rather than queues: neither the stop nor a ring
/// dump may be lost, and both are states rather than a stream of work — a
/// second stop during a stop is the same stop, and two dumps in a row are two
/// bumps of one counter.
pub(super) struct Control {
    pub(super) shutdown: watch::Receiver<bool>,
    pub(super) dump: watch::Receiver<u64>,
}

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
    #[allow(dead_code)] // the reuse it documents is asserted by the tests
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
    /// The segment's own filter, indexed by category. The producer gate is the
    /// union of the consumers' policies, so a record can reach this task that
    /// the segment does not want: the text view or the ring asked for it, and
    /// this is where the disk policy becomes exact.
    #[cfg(feature = "log-disk")]
    disk: [Filter; CATEGORY_COUNT],
    failures: u64,
    overflow_window: Instant,
}

impl<S: BatchSink> Task<S> {
    /// Takes one record off the channel, keeping it when the segment wants it.
    /// Returns whether it was buffered, which is what decides on a flush.
    fn ingest(&mut self, record: LogRecord) -> bool {
        if !self.keeps(&record) {
            return false;
        }
        self.writer.push(record);
        true
    }

    /// True when the segment's filter keeps this record.
    ///
    /// A level this build does not know — a discriminant a later writer added,
    /// which `prost` preserves as an integer — is kept rather than dropped: the
    /// filter exists to keep the file small, not to lose records it cannot
    /// classify.
    #[cfg(feature = "log-disk")]
    fn keeps(&self, record: &LogRecord) -> bool {
        let Some(filter) = self.disk.get(record.category as usize) else {
            return false;
        };
        match Level::try_from(record.level) {
            Ok(level) => filter.keeps(level),
            Err(_) => true,
        }
    }

    /// A build without the `log-disk` feature has no segment to filter for: the
    /// sink under this task is the memory one, and the writer batches whatever
    /// reached the channel. What dropped a record was the producer gate — the
    /// text view's floor and the ring's — before it ever got here.
    #[cfg(not(feature = "log-disk"))]
    fn keeps(&self, _record: &LogRecord) -> bool {
        true
    }

    /// Takes a record the view has already seen: buffered for the segment when
    /// the segment wants it, flushed when the batch is full.
    fn accept(&mut self, record: LogRecord, view: &mut View) {
        if self.ingest(record) && self.writer.is_full() {
            self.flush(view);
        }
    }

    /// Reports any records the producers dropped, then writes what is
    /// buffered.
    fn flush(&mut self, view: &mut View) {
        self.report_overflow(view);
        if let Err(error) = self.writer.flush() {
            self.failures += 1;
            // Not a record: this is the sink the record would have been
            // written to saying it could not write. The count is in the line
            // because the first failure is the interesting one and the
            // thousandth is the same failure.
            crate::direct!(
                "log sink write failed ({} so far), batch dropped: {error}",
                self.failures
            );
        }
    }

    /// Turns the producer-side drop counter into a record of its own.
    ///
    /// The count is taken rather than read, so each report covers the window
    /// since the previous one and a burst of drops becomes one line in the file
    /// instead of a line per dropped record — the channel being full is exactly
    /// when writing more records is the wrong answer.
    fn report_overflow(&mut self, view: &mut View) {
        let dropped = self.counters.dropped.swap(0, Relaxed);
        if dropped == 0 {
            return;
        }

        let now = Instant::now();
        let record = LogRecord {
            ts_ns: now_ns(),
            conn_id: 0,
            seq: self.counters.next_seq(),
            level: Level::Warn as i32,
            category: Category::Overflow as i32,
            event: Some(Event::LogOverflow(LogOverflow {
                dropped,
                window_ns: now.duration_since(self.overflow_window).as_nanos() as u64,
            })),
        };
        // Through the view as well: this record never crossed the channel, but
        // it is the one line an operator reads a burst by.
        view.show(&record);
        self.ingest(record);
        self.overflow_window = now;
    }
}

/// How long the drain keeps listening after the channel has gone quiet.
///
/// The shutdown signal reaches the writer when the accept loop stops, and a
/// session that was already past that point emits its close record a moment
/// later. "A clean stop loses nothing" has to cover that moment, not only the
/// records that were queued when the signal arrived.
///
/// A hundred milliseconds, not twenty-five: the margin has to survive a host
/// that schedules the emitting task late, and stage 6 measured one. Running the
/// suite under `qemu-aarch64` — a slow host by any measure — the test that
/// emits 5 ms after the stop failed three times out of three at 25 ms, and
/// passes at 100. A router is slower than this container and faster than qemu,
/// which is exactly the range where 25 ms is not enough and 100 is.
const DRAIN_QUIET: Duration = Duration::from_millis(100);

/// The longest the drain may run, however busy the producers still are.
///
/// Bounded on purpose: a stop must not be held hostage by a producer that keeps
/// emitting, and the records it produces after this point are the ones a stop
/// is allowed to cost.
const DRAIN_LIMIT: Duration = Duration::from_millis(250);

/// The writer task. Runs until the handle asks it to stop or the channel
/// closes, then flushes what is left before returning.
pub(super) async fn run<S: BatchSink + 'static>(
    sink: S,
    mut rx: mpsc::Receiver<LogRecord>,
    counters: Arc<Counters>,
    settings: Settings,
    mut control: Control,
    mut view: View,
) {
    let mut task = Task {
        writer: Writer::new(sink, settings.batch_max),
        counters,
        #[cfg(feature = "log-disk")]
        disk: settings.disk,
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

    // Stays true until the handle is dropped, which is when there is nobody
    // left to ask for a dump. An unchanged `watch` receiver whose sender is
    // gone reports a change every time it is polled, which in a `biased`
    // `select!` is a spin.
    let mut dumps_wanted = true;

    loop {
        tokio::select! {
            // Shutdown first: when the process is going away, the last thing it
            // wants is to keep draining a queue that is about to disappear.
            biased;

            _ = control.shutdown.changed() => break,

            result = control.dump.changed(), if dumps_wanted => {
                if result.is_err() {
                    dumps_wanted = false;
                } else {
                    // Everything already queued belongs in the dump: the
                    // operator is asking about the last few hundred records,
                    // and the ones still in flight are the most recent of them.
                    while let Ok(record) = rx.try_recv() {
                        view.show(&record);
                        task.accept(record, &mut view);
                    }
                    view.dump();
                }
            }

            received = rx.recv() => {
                let Some(record) = received else { break };
                // The view first, and whatever the segment's own filter thinks
                // of the record: the text and the ring have floors of their own.
                view.show(&record);
                let warn_now = settings.flush_on_warn && record.level >= Level::Warn as i32;
                if task.ingest(record) && (warn_now || task.writer.is_full()) {
                    task.flush(&mut view);
                }
            }

            _ = ticker.tick() => task.flush(&mut view),
        }
    }

    // Whatever arrived between the last flush and the signal. Written before
    // the drain window opens, so a stop that is killed during it still has
    // everything that was already queued.
    while let Ok(record) = rx.try_recv() {
        view.show(&record);
        task.accept(record, &mut view);
    }
    task.flush(&mut view);

    // And now the tail: the sessions that were mid-teardown when the signal
    // arrived. A record that lands exactly on the boundary is still lost — the
    // window is a bound on how long a stop may wait, not a promise about a
    // producer that cannot say when it is finished.
    let started = Instant::now();
    while started.elapsed() < DRAIN_LIMIT {
        match tokio::time::timeout(DRAIN_QUIET, rx.recv()).await {
            Ok(Some(record)) => {
                view.show(&record);
                task.accept(record, &mut view);
            }
            // Every producer is gone, or none has spoken for a whole window.
            Ok(None) | Err(_) => break,
        }
    }

    task.flush(&mut view);
    // The text was written line by line and flushed on every warning; this is
    // the last line of the stop, and a sink that buffers at all gets its chance
    // to write what it holds before the process is gone.
    view.flush();
}
