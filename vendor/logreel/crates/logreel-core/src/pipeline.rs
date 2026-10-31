use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use logreel_store::{BatchSink, Durability};

use crate::batch::BatchEncoder;
use crate::filter::Filters;
use crate::observer::Observer;
use crate::settings::{InternalError, InternalErrorKind, Settings};
use crate::time::now_ns;
use crate::{Event, Level, Record};

enum Msg<E> {
    Record(Record<E>),
    Flush,
    Dump,
    Shutdown { quiet: Duration, limit: Duration },
}

/// Shared producer handle.
///
/// The handle is never cloned; it is shared as an Arc. It carries the bounded
/// sender, the filter table, the sequence counter and the drop counter. A
/// handle outside any configured scope still works; the scoped API is a
/// convenience on top.
pub struct Handle<E: Event> {
    tx: SyncSender<Msg<E>>,
    filters: Arc<Filters>,
    dropped: Arc<AtomicU64>,
    seq: AtomicU32,
}

impl<E: Event> Handle<E> {
    /// True when a record at this category and level is wanted.
    #[must_use]
    pub fn enabled(&self, category: u8, level: Level) -> bool {
        self.filters.enabled(category, level)
    }

    /// Filter table, for live reconfiguration.
    #[must_use]
    pub fn filters(&self) -> &Filters {
        &self.filters
    }

    /// Try to emit one record.
    ///
    /// Returns true when the record was queued, false when the filter
    /// rejected it or the channel was full. A full channel increments the
    /// drop counter and never blocks the producer.
    pub fn emit(&self, level: Level, category: u8, conn_id: u64, event: E) -> bool {
        if !self.filters.enabled(category, level) {
            return false;
        }
        let record = Record::new(
            level,
            category,
            event.kind(),
            now_ns(),
            self.seq.fetch_add(1, Ordering::Relaxed),
            conn_id,
            event,
        );
        match self.tx.try_send(Msg::Record(record)) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Ask the writer to flush the current batch.
    #[must_use]
    pub fn flush(&self) -> bool {
        self.tx.try_send(Msg::Flush).is_ok()
    }

    /// Ask the writer to drain everything it holds and hand the observer its
    /// [Observer::dump] once the queue is empty. False means the writer was
    /// already gone.
    #[must_use]
    pub fn request_dump(&self) -> bool {
        self.tx.try_send(Msg::Dump).is_ok()
    }

    /// Records dropped because the channel was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Next sequence number that will be assigned.
    #[must_use]
    pub fn sequence(&self) -> u32 {
        self.seq.load(Ordering::Relaxed)
    }
}

impl<E: Event> fmt::Debug for Handle<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Handle")
            .field("dropped", &self.dropped())
            .field("sequence", &self.sequence())
            .finish()
    }
}

/// Counters collected by the writer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Records handed to a sink.
    pub records: u64,
    /// Batches handed to a sink.
    pub batches: u64,
    /// Payload bytes plus frame headers.
    pub bytes: u64,
    /// Records dropped by a full channel.
    pub dropped: u64,
    /// Sink write or sync failures.
    pub sink_errors: u64,
    /// Last sink error, if any.
    pub error: Option<String>,
}

/// Owner of the writer thread.
///
/// Dropping the logger without calling [Logger::shutdown] disconnects the
/// channel and lets the writer drain in the background; the thread is not
/// joined. Call shutdown for a deterministic stop.
pub struct Logger<E: Event> {
    handle: Arc<Handle<E>>,
    join: Option<JoinHandle<WriterResult>>,
}

impl<E: Event> Logger<E> {
    /// Shared producer handle.
    #[must_use]
    pub fn handle(&self) -> &Arc<Handle<E>> {
        &self.handle
    }

    /// Stop the writer deterministically: drain, flush, sync, join.
    ///
    /// The channel may be full, and the writer is the only consumer, so a
    /// blocking send is correct: it drains records before it observes the
    /// shutdown.
    #[must_use]
    pub fn shutdown(self) -> ShutdownReport {
        self.shutdown_with(Duration::ZERO, Duration::ZERO)
    }

    /// Stop after a grace window.
    ///
    /// The writer keeps draining until the channel has been quiet for
    /// `quiet`, or until `limit` has passed in total, whichever comes first;
    /// then it flushes the tail and returns. A zero `limit` is
    /// [Logger::shutdown]. Callers that must not block a runtime worker use
    /// this to bound the tail.
    #[must_use]
    pub fn shutdown_with(mut self, quiet: Duration, limit: Duration) -> ShutdownReport {
        let _ = self.handle.tx.send(Msg::Shutdown { quiet, limit });
        let result = self
            .join
            .take()
            .and_then(|join| join.join().ok())
            .map(ShutdownReport::from)
            .unwrap_or_default();
        ShutdownReport {
            dropped: self.handle.dropped(),
            ..result
        }
    }
}

impl<E: Event> fmt::Debug for Logger<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Logger")
            .field("handle", &self.handle)
            .finish()
    }
}

/// Configuration error detected before the writer starts.
#[derive(Debug)]
pub enum InitError {
    /// The channel capacity is zero.
    ZeroCapacity,
    /// The batch size is zero.
    ZeroBatch,
    /// The flush interval is zero.
    ZeroFlushInterval,
    /// The writer thread could not be spawned.
    Spawn(String),
}

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => formatter.write_str("channel capacity must be non-zero"),
            Self::ZeroBatch => formatter.write_str("batch size must be non-zero"),
            Self::ZeroFlushInterval => formatter.write_str("flush interval must be non-zero"),
            Self::Spawn(message) => write!(formatter, "writer thread: {message}"),
        }
    }
}

impl std::error::Error for InitError {}

/// Start the pipeline.
pub fn init<E: Event + Send + 'static>(
    settings: Settings,
    sink: Box<dyn BatchSink>,
) -> Result<Logger<E>, InitError> {
    init_with(settings, None, sink)
}

/// Start the pipeline with a consumer that sees records as they arrive.
///
/// The observer runs on the writer thread; see [Observer] for the ordering.
/// The sink table in [Settings::sink_min_level] and the per-category
/// overrides decide what reaches `sink`; the producer gate stays the union of
/// every consumer.
pub fn init_with<E: Event + Send + 'static>(
    settings: Settings,
    observer: Option<Box<dyn Observer<E> + Send>>,
    sink: Box<dyn BatchSink>,
) -> Result<Logger<E>, InitError> {
    if settings.channel_capacity == 0 {
        return Err(InitError::ZeroCapacity);
    }
    if settings.batch_max == 0 {
        return Err(InitError::ZeroBatch);
    }
    if settings.flush_interval.is_zero() {
        return Err(InitError::ZeroFlushInterval);
    }
    let filters = Arc::new(Filters::new(settings.min_level));
    for &(category, level) in &settings.filter_overrides {
        filters.set(category, level);
    }
    let sink_filters = Arc::new(Filters::new(settings.sink_min_level));
    for &(category, level) in &settings.sink_filter_overrides {
        sink_filters.set(category, level);
    }
    let dropped = Arc::new(AtomicU64::new(0));
    let (tx, rx) = sync_channel(settings.channel_capacity);
    let handle = Arc::new(Handle {
        tx,
        filters,
        dropped: Arc::clone(&dropped),
        // One, not zero: zero is the unused-looking value a reader can treat as
        // "no sequence yet", and it keeps the first record's number stable
        // across the version that assigned it from outside.
        seq: AtomicU32::new(1),
    });
    let join = thread::Builder::new()
        .name("logreel-writer".to_owned())
        .spawn(move || writer_loop(rx, settings, observer, sink, sink_filters, dropped))
        .map_err(|error| InitError::Spawn(error.to_string()))?;
    Ok(Logger {
        handle,
        join: Some(join),
    })
}

#[derive(Default)]
struct WriterResult {
    records: u64,
    batches: u64,
    bytes: u64,
    sink_errors: u64,
    error: Option<String>,
}

struct Writer<E: Event> {
    settings: Settings,
    observer: Option<Box<dyn Observer<E> + Send>>,
    sink: Box<dyn BatchSink>,
    sink_filters: Arc<Filters>,
    encoder: BatchEncoder,
    batch: Vec<Record<E>>,
    dropped: Arc<AtomicU64>,
    seen_dropped: u64,
    last_overflow: Instant,
    /// A stop absorbed by a drain, served by the loop before it exits.
    stop: Option<(Duration, Duration)>,
    result: WriterResult,
}

impl<E: Event> Writer<E> {
    fn flush(&mut self) {
        // A dropped record is a record nobody wrote: turn the counter into a
        // record of its own before the batch that will carry it is encoded.
        self.report_overflow();
        if self.batch.is_empty() {
            return;
        }

        let filters = Arc::clone(&self.sink_filters);
        let mut has_warn = false;
        for record in &self.batch {
            if filters.enabled(record.category, record.level) && record.level >= Level::Warn {
                has_warn = true;
                break;
            }
        }

        let encoded = self
            .encoder
            .encode_where(&self.batch, &self.settings.domain, |record| {
                filters.enabled(record.category, record.level)
            });
        if encoded.record_count > 0 {
            self.result.records += u64::from(encoded.record_count);
            self.result.batches += 1;
            self.result.bytes += (encoded.payload_len() + 8) as u64;

            if let Err(error) = self.sink.write_batch(&encoded) {
                self.result.sink_errors += 1;
                self.result.error = Some(error.to_string());
                self.report(InternalErrorKind::Sink, error.to_string());
            }

            let mode = match self.settings.durability {
                Durability::OnWarn if has_warn => Durability::Immediate,
                other => other,
            };
            if let Err(error) = self.sink.sync(mode) {
                self.result.sink_errors += 1;
                self.result.error = Some(error.to_string());
                self.report(InternalErrorKind::Sink, error.to_string());
            }
        }

        if let Some(observer) = self.observer.as_mut() {
            observer.flush();
        }
        self.batch.clear();
    }

    /// Take one record: the observer, then the batch.
    ///
    /// The observer sees a record on arrival, not at flush: a line that waits
    /// for the next batch is a line a crash can still lose.
    fn push(&mut self, record: Record<E>) {
        if let Some(observer) = self.observer.as_mut() {
            observer.record(&record);
        }
        self.batch.push(record);
    }

    /// Turn the shared drop counter into the observer's overflow record.
    ///
    /// Called at the top of a flush, so a storm reports once per batch rather
    /// than once per dropped record. The returned record joins the batch it
    /// was reported in front of, which is what puts it in the segment.
    fn report_overflow(&mut self) {
        let total = self.dropped.load(Ordering::Relaxed);
        if total <= self.seen_dropped {
            return;
        }
        let dropped = total - self.seen_dropped;
        self.seen_dropped = total;
        let window = self.last_overflow.elapsed();
        self.last_overflow = Instant::now();
        let Some(observer) = self.observer.as_mut() else {
            return;
        };
        if let Some(record) = observer.overflow(dropped, window.as_nanos() as u64) {
            self.push(record);
        }
    }

    fn dump(&mut self, rx: &Receiver<Msg<E>>) {
        while let Ok(msg) = rx.try_recv() {
            self.absorb(msg);
        }
        self.flush();
        if let Some(observer) = self.observer.as_mut() {
            observer.dump();
        }
    }

    fn drain_until(&mut self, rx: &Receiver<Msg<E>>, quiet: Duration, limit: Duration) {
        let start = Instant::now();
        loop {
            let remaining = limit.saturating_sub(start.elapsed());
            if limit.is_zero() || remaining.is_zero() {
                while let Ok(msg) = rx.try_recv() {
                    self.absorb(msg);
                }
                return;
            }
            let wait = quiet.min(remaining);
            match rx.recv_timeout(wait) {
                Ok(msg) => self.absorb(msg),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return,
            }
            if start.elapsed() >= limit {
                return;
            }
        }
    }

    fn absorb(&mut self, msg: Msg<E>) {
        match msg {
            Msg::Record(record) => self.push(record),
            // A flush or dump queued behind the stop is already satisfied by
            // the flush the caller is about to perform.
            Msg::Flush | Msg::Dump => {}
            // A drain that runs into the stop consumes it like anything else;
            // remembering it here is what keeps the handshake from being
            // lost to the drain that preceded it.
            Msg::Shutdown { quiet, limit } => self.stop = Some((quiet, limit)),
        }
    }

    fn finish(&mut self) {
        if let Err(error) = self.sink.flush() {
            self.result.sink_errors += 1;
            self.result.error = Some(error.to_string());
            self.report(InternalErrorKind::Sink, error.to_string());
        }
        if let Err(error) = self.sink.sync(Durability::Immediate) {
            self.result.sink_errors += 1;
            self.result.error = Some(error.to_string());
            self.report(InternalErrorKind::Sink, error.to_string());
        }
    }

    fn report(&self, kind: InternalErrorKind, message: String) {
        if let Some(callback) = &self.settings.on_internal {
            callback(InternalError { kind, message });
        }
    }
}

fn writer_loop<E: Event>(
    rx: Receiver<Msg<E>>,
    settings: Settings,
    observer: Option<Box<dyn Observer<E> + Send>>,
    sink: Box<dyn BatchSink>,
    sink_filters: Arc<Filters>,
    dropped: Arc<AtomicU64>,
) -> WriterResult {
    let mut writer = Writer {
        batch: Vec::with_capacity(settings.batch_max),
        settings,
        observer,
        sink,
        sink_filters,
        encoder: BatchEncoder::new(),
        dropped,
        seen_dropped: 0,
        last_overflow: Instant::now(),
        stop: None,
        result: WriterResult::default(),
    };

    loop {
        match rx.recv_timeout(writer.settings.flush_interval) {
            Ok(Msg::Record(record)) => {
                let warn = record.level >= Level::Warn;
                writer.push(record);
                if writer.batch.len() >= writer.settings.batch_max
                    || (writer.settings.flush_on_warn && warn)
                {
                    writer.flush();
                }
            }
            Ok(Msg::Flush) => writer.flush(),
            Ok(Msg::Dump) => writer.dump(&rx),
            Ok(Msg::Shutdown { quiet, limit }) => writer.stop = Some((quiet, limit)),
            Err(RecvTimeoutError::Timeout) => writer.flush(),
            // Every producer is gone: there is nothing left to wait for, so
            // the stop is immediate rather than graceful.
            Err(RecvTimeoutError::Disconnected) => {
                writer.stop = Some((Duration::ZERO, Duration::ZERO));
            }
        }
        if let Some((quiet, limit)) = writer.stop.take() {
            writer.drain_until(&rx, quiet, limit);
            writer.flush();
            writer.finish();
            break;
        }
    }
    writer.result
}

impl From<WriterResult> for ShutdownReport {
    fn from(result: WriterResult) -> Self {
        Self {
            records: result.records,
            batches: result.batches,
            bytes: result.bytes,
            dropped: 0,
            sink_errors: result.sink_errors,
            error: result.error,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use logreel_store::{BatchSink, EncodedBatch, StoreError};

    use super::{Handle, Logger, init_with};
    use crate::{DecodeError, Event, Level, Record, Settings};

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum TestEvent {
        Note(u64),
        Overflow(u64),
    }

    impl Event for TestEvent {
        const KINDS: u16 = 2;

        fn kind(&self) -> u16 {
            match self {
                Self::Note(_) => 0,
                Self::Overflow(_) => 1,
            }
        }

        fn encode(&self, out: &mut Vec<u8>) {
            let value = match self {
                Self::Note(value) | Self::Overflow(value) => value,
            };
            out.extend_from_slice(&value.to_le_bytes());
        }

        fn decode(kind: u16, bytes: &[u8]) -> Result<Self, DecodeError> {
            if bytes.len() != 8 {
                return Err(DecodeError::new(kind, "payload must be 8 bytes"));
            }
            let mut array = [0u8; 8];
            array.copy_from_slice(bytes);
            let value = u64::from_le_bytes(array);
            match kind {
                0 => Ok(Self::Note(value)),
                1 => Ok(Self::Overflow(value)),
                _ => Err(DecodeError::new(kind, "unknown kind")),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Step {
        Record(u64),
        Flush,
        Dump,
        Overflow(u64),
    }

    #[derive(Default)]
    struct Probe {
        steps: Mutex<Vec<Step>>,
    }

    impl Probe {
        fn steps(&self) -> Vec<Step> {
            self.steps.lock().expect("probe lock").clone()
        }
    }

    impl crate::Observer<TestEvent> for Probe {
        fn record(&mut self, record: &Record<TestEvent>) {
            let value = match record.event {
                TestEvent::Note(value) | TestEvent::Overflow(value) => value,
            };
            self.steps
                .lock()
                .expect("probe lock")
                .push(Step::Record(value));
        }

        fn flush(&mut self) {
            self.steps.lock().expect("probe lock").push(Step::Flush);
        }

        fn dump(&mut self) {
            self.steps.lock().expect("probe lock").push(Step::Dump);
        }

        fn overflow(&mut self, dropped: u64, _window_ns: u64) -> Option<Record<TestEvent>> {
            self.steps
                .lock()
                .expect("probe lock")
                .push(Step::Overflow(dropped));
            Some(Record::new(
                Level::Error,
                0,
                1,
                1,
                0,
                0,
                TestEvent::Overflow(dropped),
            ))
        }
    }

    #[derive(Clone, Default)]
    struct Batches(std::sync::Arc<Mutex<Vec<EncodedBatch>>>);

    impl Batches {
        fn all(&self) -> Vec<EncodedBatch> {
            self.0.lock().expect("batches lock").clone()
        }
    }

    struct SlowSink {
        batches: Batches,
        delay: Duration,
    }

    impl BatchSink for SlowSink {
        fn write_batch(&mut self, batch: &EncodedBatch) -> Result<(), StoreError> {
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            self.batches
                .0
                .lock()
                .expect("batches lock")
                .push(batch.clone());
            Ok(())
        }
    }

    fn settings() -> Settings {
        Settings::builder()
            .batch_max(64)
            .flush_interval(Duration::from_secs(60))
            .build()
    }

    fn probe_logger(
        settings: Settings,
        probe: std::sync::Arc<Probe>,
    ) -> (Logger<TestEvent>, Batches) {
        let batches = Batches::default();
        let logger = init_with::<TestEvent>(
            settings,
            Some(Box::new(ArcProbe(probe))),
            Box::new(SlowSink {
                batches: batches.clone(),
                delay: Duration::ZERO,
            }),
        )
        .expect("init");
        (logger, batches)
    }

    /// The observer trait takes `&mut self`; the test asserts from the
    /// outside, so the probe is shared behind an Arc and the wrapper keeps the
    /// writer's exclusive view.
    struct ArcProbe(std::sync::Arc<Probe>);

    impl crate::Observer<TestEvent> for ArcProbe {
        fn record(&mut self, record: &Record<TestEvent>) {
            let value = match record.event {
                TestEvent::Note(value) | TestEvent::Overflow(value) => value,
            };
            self.0
                .steps
                .lock()
                .expect("probe lock")
                .push(Step::Record(value));
        }

        fn flush(&mut self) {
            self.0.steps.lock().expect("probe lock").push(Step::Flush);
        }

        fn dump(&mut self) {
            self.0.steps.lock().expect("probe lock").push(Step::Dump);
        }

        fn overflow(&mut self, dropped: u64, _window_ns: u64) -> Option<Record<TestEvent>> {
            self.0
                .steps
                .lock()
                .expect("probe lock")
                .push(Step::Overflow(dropped));
            Some(Record::new(
                Level::Error,
                0,
                1,
                1,
                0,
                0,
                TestEvent::Overflow(dropped),
            ))
        }
    }

    #[test]
    fn observer_sees_records_the_sink_filter_drops() {
        let probe = std::sync::Arc::new(Probe::default());
        let settings = Settings::builder()
            .batch_max(64)
            .flush_interval(Duration::from_secs(60))
            .sink_min_level(Level::Error)
            .build();
        let (logger, batches) = probe_logger(settings, std::sync::Arc::clone(&probe));
        let handle: &Handle<TestEvent> = logger.handle();
        assert!(handle.emit(Level::Info, 0, 0, TestEvent::Note(1)));
        assert!(handle.emit(Level::Error, 0, 0, TestEvent::Note(2)));

        let report = logger.shutdown();
        assert_eq!(report.records, 1, "only the error reaches the sink");
        assert_eq!(batches.all().len(), 1);

        let records: Vec<Step> = probe
            .steps()
            .into_iter()
            .filter(|step| matches!(step, Step::Record(_)))
            .collect();
        assert_eq!(records, vec![Step::Record(1), Step::Record(2)]);
    }

    #[test]
    fn sink_filter_can_disable_one_category() {
        let probe = std::sync::Arc::new(Probe::default());
        let settings = Settings::builder()
            .batch_max(64)
            .flush_interval(Duration::from_secs(60))
            .sink_filter(5, None)
            .build();
        let (logger, batches) = probe_logger(settings, probe);
        logger.handle().emit(Level::Error, 5, 0, TestEvent::Note(1));
        logger.handle().emit(Level::Error, 6, 0, TestEvent::Note(2));
        let report = logger.shutdown();
        assert_eq!(report.records, 1);
        assert_eq!(batches.all()[0].record_count, 1);
    }

    #[test]
    fn request_dump_drains_the_queue_before_the_observer_dump() {
        let probe = std::sync::Arc::new(Probe::default());
        let settings = Settings::builder()
            .batch_max(64)
            .flush_interval(Duration::from_secs(60))
            .build();
        let (logger, _) = probe_logger(settings, std::sync::Arc::clone(&probe));
        for value in 0..3 {
            logger
                .handle()
                .emit(Level::Info, 0, 0, TestEvent::Note(value));
        }
        assert!(logger.handle().request_dump());
        let report = logger.shutdown();
        assert_eq!(report.records, 3);

        assert_eq!(
            probe.steps(),
            vec![
                Step::Record(0),
                Step::Record(1),
                Step::Record(2),
                Step::Flush,
                Step::Dump,
            ]
        );
    }

    #[test]
    fn grace_shutdown_still_drains_the_tail() {
        let probe = std::sync::Arc::new(Probe::default());
        let settings = Settings::builder()
            .batch_max(64)
            .flush_interval(Duration::from_secs(60))
            .build();
        let (logger, batches) = probe_logger(settings, probe);
        for value in 0..5 {
            logger
                .handle()
                .emit(Level::Info, 0, 0, TestEvent::Note(value));
        }
        let report = logger.shutdown_with(Duration::from_millis(100), Duration::from_millis(250));
        assert_eq!(report.records, 5);
        assert_eq!(batches.all()[0].record_count, 5);
    }

    #[test]
    fn a_full_channel_is_reported_by_the_observer() {
        let probe = std::sync::Arc::new(Probe::default());
        let settings = Settings::builder()
            .channel_capacity(1)
            .batch_max(64)
            .flush_interval(Duration::from_secs(60))
            .build();
        let batches = Batches::default();
        let logger = init_with::<TestEvent>(
            settings,
            Some(Box::new(ArcProbe(std::sync::Arc::clone(&probe)))),
            Box::new(SlowSink {
                batches: batches.clone(),
                delay: Duration::from_millis(150),
            }),
        )
        .expect("init");
        let handle = logger.handle();
        // The writer is asleep in the sink and the channel holds one record, so
        // this loop must fill it; the cap bounds a broken implementation.
        for value in 0..1_000 {
            handle.emit(Level::Info, 0, 0, TestEvent::Note(value));
            if handle.dropped() > 0 {
                break;
            }
        }
        assert!(handle.dropped() > 0, "the channel never filled");

        let report = logger.shutdown_with(Duration::from_millis(200), Duration::from_secs(5));
        assert!(report.dropped > 0);
        let steps = probe.steps();
        assert!(
            steps.iter().any(|step| matches!(step, Step::Overflow(_))),
            "the observer was never told about the drops: {steps:?}"
        );
        assert!(
            batches.all().iter().any(|batch| batch.record_count > 0),
            "the overflow record never reached the sink"
        );
    }

    #[test]
    fn sequence_counter_is_shared() {
        let probe = std::sync::Arc::new(Probe::default());
        let (logger, _) = probe_logger(settings(), probe);
        assert_eq!(logger.handle().sequence(), 1);
        logger.handle().emit(Level::Info, 0, 0, TestEvent::Note(1));
        assert_eq!(logger.handle().sequence(), 2);
        let _ = logger.shutdown();
    }
}
