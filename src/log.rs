//! Structured event log: one small typed record per routing decision, so that
//! "why did this session fall back to the Cloudflare proxy at 14:03" is a query
//! rather than a guess.
//!
//! The text a human reads is a *projection* of these records, not a parallel
//! stream: [`render`] turns one record into one console line and [`view`] writes
//! them to a terminal or a file, so the two can no longer drift apart. The
//! pipeline runs in every build and whether or not the on-disk sink is
//! configured — without one the sink keeps nothing and the text log is the
//! whole of what the records are for.
//!
//! # What the `log-disk` feature adds
//!
//! The on-disk sink sits behind a cargo feature that is **off by default**:
//! [`storage`] (`.seg` day segments), the `--log-dir` flag family,
//! `--log-level`/`--log-category` (the disk floor is the only per-category
//! policy here), and the binary's `probe-segment`/`dump-segment` reader verbs.
//! A build without it links no storage engine and its `--help` mentions none of
//! them; the text view and the `SIGUSR1` ring are unaffected. [`Disk`] is how a
//! caller hands the sink over — and in a build without the feature there is no
//! sink to hand over.
//!
//! Three things are deliberately *not* records, because they cannot be: the
//! startup banner (it carries the `tg://` links and is printed before anything
//! else exists), the log's own failures (a broken sink cannot report through
//! itself), and the lines of other crates (`rustls`, `tungstenite`), which have
//! no schema of ours to be a variant of. [`direct!`] is how those are written:
//! one `tg-ws-proxy:`-prefixed line to stderr, never gated by a level.
//!
//! [`schema`] is the wire format, written by hand rather than generated: the
//! build has no `protoc` and no `build.rs`, and `prost`'s derives give a
//! complete encode/decode/`encoded_len` implementation without either. Field
//! numbers are the part of it that can never change once a segment exists, so
//! they are fixed by `artifacts/logging/10_SCHEMA.md` in the design set and this
//! module follows it rather than the other way round.
//!
//! # How a record travels
//!
//! A producer calls [`log_event!`], which checks the filter and hands the
//! payload to [`emit`](LogHandle::emit). The library stamps the wall clock and
//! the process-wide sequence number and pushes onto a bounded channel with
//! `try_send` — never a lock, never an `await`, because this runs on the routing
//! path in the middle of connection setup. The writer task at the far end
//! batches records and hands them to whatever sink the caller chose; the
//! channel, the filters and the batching are the library's, so this module owns
//! the settings and the view and not a second pipeline.
//!
//! The session a record belongs to is not a parameter. [`scope`] plants the
//! handle and the connection id in a task-local that the whole connection task
//! inherits — including the bridge futures and the upload tasks spawned from
//! it — so the ~110 call sites carry neither. A producer outside any scope
//! (or outside a connection entirely) emits nothing rather than panicking;
//! process-wide events are emitted inside a scope with `conn_id = 0` instead.

use std::future::Future;
#[cfg(feature = "log-disk")]
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use schema::{Category, Event, Level};
use view::{TEXT_RING_DEFAULT, TextTarget, View};

pub mod event;
pub mod render;
pub mod schema;
#[cfg(feature = "log-disk")]
pub mod storage;
pub mod view;

#[cfg(test)]
mod tests;

/// Number of category slots in a filter table, from the enum itself so that a
/// new category cannot be added without the table growing with it.
pub const CATEGORY_COUNT: usize = Category::Overflow as usize + 1;
const _: () = assert!(CATEGORY_COUNT == 11);

/// Records accepted per flush by Settings::batch_max's default.
pub const DEFAULT_BATCH_MAX: usize = 256;
/// Bounds of Settings::batch_max. The lower bound keeps a batch from being so
/// small that every record becomes its own write; the upper one keeps one flush
/// from holding a whole second of records in a batch.
pub const MIN_BATCH_MAX: usize = 16;
pub const MAX_BATCH_MAX: usize = 4096;

/// How long a record may sit unwritten before the writer flushes it.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Depth of the producer to writer channel.
///
/// Sized in *records*, which is what actually costs memory here: one record
/// carries its payload inline, so the channel is CHANNEL_CAPACITY times
/// size_of::<Record>() bytes of worst-case RAM on a device that may have 64 MB
/// of it. 1024 is two flushes' worth of steady-state traffic (5 ev/s over 2 s)
/// with two orders of magnitude of headroom for the reconnect storm that
/// follows a network change; a longer burst is a burst the log may lose.
pub(crate) const CHANNEL_CAPACITY: usize = 1024;

/// Version of the bytes a batch carries outside its records.
///
/// The domain field of every batch names the app version, the record schema and
/// this number: the reader prints them and a converter checks them before
/// trusting a file. It is independent of the segment format, which the library
/// versions itself.
pub const WRITER_PROTOCOL: u32 = 1;

/// How long a stop keeps draining after the channel goes quiet.
///
/// The accept loop stops before a session that is still tearing down, so the
/// moment between "stop" and "the writer exits" is exactly when the last
/// session's close record is produced. A hundred milliseconds, not twenty-five:
/// an earlier round measured the tail on a slow host and 25 ms was not enough.
const SHUTDOWN_QUIET: Duration = Duration::from_millis(100);
/// The longest a stop may wait for that tail, however busy the producers are.
const SHUTDOWN_LIMIT: Duration = Duration::from_millis(250);

/// Why the log subsystem could not be started.
///
/// Misconfiguration is fatal and runtime degradation is not: these are the
/// failures an operator has to fix, and the only ones that stop the process. A
/// write that fails once the proxy is running is a backoff and a warning
/// instead, because losing logs must never cost more than the logs.
#[derive(Debug)]
pub enum LogError {
    /// The log directory could not be created or opened.
    Io(std::io::Error),
    /// The filesystem cannot carry a segment; see storage::check_filesystem.
    #[cfg(feature = "log-disk")]
    FsUnsupported(String),
    /// Another process is already writing today's segment.
    #[cfg(feature = "log-disk")]
    WriterConflict(PathBuf),
    /// The segment file is not one this build can write.
    #[cfg(feature = "log-disk")]
    Segment(String),
    /// The text view's destination could not be opened. Fatal for the same
    /// reason the segment's is: an operator who asked for a log file and did
    /// not get one has to hear about it at startup, not at the first warning.
    TextSink(String),
    /// The library refused its configuration before the writer started.
    Pipeline(String),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            #[cfg(feature = "log-disk")]
            Self::FsUnsupported(reason) => f.write_str(reason),
            #[cfg(feature = "log-disk")]
            Self::WriterConflict(path) => write!(
                f,
                "another process is writing {}; use a different --log-dir for multi-instance deployments",
                path.display()
            ),
            #[cfg(feature = "log-disk")]
            Self::Segment(reason) => f.write_str(reason),
            Self::TextSink(reason) => f.write_str(reason),
            Self::Pipeline(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// One consumer's level policy.
///
/// The stream has three consumers -- the segment on disk, the text view and the
/// RAM ring -- and each has its own floor, so a single Level table is no longer
/// enough to describe one. Off is a policy and not the absence of one: the
/// producer gate is the union of the three, so a consumer nobody asked for must
/// not be the reason a payload is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Keeps nothing, whatever the level.
    Off,
    /// Keeps this level and everything above it.
    At(Level),
}

impl Filter {
    /// Keeps level and above.
    pub const fn at(level: Level) -> Self {
        Self::At(level)
    }

    /// Keeps nothing.
    pub const fn off() -> Self {
        Self::Off
    }

    /// True when this policy keeps nothing at all.
    pub fn is_off(self) -> bool {
        matches!(self, Self::Off)
    }

    /// The lowest level kept, or None when nothing is.
    pub fn floor(self) -> Option<Level> {
        match self {
            Self::Off => None,
            Self::At(level) => Some(level),
        }
    }

    /// True when a record at this level is kept: a floor, not a ceiling, so
    /// warn keeps warnings and errors and drops the rest.
    pub fn keeps(self, level: Level) -> bool {
        match self {
            Self::Off => false,
            Self::At(floor) => level as i32 >= floor as i32,
        }
    }

    /// The name the banner prints: the level's own, or off.
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::At(level) => level.name(),
        }
    }
}

/// What the subsystem is configured with.
///
/// One filter per consumer, plus the writer's batching policy. Which consumer
/// sees which record is decided in the library's writer from these tables: the
/// producers only ask whether *anyone* wants the payload.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Lowest level the segment sink records, indexed by Category. The only
    /// consumer with per-category exceptions, because it is the one an operator
    /// tunes: a flat table rather than a map, so the filter is an index and a
    /// compare.
    ///
    /// Only a build with the log-disk feature has a segment to record into, so
    /// only such a build has this table: without it the producer gate is the
    /// text view's floor and the ring's.
    #[cfg(feature = "log-disk")]
    pub disk: [Filter; CATEGORY_COUNT],
    /// Lowest level the text view renders. One floor for every category: the
    /// view is read by a human watching a terminal, not queried.
    pub text: Filter,
    /// Lowest level the RAM ring keeps, for the SIGUSR1 dump.
    pub ring: Filter,
    /// Where the rendered lines go.
    ///
    /// Settings::default is the quiet configuration: the text view is
    /// something an embedder opts into, and the binary's own default lives with
    /// its command line.
    pub text_log: TextTarget,
    /// Records the RAM ring holds, clamped to view::TEXT_RING_MIN and
    /// view::TEXT_RING_MAX.
    pub ring_capacity: usize,
    /// Records per flush, clamped to MIN_BATCH_MAX and MAX_BATCH_MAX.
    pub batch_max: usize,
    /// Records older than this are flushed even if the batch is not full.
    pub flush_interval: Duration,
    /// Flush as soon as a record at Level::Warn or above arrives, instead of
    /// waiting for the interval: a warning that reaches the file two seconds
    /// after the crash that followed it is not much of a warning.
    pub flush_on_warn: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            #[cfg(feature = "log-disk")]
            disk: [Filter::at(Level::Info); CATEGORY_COUNT],
            text: Filter::at(Level::Info),
            ring: Filter::at(Level::Info),
            text_log: TextTarget::Off,
            ring_capacity: TEXT_RING_DEFAULT,
            batch_max: DEFAULT_BATCH_MAX,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            flush_on_warn: false,
        }
    }
}

impl Settings {
    /// Lowest level any consumer keeps, or None when all three are off.
    fn gate(&self) -> Option<Level> {
        let mut floor: Option<Level> = None;
        let mut take = |filter: Filter| {
            if let Some(level) = filter.floor() {
                floor = Some(match floor {
                    Some(current) if (current as i32) <= (level as i32) => current,
                    _ => level,
                });
            }
        };
        #[cfg(feature = "log-disk")]
        for filter in self.disk {
            take(filter);
        }
        take(self.text);
        take(self.ring);
        floor
    }
}

/// The producer-side handle: one per process, shared as an Arc.
///
/// Deliberately not Clone: INV:log.single_writer says there is one writer per
/// process, and the writer's half of this struct is the library's Logger, which
/// cannot be duplicated. Share the Arc instead.
pub struct LogHandle {
    /// The library's producer handle: filter table, sequence counter, channel.
    inner: Arc<logreel::Handle<Event>>,
    /// Session numbering, which the library does not do.
    counters: Counters,
    /// The text view's floor, copied out of Settings so direct_at! needs no lock
    /// and no second lookup.
    text: Filter,
    /// The library's writer, taken by LogHandle::shutdown.
    logger: StdMutex<Option<logreel::Logger<Event>>>,
}

/// Session numbering. The sequence number moved into the library with the
/// channel; only the connection id is still this crate's, because a session is
/// a proxy concept and not a logging one.
#[derive(Default)]
struct Counters {
    /// AtomicU32 rather than AtomicU64 because the OpenWrt tier has to build:
    /// mips-unknown-linux-musl and its little-endian twin are 32-bit targets
    /// without 64-bit atomics, where AtomicU64 does not exist at all. Four
    /// billion connections is a thousand years of a busy home router, and a
    /// wrap is handled rather than assumed away.
    conn: AtomicU32,
}

impl Counters {
    /// The next session id, never zero: that is what makes conn_id == 0
    /// readable as "not a session" for the life of the process, wrap included.
    fn next_conn(&self) -> u64 {
        match self.conn.fetch_add(1, Relaxed) {
            0 => u64::from(self.conn.fetch_add(1, Relaxed)),
            id => u64::from(id),
        }
    }
}

impl LogHandle {
    /// True when a record of this category and level would be kept by *any*
    /// consumer: the segment, the text view or the ring.
    ///
    /// A level is a floor, not a ceiling: a threshold of info keeps info, warn
    /// and error and drops debug, which is what every operator means by
    /// "log level info".
    ///
    /// Callers use this to skip building a payload that no consumer wants. What
    /// each consumer keeps is a narrower question, answered in the writer where
    /// the record is delivered: getting the widening right here is what makes
    /// three consumers cost no more than one.
    pub fn enabled(&self, category: Category, level: Level) -> bool {
        self.inner.enabled(category as u8, logreel_level(level))
    }

    /// True when the *text view* would render a record at this level. Its own
    /// policy, not the union: a line the segment alone asked for is not a line
    /// to print.
    pub fn text_keeps(&self, level: Level) -> bool {
        self.text.keeps(level)
    }

    /// Next session id, allocated once per accepted connection. Never zero,
    /// which is what makes conn_id == 0 readable as "not a session".
    pub fn next_conn_id(&self) -> u64 {
        self.counters.next_conn()
    }

    /// Records that did not fit the channel. Not an error: the alternative
    /// would be blocking a connection on a logging write.
    pub fn dropped(&self) -> u32 {
        self.inner.dropped().min(u64::from(u32::MAX)) as u32
    }

    /// Appends one record. Never awaits, never blocks, never allocates.
    ///
    /// Takes the session id rather than reading the task-local so that
    /// process-wide emitters and tests can call it directly; emit is the
    /// scope-aware wrapper producers normally reach through log_event!.
    pub fn emit(&self, conn_id: u64, category: Category, level: Level, event: Event) {
        let _ = self
            .inner
            .emit(logreel_level(level), category as u8, conn_id, event);
    }

    /// Prints the last records the ring holds, through the text sink.
    ///
    /// Asynchronous by construction: this only asks, and the writer -- the only
    /// owner of the ring -- answers when it next runs. A signal handler must
    /// never wait for a task that may be mid-flush.
    pub fn dump_ring(&self) {
        let _ = self.inner.request_dump();
    }

    /// Stops the writer, flushing what is already queued, and waits for it.
    ///
    /// Idempotent, and safe to call when a shutdown is already in progress: the
    /// second caller finds no writer left to stop. On return the file contains
    /// everything this process emitted before the call, up to the grace window
    /// that lets a session mid-teardown emit its close record.
    pub async fn shutdown(&self) {
        let logger = self
            .logger
            .lock()
            .expect("log writer mutex cannot be poisoned")
            .take();
        let Some(logger) = logger else {
            return;
        };

        // The writer is a std thread and its stop is an fsync: blocking a tokio
        // worker on it would stall every other task sharing that thread.
        match tokio::task::spawn_blocking(move || {
            logger.shutdown_with(SHUTDOWN_QUIET, SHUTDOWN_LIMIT)
        })
        .await
        {
            Ok(report) if report.sink_errors > 0 => crate::direct!(
                "log sink failed {} time(s) during shutdown: {}",
                report.sink_errors,
                report.error.as_deref().unwrap_or("no detail")
            ),
            Ok(_) => {}
            Err(error) => crate::direct!("log writer did not join: {error}"),
        }
    }
}

/// Where the on-disk sink writes, and how.
///
/// A wrapper rather than two more parameters on init, because the storage
/// policy types live behind the log-disk feature and the caller that starts the
/// subsystem should not have to know whether this build has a sink at all.
#[cfg(feature = "log-disk")]
#[derive(Clone, Debug)]
pub struct Disk {
    /// Directory holding one <date>.seg per UTC day.
    pub dir: PathBuf,
    /// Compression, durability and retention for those segments.
    pub options: storage::Options,
}

/// The sink a build without the log-disk feature does not have: see the variant
/// with fields above. It has no public constructor, so None is the only value
/// init can be given in such a build; it exists so that the call has one shape
/// whether or not the feature is there.
#[cfg(not(feature = "log-disk"))]
#[derive(Clone, Debug)]
pub struct Disk(());

/// Starts the subsystem: opens today's segment if there is a Disk, and the
/// library's writer behind it, or reports why it could not.
///
/// disk is the only optional part. Without one the records go nowhere but the
/// text view and the ring: the pipeline itself is unconditional, because the
/// text a human reads is a projection of it and a run without a segment is
/// still a run somebody has to be able to read.
///
/// This is the only fallible step in the module, and it is fallible for exactly
/// one reason: a destination. A directory that cannot be created, a filesystem
/// that cannot carry a segment, another process already writing today's file, a
/// text log that cannot be opened -- all of them are startup errors with an exit
/// code, which is what lets the caller refuse to run rather than run without
/// logs. Everything after this point degrades instead: a write that fails later
/// is a backoff and a warning.
pub fn init(settings: Settings, disk: Option<Disk>) -> Result<Arc<LogHandle>, LogError> {
    let view = View::open(&settings).map_err(|error| {
        LogError::TextSink(format!(
            "{} could not be opened: {error}",
            settings.text_log
        ))
    })?;

    #[cfg(feature = "log-disk")]
    let (sink, durability): (Box<dyn logreel::BatchSink>, logreel::Durability) = match disk {
        Some(disk) => {
            let durability = storage::durability_of(disk.options.durability);
            (
                Box::new(storage::FileSink::open(&disk.dir, disk.options)?),
                durability,
            )
        }
        None => (
            Box::new(logreel::SharedSink::new()),
            logreel::Durability::Eventual,
        ),
    };
    #[cfg(not(feature = "log-disk"))]
    let (sink, durability): (Box<dyn logreel::BatchSink>, logreel::Durability) = {
        // Nothing outside this crate can build the Disk this arm would need,
        // which is the point: without the feature there is no sink to hand over.
        let _ = disk;
        (
            Box::new(logreel::SharedSink::new()),
            logreel::Durability::Eventual,
        )
    };

    let logger = logreel::init_with(
        logreel_settings(&settings, durability),
        None,
        Some(Box::new(view)),
        sink,
    )
    .map_err(|error| LogError::Pipeline(error.to_string()))?;

    let handle = Arc::new(LogHandle {
        inner: Arc::clone(logger.handle()),
        counters: Counters::default(),
        text: settings.text,
        logger: StdMutex::new(Some(logger)),
    });
    dump_on_usr1(Arc::clone(&handle));
    Ok(handle)
}

/// init with a caller-chosen sink: the tests' way in.
///
/// The production entry point picks the sink from the Disk it is given; a test
/// that wants to see the batches has to hand its own, which is the one
/// difference between this and init.
#[cfg(test)]
fn start_with_sink<S: logreel::BatchSink + 'static>(
    sink: S,
    settings: Settings,
) -> Result<LogHandle, LogError> {
    let view = View::open(&settings).map_err(|error| {
        LogError::TextSink(format!(
            "{} could not be opened: {error}",
            settings.text_log
        ))
    })?;
    let logger = logreel::init_with(
        logreel_settings(&settings, logreel::Durability::Eventual),
        None,
        Some(Box::new(view)),
        Box::new(sink),
    )
    .map_err(|error| LogError::Pipeline(error.to_string()))?;
    Ok(LogHandle {
        inner: Arc::clone(logger.handle()),
        counters: Counters::default(),
        text: settings.text,
        logger: StdMutex::new(Some(logger)),
    })
}

/// The proxy's settings as the library's.
///
/// Two tables leave: the producer gate, which is the union of the three
/// consumers, and the sink's, which is the segment's per-category policy. The
/// text view and the ring are not the library's built-ins -- the proxy's View is
/// its observer -- so they contribute only to the gate.
fn logreel_settings(settings: &Settings, durability: logreel::Durability) -> logreel::Settings {
    let mut builder = logreel::Settings::builder()
        .channel_capacity(CHANNEL_CAPACITY)
        .batch_max(settings.batch_max)
        .flush_interval(settings.flush_interval)
        .flush_on_warn(settings.flush_on_warn)
        .durability(durability)
        .domain(domain())
        .on_internal(|error| crate::direct!("log internal error: {}", error.message));

    match settings.gate() {
        Some(level) => builder = builder.min_level(logreel_level(level)),
        None => {
            // No consumer wants anything: one floor, then every category off.
            builder = builder.min_level(logreel::Level::Error);
            for category in 0..CATEGORY_COUNT {
                builder = builder.filter(category as u8, None);
            }
        }
    }

    #[cfg(feature = "log-disk")]
    {
        let floor = settings
            .disk
            .iter()
            .filter_map(|filter| filter.floor())
            .min_by_key(|level| *level as i32)
            .unwrap_or(Level::Error);
        builder = builder.sink_min_level(logreel_level(floor));
        for (category, filter) in settings.disk.iter().enumerate() {
            builder = builder.sink_filter(category as u8, filter.floor().map(logreel_level));
        }
    }
    #[cfg(not(feature = "log-disk"))]
    {
        let floor = settings.gate().unwrap_or(Level::Error);
        builder = builder.sink_min_level(logreel_level(floor));
    }

    builder.build()
}

/// The opaque domain bytes every batch carries: who wrote it and in what shape.
fn domain() -> Box<[u8]> {
    format!(
        "app={};schema={};protocol={}",
        env!("CARGO_PKG_VERSION"),
        schema::SCHEMA_VERSION,
        WRITER_PROTOCOL
    )
    .into_bytes()
    .into_boxed_slice()
}

/// The proxy's level as the library's. They share the four named levels and
/// differ only in the name of zero: unspecified here, trace there.
fn logreel_level(level: Level) -> logreel::Level {
    logreel::Level::from_u8(level as u8).unwrap_or(logreel::Level::Trace)
}

/// Answers SIGUSR1 with the ring's contents.
///
/// A signal handler runs in a context where almost nothing may be done -- not
/// writing to a file, not allocating -- so this is a task waiting on the signal
/// rather than a handler doing the work: it asks, and the writer prints the ring
/// the next time it wakes. Nothing is lost if the signal arrives while the
/// process is stopping; the dump is a diagnostic, not a record.
#[cfg(unix)]
fn dump_on_usr1(handle: Arc<LogHandle>) {
    use tokio::signal::unix::{SignalKind, signal};

    let Ok(mut usr1) = signal(SignalKind::user_defined1()) else {
        return;
    };
    tokio::spawn(async move {
        while usr1.recv().await.is_some() {
            handle.dump_ring();
        }
    });
}

#[cfg(not(unix))]
fn dump_on_usr1(_handle: Arc<LogHandle>) {}

tokio::task_local! {
    /// The session a record belongs to, and the handle to send it through.
    static LOG_CTX: LogCtx;
}

struct LogCtx {
    handle: Arc<LogHandle>,
    conn_id: u64,
}

/// Runs future with the log context planted, so every log_event! inside it --
/// in this task or in any task spawned from it -- is attributed to conn_id.
///
/// This is the one place a connection's logging is set up: the accept arm in
/// server.rs wraps the per-connection task in it, and
/// proxy::handle_client_with_runtime needs no logging parameter because of it.
/// Callers that forget to scope lose the attribution, not correctness.
pub fn scope<F>(conn_id: u64, handle: Arc<LogHandle>, future: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    LOG_CTX.scope(LogCtx { handle, conn_id }, future)
}

/// LogHandle::emit for process-wide events, tolerating a caller that has no
/// handle at all.
///
/// The binary starts the subsystem only when there is somewhere to put it, and
/// the process-wide emitters (the banner record, the accept loop's own errors)
/// run whether or not there is a sink. A record nobody can receive is not built:
/// the payload's Vecs and the Strings behind them cost an allocation each on a
/// path that has no reader.
pub fn emit_global(
    handle: Option<&Arc<LogHandle>>,
    category: Category,
    level: Level,
    event: Event,
) {
    if let Some(handle) = handle {
        handle.emit(0, category, level, event);
    }
}

/// scope for work that belongs to no session: the accept loop's own errors, the
/// descriptor snapshot, pool refills, the --check probes. Their records carry
/// conn_id = 0, which is the documented way to say so.
pub fn scope_global<F>(handle: Arc<LogHandle>, future: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    scope(0, handle, future)
}

/// True when the current task is inside a scope. Used by the process-wide
/// emitters to assert they were set up, since forgetting is otherwise silent.
pub fn inside_scope() -> bool {
    LOG_CTX.try_with(|_| ()).is_ok()
}

/// Emits into the current scope, or does nothing when there is none.
///
/// The no-op is deliberate: a record emitted from a task nobody scoped is a
/// missing log line, and taking the connection down over one would be a
/// strictly worse trade.
pub fn emit(category: Category, level: Level, event: Event) {
    let _ = LOG_CTX.try_with(|ctx| ctx.handle.emit(ctx.conn_id, category, level, event));
}

/// LogHandle::enabled for the current scope. Without a scope nothing is enabled,
/// so a producer outside one does not even build its payload.
pub fn enabled(category: Category, level: Level) -> bool {
    LOG_CTX
        .try_with(|ctx| ctx.handle.enabled(category, level))
        .unwrap_or(false)
}

/// True when the *text view* renders records at level and above.
///
/// The producer gate is the union of three policies; this is one of them, and it
/// is the one that governs the few console lines that are not records: a
/// handshake refused before a session existed. Without a scope, or with the text
/// log off, nothing is written.
pub fn text_keeps(level: Level) -> bool {
    LOG_CTX
        .try_with(|ctx| ctx.handle.text_keeps(level))
        .unwrap_or(false)
}

/// Writes one line that is not a record: stderr, one write, tg-ws-proxy: in
/// front of it.
///
/// The prefix is what tells a reader which lines came from this process rather
/// than from a record's own rendering, and it is the same prefix the Android shim
/// tags logcat with. Never gated by a level: what uses this either has nowhere
/// else to go (a sink that failed) or has already decided (direct_at!).
#[macro_export]
macro_rules! direct {
    ($($arg:tt)*) => {
        eprintln!("tg-ws-proxy: {}", format_args!($($arg)*))
    };
}

/// direct! for a line that belongs to no session but would be a record at level
/// if it did: the refused-handshake diagnostics.
///
/// They follow the text view's floor rather than a policy of their own: at the
/// default info a port scanner leaves nothing behind, and at --text-level debug
/// the operator gets exactly the lines --verbose used to print.
#[macro_export]
macro_rules! direct_at {
    ($level:expr, $($arg:tt)*) => {
        if $crate::log::text_keeps($level) {
            $crate::direct!($($arg)*)
        }
    };
}

/// Logs one structured event, if the current scope's filter keeps it.
///
/// The payload struct is named after its oneof variant, so the macro can take
/// the variant and build the struct: one log_event! line per call site instead of
/// a nested constructor. The level and category come from the artifact's event
/// catalog rather than from the payload, because they belong to the event, not
/// to its data.
///
/// The payload is only built when the record would be kept, which is what makes a
/// DEBUG line that formats a domain or an address free when DEBUG is off.
#[macro_export]
macro_rules! log_event {
    ($category:expr, $level:expr, Event::$variant:ident { $($field:ident $(: $value:expr)?),* $(,)? } $(,)?) => {
        if $crate::log::enabled($category, $level) {
            $crate::log::emit(
                $category,
                $level,
                $crate::log::schema::Event::$variant($crate::log::schema::$variant {
                    $($field $(: $value)?),*
                }),
            );
        }
    };
}

/// Wall clock in unix nanoseconds. The view stamps the overflow record with
/// this; every other record's timestamp comes from the library's writer.
pub(crate) fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0)
}
