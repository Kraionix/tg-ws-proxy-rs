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
//! # How a record travels
//!
//! A producer calls [`log_event!`], which checks the filter and hands the
//! payload to [`emit`](LogHandle::emit). That stamps the wall clock and the
//! process-wide sequence number and pushes onto a bounded channel with
//! `try_send` — never a lock, never an `await`, because this runs on the routing
//! path in the middle of connection setup. The writer task at the far end
//! batches records, writes them through a [`writer::BatchSink`], and hands them
//! to storage; a full channel drops records and counts them, which is a
//! counter and not an error (`INV:errors.drop_not_error`).
//!
//! The session a record belongs to is not a parameter. [`scope`] plants the
//! handle and the connection id in a task-local that the whole connection task
//! inherits — including the bridge futures and the upload tasks spawned from
//! it — so the ~110 call sites carry neither. A producer outside any scope
//! (or outside a connection entirely) emits nothing rather than panicking;
//! process-wide events are emitted inside a scope with `conn_id = 0` instead.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use schema::{Category, Event, Level, LogRecord};

pub mod schema;
pub mod storage;
mod writer;

#[cfg(test)]
mod tests;

/// Number of category slots in a filter table, from the enum itself so that a
/// new category cannot be added without the table growing with it.
pub const CATEGORY_COUNT: usize = Category::Overflow as usize + 1;
const _: () = assert!(CATEGORY_COUNT == 11);

/// Records accepted per flush by [`Settings::batch_max`]'s default.
pub const DEFAULT_BATCH_MAX: usize = 256;
/// Bounds of [`Settings::batch_max`]. The lower bound keeps a batch from being
/// so small that every record becomes its own write; the upper one keeps one
/// flush from holding a whole second of records in a batch header.
pub const MIN_BATCH_MAX: usize = 16;
pub const MAX_BATCH_MAX: usize = 4096;

/// How long a record may sit unwritten before the writer flushes it.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Depth of the producer→writer channel.
///
/// Sized in *records*, which is what actually costs memory here: one
/// `LogRecord` carries its payload inline, so the channel is
/// `CHANNEL_CAPACITY × size_of::<LogRecord>()` bytes of worst-case RAM on a
/// device that may have 64 MB of it. 1024 is two flushes' worth of steady-state
/// traffic (5 ev/s × 2 s) with two orders of magnitude of headroom for the
/// reconnect storm that follows a network change; a longer burst is a burst the
/// log is allowed to lose records from.
pub(crate) const CHANNEL_CAPACITY: usize = 1024;

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
    /// The filesystem cannot carry a segment — see [`storage::check_filesystem`].
    FsUnsupported(String),
    /// Another process is already writing today's segment.
    WriterConflict(PathBuf),
    /// The segment file is not one this build can write.
    Segment(String),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::FsUnsupported(reason) => f.write_str(reason),
            Self::WriterConflict(path) => write!(
                f,
                "another process is writing {}; use a different --log-dir for \
                 multi-instance deployments",
                path.display()
            ),
            Self::Segment(reason) => f.write_str(reason),
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

/// What the subsystem is configured with. Every field has a CLI flag behind it
/// in a later stage; nothing here allocates.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Lowest level recorded, indexed by [`Category`]. Initialised from one
    /// global level and overridden per category — a flat table rather than a
    /// map so the filter on the emit path is an index and a compare.
    pub levels: [Level; CATEGORY_COUNT],
    /// Records per flush, clamped to [`MIN_BATCH_MAX`]..=[`MAX_BATCH_MAX`].
    pub batch_max: usize,
    /// Records older than this are flushed even if the batch is not full.
    pub flush_interval: Duration,
    /// Flush as soon as a record at [`Level::Warn`] or above arrives, instead of
    /// waiting for the interval — a warning that reaches the file two seconds
    /// after the crash that followed it is not much of a warning.
    pub flush_on_warn: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            levels: [Level::Info; CATEGORY_COUNT],
            batch_max: DEFAULT_BATCH_MAX,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            flush_on_warn: false,
        }
    }
}

/// The producer-side handle: one per process, shared as an `Arc`.
///
/// Deliberately not `Clone` — `INV:log.single_writer` says there is one writer
/// per process, and the writer's half of this struct is a `JoinHandle` that
/// cannot be duplicated. Share the `Arc` instead.
pub struct LogHandle {
    tx: mpsc::Sender<LogRecord>,
    counters: Arc<Counters>,
    levels: [Level; CATEGORY_COUNT],
    shutdown: watch::Sender<bool>,
    join: StdMutex<Option<JoinHandle<()>>>,
}

/// Shared with the writer task, which needs the same sequence numbering and
/// reports from the same drop counter the producers add to.
#[derive(Default)]
struct Counters {
    seq: AtomicU32,
    dropped: AtomicU32,
    conn: AtomicU64,
}

impl Counters {
    /// Zero is reserved for "not a session", so numbering starts at one.
    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Relaxed).wrapping_add(1)
    }

    fn next_conn(&self) -> u64 {
        self.conn.fetch_add(1, Relaxed) + 1
    }
}

impl LogHandle {
    /// True when a record of this category and level would be kept.
    ///
    /// A level is a floor, not a ceiling: a threshold of `info` keeps `info`,
    /// `warn` and `error` and drops `debug`, which is what every operator
    /// means by "log level info".
    ///
    /// Callers use this to skip building a payload — the `key_display` strings
    /// and the `format!` behind them — that the filter would drop anyway.
    pub fn enabled(&self, category: Category, level: Level) -> bool {
        level as i32 >= self.levels[category as usize] as i32
    }

    /// Next session id, allocated once per accepted connection. Never zero,
    /// which is what makes `conn_id == 0` readable as "not a session".
    pub fn next_conn_id(&self) -> u64 {
        self.counters.next_conn()
    }

    /// Records that did not fit the channel. Not an error: the alternative
    /// would be blocking a connection on a logging write.
    pub fn dropped(&self) -> u32 {
        self.counters.dropped.load(Relaxed)
    }

    /// Appends one record. Never awaits, never blocks, never allocates.
    ///
    /// Takes the session id rather than reading the task-local so that
    /// process-wide emitters and tests can call it directly; [`emit`] is the
    /// scope-aware wrapper producers normally reach through [`log_event!`].
    pub fn emit(&self, conn_id: u64, category: Category, level: Level, event: Event) {
        if !self.enabled(category, level) {
            return;
        }

        let record = LogRecord {
            ts_ns: now_ns(),
            conn_id,
            seq: self.counters.next_seq(),
            level: level as i32,
            category: category as i32,
            event: Some(event),
        };

        // A full channel and a writer that has already stopped are the same
        // thing from here: the record did not get written, and the count is how
        // the next successful flush says so.
        if self.tx.try_send(record).is_err() {
            self.counters.dropped.fetch_add(1, Relaxed);
        }
    }

    /// Stops the writer, flushing what is already queued, and waits for it.
    ///
    /// Idempotent, and safe to call when a shutdown is already in progress:
    /// the second caller finds no task left to join. On return the file
    /// contains everything this process emitted before the call.
    pub async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        let task = self
            .join
            .lock()
            .expect("log writer join mutex cannot be poisoned by `take`")
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

/// Starts the writer task and returns the producer-side handle.
///
/// The sink is whatever the caller wants the batches written to; nothing in
/// this module can fail yet, so there is no `Result` here — a log directory
/// that cannot be opened is a problem for the storage layer, which is the only
/// thing that can have one.
fn start<S: writer::BatchSink + 'static>(sink: S, settings: Settings) -> LogHandle {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());

    let handle = LogHandle {
        tx,
        counters: Arc::clone(&counters),
        levels: settings.levels,
        shutdown,
        join: StdMutex::new(None),
    };

    let task = tokio::spawn(writer::run(sink, rx, counters, settings, shutdown_rx));
    *handle
        .join
        .lock()
        .expect("log writer join mutex cannot be poisoned by `take`") = Some(task);

    handle
}

/// Starts the subsystem: opens today's segment under `dir` and the writer task
/// behind it, or reports why it could not.
///
/// This is the only fallible step in the module, and it is fallible for exactly
/// one reason: the sink. A directory that cannot be created, a filesystem that
/// cannot carry a segment, another process already writing today's file — all
/// of them are startup errors with an exit code, which is what lets the caller
/// refuse to run rather than run without logs. Everything after this point
/// degrades instead: a write that fails later is a backoff and a warning.
///
/// Must be called from within a Tokio runtime — the writer is a spawned task.
pub fn init(
    dir: &Path,
    settings: Settings,
    options: storage::Options,
) -> Result<Arc<LogHandle>, LogError> {
    let sink = storage::FileSink::open(dir, options)?;
    Ok(Arc::new(start(sink, settings)))
}

tokio::task_local! {
    /// The session a record belongs to, and the handle to send it through.
    static LOG_CTX: LogCtx;
}

struct LogCtx {
    handle: Arc<LogHandle>,
    conn_id: u64,
}

/// Runs `future` with the log context planted, so every [`log_event!`] inside
/// it — in this task or in any task spawned from it — is attributed to
/// `conn_id`.
///
/// This is the one place a connection's logging is set up: the accept arm in
/// `server.rs` wraps the per-connection task in it, and
/// `proxy::handle_client_with_runtime` needs no logging parameter because of
/// it. Callers that forget to scope lose the attribution, not correctness.
pub fn scope<F>(conn_id: u64, handle: Arc<LogHandle>, future: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    LOG_CTX.scope(LogCtx { handle, conn_id }, future)
}

/// [`scope`] for work that belongs to no session — the accept loop's own
/// errors, the descriptor snapshot, pool refills, the `--check` probes. Their
/// records carry `conn_id = 0`, which is the documented way to say so.
pub fn scope_global<F>(handle: Arc<LogHandle>, future: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    scope(0, handle, future)
}

/// True when the current task is inside a [`scope`]. Used by the process-wide
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

/// [`LogHandle::enabled`] for the current scope. Without a scope nothing is
/// enabled, so a producer outside one does not even build its payload.
pub fn enabled(category: Category, level: Level) -> bool {
    LOG_CTX
        .try_with(|ctx| ctx.handle.enabled(category, level))
        .unwrap_or(false)
}

/// Logs one structured event, if the current scope's filter keeps it.
///
/// ```ignore
/// log_event!(Category::Routing, Level::Info, Event::TierFallback {
///     from_tier: Tier::Ws as i32,
///     to_tier: Tier::Cfworker as i32,
///     reason: Reason::WsFail as i32,
/// });
/// ```
///
/// The payload struct is named after its oneof variant, so the macro can take
/// the variant and build the struct — one `log_event!` line per call site
/// instead of a nested constructor. The level and category come from the
/// artifact's event catalog rather than from the payload, because they belong
/// to the event, not to its data.
///
/// The payload is only built when the record would be kept, which is what makes
/// a `DEBUG` line that formats a domain or an address free when `DEBUG` is off.
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

/// Wall clock in unix nanoseconds, which is what `LogRecord.ts_ns` carries.
/// A clock before 1970 is not a case worth a branch on the emit path.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0)
}
