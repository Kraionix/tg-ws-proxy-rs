//! The log wire format: `LogRecord`, the `LogBatch` it travels in, and the
//! bit-packing helpers both sides of the file need.
//!
//! Field numbers, oneof tags and event semantics are fixed by the `.proto` in
//! `artifacts/logging/10_SCHEMA.md`, which is the source of record. What is
//! written here is the hand-written equivalent of what `prost-build` would emit
//! for it — same message and variant names, so a generated file would be a
//! drop-in — with two additions that the artifact's event catalog needs in
//! order to stay lossless:
//!
//! * [`ErrorCode`]: an `err` field on the four events that can fail, plus an
//!   `err_code` on the three where a numeric status is the answer. The event
//!   variants record what was attempted, not why it failed, and
//!   `ws_client::WsConnectResult` already classifies the why as a Rust enum;
//!   recording it as text would undo the point of a typed log.
//! * [`dc_bit`] returning an `Option`: the artifact's `dc - 1` underflows for
//!   `dc = 0`, which is exactly what a non-session event carries.
//!
//! Time is `fixed64` unix nanoseconds rather than a varint: a nanosecond clock
//! needs all 64 bits, so a varint would cost ten bytes every record. Durations
//! are `uint32` nanoseconds, which caps a single measured span at ~4.29 s —
//! every span recorded here is a connect or a handshake.

/// Written into a day-segment's `STOR:meta` so a reader can tell which rules a
/// file was written under. Bumped only for a non-additive change.
///
/// `2` is the version that moved the session's own facts — DC, media flag, the
/// rung that carried it — into a [`Ctx`] on every event that has them, so that
/// one record renders to a text line without the records before it. It also
/// adds the fields the console line printed and the record did not: the host a
/// rung was dialled at, the domain a session ran through, the raw `errno`
/// behind a classified error, and the two pool counters.
pub const SCHEMA_VERSION: u32 = 2;

/// Upper bound on distinct `conn_id`s in one [`LogBatch`], so that
/// `STOR:by_conn`'s key prefix stays selective: a batch spanning more sessions
/// than this is split even though it would encode fine.
pub const BATCH_MAX_UNIQUE_CONNS: usize = 16;

// ── Envelope ───────────────────────────────────────────────────────────────

/// One logged event: a fixed envelope plus exactly one payload.
///
/// The envelope fields are plain proto3 scalars, so a zero value is not written
/// at all — which is why `conn_id = 0` is a free way to say "not a session"
/// rather than an `optional` field every producer has to set.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogRecord {
    /// Wall clock, unix ns. Record ordering inside a batch is by `seq`, not by
    /// this: two producers can stamp timestamps out of order.
    #[prost(fixed64, tag = "1")]
    pub ts_ns: u64,
    /// Client session this event belongs to, or `0` when it is not
    /// session-scoped (pool background work, process-wide events).
    #[prost(uint64, tag = "2")]
    pub conn_id: u64,
    /// Per-process monotonic, assigned at emit time.
    #[prost(uint32, tag = "3")]
    pub seq: u32,
    #[prost(enumeration = "Level", tag = "4")]
    pub level: i32,
    #[prost(enumeration = "Category", tag = "5")]
    pub category: i32,
    #[prost(
        oneof = "Event",
        tags = "16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37"
    )]
    pub event: Option<Event>,
}

/// One payload per `EVT:*` in the artifact's event catalog.
///
/// Tags start at 16 rather than 1 so the envelope can grow to fifteen more
/// fields without colliding with an event number that is already on disk.
#[derive(Clone, PartialEq, ::prost::Oneof)]
pub enum Event {
    #[prost(message, tag = "16")]
    SessionOpened(SessionOpened),
    #[prost(message, tag = "17")]
    SessionClosed(SessionClosed),
    #[prost(message, tag = "18")]
    TierAttempt(TierAttempt),
    #[prost(message, tag = "19")]
    TierFallback(TierFallback),
    #[prost(message, tag = "20")]
    CooldownArmed(CooldownArmed),
    #[prost(message, tag = "21")]
    CooldownCleared(CooldownCleared),
    #[prost(message, tag = "22")]
    CooldownSkipped(CooldownSkipped),
    #[prost(message, tag = "23")]
    PoolHit(PoolHit),
    #[prost(message, tag = "24")]
    PoolMiss(PoolMiss),
    #[prost(message, tag = "25")]
    PoolRefill(PoolRefill),
    #[prost(message, tag = "26")]
    TlsHandshake(TlsHandshake),
    #[prost(message, tag = "27")]
    RelayInitRetries(RelayInitRetries),
    #[prost(message, tag = "28")]
    AcceptError(AcceptError),
    #[prost(message, tag = "29")]
    FdSnapshot(FdSnapshot),
    #[prost(message, tag = "30")]
    ProbeResult(ProbeResult),
    #[prost(message, tag = "31")]
    LogOverflow(LogOverflow),
    #[prost(message, tag = "32")]
    StartupSummary(StartupSummary),
    #[prost(message, tag = "33")]
    PoolDiscard(PoolDiscard),
    #[prost(message, tag = "34")]
    WarmupComplete(WarmupComplete),
    #[prost(message, tag = "35")]
    AttemptSkipped(AttemptSkipped),
    #[prost(message, tag = "36")]
    DomainListFetched(DomainListFetched),
    #[prost(message, tag = "37")]
    Shutdown(Shutdown),
}

/// What a writer hands to storage: the batch's summary plus its records.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogBatch {
    #[prost(message, optional, tag = "1")]
    pub header: Option<BatchHeader>,
    #[prost(message, repeated, tag = "2")]
    pub records: Vec<LogRecord>,
}

/// The summary computed by [`build_batch`].
///
/// Everything here is derivable from the records; it exists so that a reader
/// can filter a day of segments — by DC, by category, by connection — without
/// decoding every record in them.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BatchHeader {
    #[prost(fixed64, tag = "1")]
    pub ts_first_ns: u64,
    #[prost(fixed64, tag = "2")]
    pub ts_last_ns: u64,
    #[prost(uint32, tag = "3")]
    pub record_count: u32,
    /// One bit per oneof field number, offset by 16: `EVT:session_opened` (16)
    /// is bit 0, `EVT:shutdown` (37) is bit 21.
    #[prost(uint64, tag = "4")]
    pub kind_mask: u64,
    /// One bit per DC, laid out by [`dc_bit`] — never `1 << dc`, which
    /// overflows at 203.
    #[prost(uint32, tag = "5")]
    pub dc_mask: u32,
    /// Same layout as `dc_mask`, set only for media sessions.
    #[prost(uint32, tag = "6")]
    pub dc_media_mask: u32,
    /// Ascending, deduplicated, at most [`BATCH_MAX_UNIQUE_CONNS`] entries.
    #[prost(uint64, repeated, tag = "7")]
    pub conn_ids: Vec<u64>,
}

// ── Enums ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Level {
    Unspecified = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl Level {
    /// Lower-case name, the way `--log-level` and the docs spell it.
    ///
    /// The `Enumeration` derive generates no `as_str_name`, and a startup
    /// record that says `2` where the operator reads `info` in the banner is
    /// worse than a match that the compiler keeps exhaustive.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Category {
    Unspecified = 0,
    Session = 1,
    Routing = 2,
    Pool = 3,
    Cooldown = 4,
    Tls = 5,
    Crypto = 6,
    Accept = 7,
    Check = 8,
    Config = 9,
    Overflow = 10,
}

impl Category {
    /// Every category an event can carry, in enum order.
    ///
    /// `Unspecified` is the schema's zero value, not a category: nothing emits
    /// it, so a list that offered it would advertise a filter nothing matches.
    pub const ALL: [Self; 10] = [
        Self::Session,
        Self::Routing,
        Self::Pool,
        Self::Cooldown,
        Self::Tls,
        Self::Crypto,
        Self::Accept,
        Self::Check,
        Self::Config,
        Self::Overflow,
    ];

    /// Lower-case name, as `--log-category` spells it and the startup record
    /// prints it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Session => "session",
            Self::Routing => "routing",
            Self::Pool => "pool",
            Self::Cooldown => "cooldown",
            Self::Tls => "tls",
            Self::Crypto => "crypto",
            Self::Accept => "accept",
            Self::Check => "check",
            Self::Config => "config",
            Self::Overflow => "overflow",
        }
    }

    /// The inverse of [`Self::name`], for the one caller that reads a category
    /// out of a command line.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.name() == name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Tier {
    Unspecified = 0,
    Ws = 1,
    Cfworker = 2,
    Cfproxy = 3,
    Mtproto = 4,
    Tcp = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ClosedBy {
    Unspecified = 0,
    Client = 1,
    Upstream = 2,
    /// The proxy gave up before it bridged anything: every rung of the ladder
    /// failed or was skipped, so there was never an upstream to close it. The
    /// bytes are zero and the duration is the time spent trying, which is what
    /// makes a session that opened and never closed readable as a failure
    /// rather than as a crash.
    NoRoute = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum HandshakeKind {
    Unspecified = 0,
    Full = 1,
    Resumed = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CooldownKind {
    Unspecified = 0,
    WsFail = 1,
    IpFail = 2,
    UpstreamFail = 3,
    CfWorkerFail = 4,
    CfEdgeTlsFail = 5,
    CfEdgePlaintext = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ProbeKind {
    Unspecified = 0,
    CfDomain = 1,
    CfWorker = 2,
    MtprotoProxy = 3,
    Listener = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Reason {
    Unspecified = 0,
    WsFail = 1,
    IpCooldown = 2,
    CfWorkerFail = 3,
    CfProxyFail = 4,
    UpstreamFail = 5,
    NotInDcIp = 6,
    Pinned = 7,
    NoFallback = 8,
}

impl Reason {
    /// The name the routing code prints in its `tracing` lines.
    ///
    /// These are the strings that were threaded down the ladder as free text
    /// before the record existed, verbatim — the console output is part of the
    /// shipped interface, so moving the vocabulary onto the wire must not move
    /// a byte of it. The three that have no console line are named for the
    /// record's sake and read like the others.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::WsFail => "WS failed",
            Self::IpCooldown => "IP in cooldown",
            Self::CfWorkerFail => "CF Worker failed",
            Self::CfProxyFail => "CF proxy failed",
            Self::UpstreamFail => "upstream failed",
            Self::NotInDcIp => "not in --dc-ip config",
            Self::Pinned => "pinned",
            Self::NoFallback => "no fallback",
        }
    }
}

/// Why an attempt failed, at the granularity of the code that handles it.
///
/// Deliberately not one value per `std::io::Error` variant: these are the
/// classes with distinct recovery paths — a `TcpConnectTimeout` is a
/// DPI-blocked address and arms a cooldown, a `TlsTimeout` is a stalled
/// handshake after the server answered and triggers fronting, a `Resource`
/// failure means the process is out of file descriptors and the connection
/// should not be retried at all.
///
/// A reader must survive a discriminant it does not know: `prost` decodes an
/// unrecognised enum value as the raw integer, so codes added by a later binary
/// are readable as numbers by this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ErrorCode {
    Unspecified = 0,
    /// Name resolution failed.
    Dns = 1,
    /// Connect refused or unreachable.
    TcpConnect = 2,
    /// Connect timed out — the DPI-blocked-address signature.
    TcpConnectTimeout = 3,
    /// TLS handshake failed.
    Tls = 4,
    /// The server answered but then stalled; a fronting trigger.
    TlsTimeout = 5,
    /// Non-101 status; the status itself is in `err_code`.
    HttpStatus = 6,
    /// Telegram redirected, i.e. WS is unavailable here.
    HttpRedirect = 7,
    /// 101 was expected and something else arrived.
    Upgrade = 8,
    /// MTProto or FakeTLS framing violation.
    Protocol = 9,
    /// The stream ended mid-handshake, or would not take the write.
    Read = 10,
    /// `EMFILE`, `ENFILE`, or no connection permit available.
    Resource = 11,
    /// Sink-side I/O (`ENOSPC` and friends).
    LocalIo = 12,
    /// The `--log-dir` filesystem is one that cannot carry a redb segment.
    FsUnsupported = 13,
    /// Another process holds the current day's segment.
    WriterConflict = 14,
}

/// Why an idle pooled connection was thrown away.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DiscardReason {
    Unspecified = 0,
    /// Older than the pool's maximum age.
    Stale = 1,
    /// The server had already closed it, or sent something on an idle
    /// connection — the liveness check that costs nothing to run.
    Closed = 2,
}

/// Where the Cloudflare domain list in use came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DomainSource {
    Unspecified = 0,
    /// The community list, fetched over HTTPS.
    Github = 1,
    /// The list compiled into the binary, used when the fetch produced
    /// nothing.
    Builtin = 2,
}

/// Which part of a stop a `shutdown` record describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ShutdownPhase {
    Unspecified = 0,
    /// A signal arrived; the proxy is about to stop serving.
    Requested = 1,
    /// The accept loop is gone and the sink has been flushed.
    Complete = 2,
    /// A second signal cut the stop short.
    Forced = 3,
}

/// The signal behind a [`ShutdownPhase::Requested`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ShutdownSignal {
    Unspecified = 0,
    Term = 1,
    Int = 2,
}

// ── Event payloads ─────────────────────────────────────────────────────────

/// `EVT:session_opened` — one per inbound client handshake.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionOpened {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    /// The only event that carries the peer: every later one is about the route
    /// rather than the caller, and a reader that wants the prefix back replays
    /// the stream from the session's own open record.
    #[prost(message, optional, tag = "2")]
    pub peer: Option<Peer>,
}

/// `EVT:session_closed` — one per bridge session end, whatever ended it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionClosed {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    #[prost(enumeration = "ClosedBy", tag = "2")]
    pub closed_by: i32,
    #[prost(uint64, tag = "3")]
    pub bytes_up: u64,
    #[prost(uint64, tag = "4")]
    pub bytes_down: u64,
    #[prost(uint32, tag = "5")]
    pub dur_ms: u32,
    /// The domain or worker the session actually ran through, empty when the
    /// rung has none: `kws2.web.telegram.org`, the CF fronting domain, the
    /// worker URL's host. The console line printed it and the record could not,
    /// which left a saved segment unable to say which way a session went.
    #[prost(string, tag = "6")]
    pub via: String,
}

/// `EVT:tier_attempt` — one per rung that actually opens a connection.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TierAttempt {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    /// The host the rung dialled — `kws2.web.telegram.org`, a CF domain, a
    /// worker host, `host:port` for the MTProto proxy and TCP rungs. Empty for
    /// a rung that dialled an address it does not name.
    #[prost(string, tag = "2")]
    pub host: String,
    #[prost(bool, tag = "3")]
    pub ok: bool,
    /// Nanoseconds, as a `u64` because a rung's dial is bounded by
    /// `--ws-connect-timeout` / `--cf-connect-timeout` — ten seconds by
    /// default, and a `u32` of nanoseconds saturates at 4.29.
    #[prost(uint64, tag = "4")]
    pub dur_ns: u64,
    /// [`ErrorCode`] discriminant; meaningful when `ok` is false, and not
    /// written at all when it is zero.
    #[prost(enumeration = "ErrorCode", tag = "5")]
    pub err: i32,
    /// Numeric detail behind `err`, currently the HTTP status for
    /// `ErrorCode::HttpStatus` and `ErrorCode::HttpRedirect`.
    #[prost(uint32, tag = "6")]
    pub err_code: u32,
    /// The OS error behind `err`, when there was one. `err` classifies the
    /// failure for recovery; this is the diagnosis — `ENETUNREACH` and
    /// `ECONNREFUSED` are the same `TcpConnect` and a different problem.
    #[prost(int32, tag = "7")]
    pub errno: i32,
}

/// `EVT:tier_fallback` — the ladder stepping down from one rung to the next.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TierFallback {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    #[prost(enumeration = "Tier", tag = "2")]
    pub from_tier: i32,
    #[prost(enumeration = "Tier", tag = "3")]
    pub to_tier: i32,
    #[prost(enumeration = "Reason", tag = "4")]
    pub reason: i32,
}

/// `EVT:cooldown_armed` — failure memory being set.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CooldownArmed {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    #[prost(enumeration = "CooldownKind", tag = "2")]
    pub kind: i32,
    /// The map key as the operator would recognise it: a DC, an IP, a domain, a
    /// worker URL. Never a secret.
    #[prost(string, tag = "3")]
    pub key_display: String,
    #[prost(uint32, tag = "4")]
    pub dur_s: u32,
    /// Why the cooldown was armed — without it the log records the penalty and
    /// not the offence.
    #[prost(enumeration = "ErrorCode", tag = "5")]
    pub err: i32,
    #[prost(uint32, tag = "6")]
    pub err_code: u32,
}

/// `EVT:cooldown_cleared` — a success that cleared a cooldown entry.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CooldownCleared {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    #[prost(enumeration = "CooldownKind", tag = "2")]
    pub kind: i32,
    #[prost(string, tag = "3")]
    pub key_display: String,
}

/// `EVT:cooldown_skipped` — a rung that was not tried because of a cooldown.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CooldownSkipped {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    #[prost(enumeration = "CooldownKind", tag = "2")]
    pub kind: i32,
    #[prost(string, tag = "3")]
    pub key_display: String,
}

/// `EVT:pool_hit` — a pre-warmed connection was reused.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolHit {
    /// [`Ctx::tier`] names the bucket: the plain WebSocket pool and the
    /// Cloudflare ones are keyed separately, so without it the record cannot
    /// say which path the pre-warmed connection was for.
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    /// Connections left in the bucket after this one was taken, which is what
    /// says whether the pool is keeping up.
    #[prost(uint32, tag = "2")]
    pub left: u32,
}

/// `EVT:pool_miss` — no idle connection in the bucket.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolMiss {
    /// See [`PoolHit::ctx`].
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
}

/// `EVT:pool_refill` — background refill finished, with what it produced.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolRefill {
    /// See [`PoolHit::ctx`].
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    /// Connections this refill added.
    #[prost(uint32, tag = "2")]
    pub added: u32,
    /// Connections the bucket holds once it is done — `added` says what the
    /// dial produced, `ready` what the pool is worth now.
    #[prost(uint32, tag = "3")]
    pub ready: u32,
    #[prost(uint32, tag = "4")]
    pub dur_ms: u32,
    /// Why the dial stopped short, when it did — a refill that added nothing is
    /// told apart by this from one the pool no longer had room for.
    #[prost(enumeration = "ErrorCode", tag = "5")]
    pub err: i32,
    /// The OS error behind `err`; see [`TierAttempt::errno`].
    #[prost(int32, tag = "6")]
    pub errno: i32,
}

/// `EVT:tls_handshake` — the TLS cost of one upstream WebSocket connect.
///
/// A failing handshake carries the classification and the OS error rather than
/// an `ok` flag: zero `err` is the success this event exists to time, and a
/// failure is a `tls_handshake` record that says why.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TlsHandshake {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    #[prost(enumeration = "HandshakeKind", tag = "2")]
    pub kind: i32,
    /// Nanoseconds; `u64` for the same reason as [`TierAttempt::dur_ns`].
    #[prost(uint64, tag = "3")]
    pub dur_ns: u64,
    #[prost(enumeration = "ErrorCode", tag = "4")]
    pub err: i32,
    /// See [`TierAttempt::errno`].
    #[prost(int32, tag = "5")]
    pub errno: i32,
}

/// `EVT:relay_init_retries` — reserved-prefix rejections while generating the
/// init frame. A high count means the RNG is being asked for a prefix the
/// obfuscation format cannot carry, not that the network is failing.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelayInitRetries {
    #[prost(uint32, tag = "1")]
    pub n: u32,
}

/// `EVT:accept_error` — the listener failed to accept a connection.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AcceptError {
    /// Raw syscall errno, kept because the accept loop branches on it.
    #[prost(int32, tag = "1")]
    pub errno: i32,
    #[prost(uint32, tag = "2")]
    pub backoff_ms: u32,
    /// [`ErrorCode`] discriminant; distinguishes running out of descriptors
    /// from an ordinary accept failure.
    #[prost(enumeration = "ErrorCode", tag = "3")]
    pub err: i32,
}

/// `EVT:fd_snapshot` — periodic view of the descriptor budget.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FdSnapshot {
    #[prost(uint32, tag = "1")]
    pub open: u32,
    #[prost(uint32, tag = "2")]
    pub soft_limit: u32,
    #[prost(uint32, tag = "3")]
    pub sem_avail: u32,
}

/// `EVT:probe_result` — one `--check` probe.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProbeResult {
    #[prost(enumeration = "ProbeKind", tag = "1")]
    pub kind: i32,
    #[prost(string, tag = "2")]
    pub target: String,
    #[prost(bool, tag = "3")]
    pub ok: bool,
    /// Nanoseconds; `u64` — a probe that runs out its connect timeout is ten
    /// seconds, which a `u32` of nanoseconds cannot hold.
    #[prost(uint64, tag = "4")]
    pub dur_ns: u64,
    #[prost(enumeration = "ErrorCode", tag = "5")]
    pub err: i32,
    #[prost(uint32, tag = "6")]
    pub err_code: u32,
}

/// `EVT:log_overflow` — the writer's own diagnostic after dropping records.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogOverflow {
    #[prost(uint32, tag = "1")]
    pub dropped: u32,
    #[prost(uint64, tag = "2")]
    pub window_ns: u64,
}

/// `EVT:startup_summary` — the banner as one record, so a segment says which
/// configuration produced it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StartupSummary {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub listen: String,
    #[prost(message, repeated, tag = "3")]
    pub dc_ips: Vec<DcIp>,
    #[prost(string, repeated, tag = "4")]
    pub tiers: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub categories: Vec<String>,
}

/// `EVT:pool_discard` — an idle connection thrown away instead of handed to a
/// client.
///
/// One record per connection, unlike the console line it replaces: the line
/// said the pool was shedding, this says how much of it and why.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolDiscard {
    /// See [`PoolHit::ctx`].
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    #[prost(enumeration = "DiscardReason", tag = "2")]
    pub reason: i32,
}

/// `EVT:warmup_complete` — the startup warm-up finished.
///
/// Process-wide rather than per bucket: the per-bucket half is the
/// `pool_refill` each bucket already reports, and what this adds is the one
/// question the console answered — "is the pool up?".
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WarmupComplete {
    /// Connections the pool holds across every bucket.
    #[prost(uint32, tag = "1")]
    pub ready: u32,
    #[prost(uint32, tag = "2")]
    pub dur_ms: u32,
}

/// `EVT:attempt_skipped` — a rung that the ladder did not dial at all.
///
/// Distinct from `tier_attempt`: nothing was tried, so there is no duration and
/// no error, only the reason the rung was passed over. Today's console prints
/// these as ladder notes and a segment cannot reconstruct the walk without
/// them.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttemptSkipped {
    #[prost(message, optional, tag = "1")]
    pub ctx: Option<Ctx>,
    /// The rung that was passed over.
    #[prost(enumeration = "Tier", tag = "2")]
    pub tier: i32,
    #[prost(enumeration = "Reason", tag = "3")]
    pub reason: i32,
}

/// `EVT:domain_list_fetched` — where the default Cloudflare domain list came
/// from.
///
/// The list decides which routes exist for the whole process, and the console
/// said so once at startup; a segment that starts after the banner could not.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DomainListFetched {
    #[prost(enumeration = "DomainSource", tag = "1")]
    pub source: i32,
    /// Domains in the list that is now in use.
    #[prost(uint32, tag = "2")]
    pub count: u32,
    /// Why the fetch failed, when it did — the record that says the built-in
    /// list is in use because GitHub was unreachable rather than because the
    /// operator asked for it.
    #[prost(enumeration = "ErrorCode", tag = "3")]
    pub err: i32,
    #[prost(uint32, tag = "4")]
    pub err_code: u32,
}

/// `EVT:shutdown` — the process being asked to stop, and stopping.
///
/// Written through the sink it is describing, which is why it exists: the last
/// record in a segment says whether the run ended cleanly or the power did.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Shutdown {
    #[prost(enumeration = "ShutdownPhase", tag = "1")]
    pub phase: i32,
    /// The signal that asked for the stop; unset for the phases that are not
    /// caused by one.
    #[prost(enumeration = "ShutdownSignal", tag = "2")]
    pub signal: i32,
}

// ── Shared value types ─────────────────────────────────────────────────────

/// The session facts every session-scoped event carries.
///
/// The point is that a record is readable on its own: without this, `DC2 media
/// session closed` needs the `session_opened` before it to say which DC and
/// whether it was media, and a reader handed one batch — or a session whose
/// open record predates the file — has neither. `peer` deliberately stays out:
/// it is the client's address, one per session, and only [`SessionOpened`]
/// carries it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ctx {
    #[prost(uint32, tag = "1")]
    pub dc: u32,
    #[prost(bool, tag = "2")]
    pub is_media: bool,
    /// The rung this event belongs to, where one applies. Unset for events that
    /// belong to the session rather than to a route through it.
    #[prost(enumeration = "Tier", tag = "3")]
    pub tier: i32,
}

impl Ctx {
    /// The context of one event, in the order the fields are declared.
    pub fn new(dc: u32, is_media: bool, tier: Tier) -> Self {
        Self {
            dc,
            is_media,
            tier: tier as i32,
        }
    }
}

/// A client address, in one of the three encodings `70_SECURITY.md` defines.
///
/// `hashed` and `encrypted` record which encoding was active when the record
/// was written, because the bytes alone do not say: a redaction policy change
/// must not make an old segment readable as if it held raw addresses.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Peer {
    #[prost(bytes = "vec", tag = "1")]
    pub addr: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub port: u32,
    #[prost(bool, tag = "3")]
    pub hashed: bool,
    #[prost(bool, tag = "4")]
    pub encrypted: bool,
}

/// A DC and the address it was dialled at.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DcIp {
    #[prost(uint32, tag = "1")]
    pub dc: u32,
    #[prost(string, tag = "2")]
    pub ip: String,
}

// ── Derivation ─────────────────────────────────────────────────────────────

/// Bit index of `dc` in [`BatchHeader::dc_mask`], or `None` when the record
/// names no routable DC.
///
/// The mask is this fixed six-bit layout rather than `1 << dc` because DC 203
/// shifts past the end of a `u32`; `0` has no bit because it is what an
/// unscoped or not-yet-routed record carries.
pub fn dc_bit(dc: u32) -> Option<u8> {
    match dc {
        1..=5 => Some((dc - 1) as u8),
        203 => Some(5),
        _ => None,
    }
}

/// A 64-bit fingerprint of the wire format, written into every segment's
/// `STOR:meta.schema_hash`.
///
/// A reader compares it against its own to tell "this file predates a field" or
/// "this file predates a renumbering" apart from "this file is damaged". It is
/// computed by encoding one synthetic record per event variant with every field
/// set, plus each enum's discriminants, and hashing the lot — so any change to
/// a field number, a oneof tag or an enum value moves it without anyone having
/// to remember to update a version number.
///
/// It is a tripwire, not a proof: a field added to a message whose synthetic
/// record below is not updated, or an enum value added to an enum without being
/// added to [`enum_values`], moves nothing. Both are visible in the diff that
/// adds them, which is the property that was actually wanted.
///
/// One class of change is invisible to it, and it is the class the wire format
/// does not distinguish either: protobuf's varint carries no width, so widening
/// a field between integer sizes that encode the same way (`u32` → `u64`, say)
/// leaves every byte below identical. That is safe for the *readers* the
/// fingerprint exists to protect — an old reader truncates, it does not
/// misparse — so it is recorded here rather than defended against.
///
/// The design set specifies `SHA-256(FileDescriptorSet)` here, with the
/// descriptor itself deferred until a reader needs it. Hashing the records
/// instead covers the same ground without shipping a descriptor — and a hash
/// that does not change when the descriptor is back-filled later is the one a
/// reader can keep comparing against.
pub fn fingerprint() -> u64 {
    use prost::Message as _;
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.to_le_bytes());
    hasher.update((BATCH_MAX_UNIQUE_CONNS as u32).to_le_bytes());
    for values in enum_values() {
        for value in values {
            hasher.update(value.to_le_bytes());
        }
    }
    for record in canonical_records() {
        hasher.update(record.encode_to_vec());
    }

    let digest = hasher.finalize();
    let mut first_eight = [0u8; 8];
    first_eight.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(first_eight)
}

/// Every enum's discriminants, in declaration order.
fn enum_values() -> [&'static [i32]; 13] {
    [
        &[
            Level::Unspecified as i32,
            Level::Debug as i32,
            Level::Info as i32,
            Level::Warn as i32,
            Level::Error as i32,
        ],
        &[
            Category::Unspecified as i32,
            Category::Session as i32,
            Category::Routing as i32,
            Category::Pool as i32,
            Category::Cooldown as i32,
            Category::Tls as i32,
            Category::Crypto as i32,
            Category::Accept as i32,
            Category::Check as i32,
            Category::Config as i32,
            Category::Overflow as i32,
        ],
        &[
            Tier::Unspecified as i32,
            Tier::Ws as i32,
            Tier::Cfworker as i32,
            Tier::Cfproxy as i32,
            Tier::Mtproto as i32,
            Tier::Tcp as i32,
        ],
        &[
            ClosedBy::Unspecified as i32,
            ClosedBy::Client as i32,
            ClosedBy::Upstream as i32,
            ClosedBy::NoRoute as i32,
        ],
        &[
            HandshakeKind::Unspecified as i32,
            HandshakeKind::Full as i32,
            HandshakeKind::Resumed as i32,
        ],
        &[
            CooldownKind::Unspecified as i32,
            CooldownKind::WsFail as i32,
            CooldownKind::IpFail as i32,
            CooldownKind::UpstreamFail as i32,
            CooldownKind::CfWorkerFail as i32,
            CooldownKind::CfEdgeTlsFail as i32,
            CooldownKind::CfEdgePlaintext as i32,
        ],
        &[
            ProbeKind::Unspecified as i32,
            ProbeKind::CfDomain as i32,
            ProbeKind::CfWorker as i32,
            ProbeKind::MtprotoProxy as i32,
            ProbeKind::Listener as i32,
        ],
        &[
            Reason::Unspecified as i32,
            Reason::WsFail as i32,
            Reason::IpCooldown as i32,
            Reason::CfWorkerFail as i32,
            Reason::CfProxyFail as i32,
            Reason::UpstreamFail as i32,
            Reason::NotInDcIp as i32,
            Reason::Pinned as i32,
            Reason::NoFallback as i32,
        ],
        &[
            ErrorCode::Unspecified as i32,
            ErrorCode::Dns as i32,
            ErrorCode::TcpConnect as i32,
            ErrorCode::TcpConnectTimeout as i32,
            ErrorCode::Tls as i32,
            ErrorCode::TlsTimeout as i32,
            ErrorCode::HttpStatus as i32,
            ErrorCode::HttpRedirect as i32,
            ErrorCode::Upgrade as i32,
            ErrorCode::Protocol as i32,
            ErrorCode::Read as i32,
            ErrorCode::Resource as i32,
            ErrorCode::LocalIo as i32,
            ErrorCode::FsUnsupported as i32,
            ErrorCode::WriterConflict as i32,
        ],
        &[
            DiscardReason::Unspecified as i32,
            DiscardReason::Stale as i32,
            DiscardReason::Closed as i32,
        ],
        &[
            DomainSource::Unspecified as i32,
            DomainSource::Github as i32,
            DomainSource::Builtin as i32,
        ],
        &[
            ShutdownPhase::Unspecified as i32,
            ShutdownPhase::Requested as i32,
            ShutdownPhase::Complete as i32,
            ShutdownPhase::Forced as i32,
        ],
        &[
            ShutdownSignal::Unspecified as i32,
            ShutdownSignal::Term as i32,
            ShutdownSignal::Int as i32,
        ],
    ]
}

/// One record per event variant with every field set, so that the encoding
/// depends on every field number and type the format declares. Synthetic
/// values, never written to a segment — including a `Peer` with both `hashed`
/// and `encrypted` set, which a real record may not be.
///
/// The text view renders this same corpus in `render::tests`, which is how a
/// variant that gains no line is caught twice: once by the exhaustive match and
/// once by a test that would otherwise be looking at an empty line.
pub(crate) fn canonical_records() -> [LogRecord; 22] {
    let record = |event: Event| LogRecord {
        ts_ns: 1,
        conn_id: 1,
        seq: 1,
        level: Level::Debug as i32,
        category: Category::Session as i32,
        event: Some(event),
    };

    [
        record(Event::SessionOpened(SessionOpened {
            ctx: Some(Ctx::new(1, true, Tier::Ws)),
            peer: Some(Peer {
                addr: vec![1],
                port: 1,
                hashed: true,
                encrypted: true,
            }),
        })),
        record(Event::SessionClosed(SessionClosed {
            ctx: Some(Ctx::new(1, true, Tier::Cfproxy)),
            closed_by: ClosedBy::Client as i32,
            bytes_up: 1,
            bytes_down: 1,
            dur_ms: 1,
            via: "v".to_string(),
        })),
        record(Event::TierAttempt(TierAttempt {
            ctx: Some(Ctx::new(1, true, Tier::Ws)),
            host: "h".to_string(),
            ok: true,
            dur_ns: 1,
            err: ErrorCode::Dns as i32,
            err_code: 1,
            errno: -1,
        })),
        record(Event::TierFallback(TierFallback {
            ctx: Some(Ctx::new(1, true, Tier::Ws)),
            from_tier: Tier::Ws as i32,
            to_tier: Tier::Tcp as i32,
            reason: Reason::WsFail as i32,
        })),
        record(Event::CooldownArmed(CooldownArmed {
            ctx: Some(Ctx::new(1, true, Tier::Cfworker)),
            kind: CooldownKind::WsFail as i32,
            key_display: "k".to_string(),
            dur_s: 1,
            err: ErrorCode::Dns as i32,
            err_code: 1,
        })),
        record(Event::CooldownCleared(CooldownCleared {
            ctx: Some(Ctx::new(1, true, Tier::Cfworker)),
            kind: CooldownKind::IpFail as i32,
            key_display: "k".to_string(),
        })),
        record(Event::CooldownSkipped(CooldownSkipped {
            ctx: Some(Ctx::new(1, true, Tier::Cfworker)),
            kind: CooldownKind::UpstreamFail as i32,
            key_display: "k".to_string(),
        })),
        record(Event::PoolHit(PoolHit {
            ctx: Some(Ctx::new(1, true, Tier::Ws)),
            left: 1,
        })),
        record(Event::PoolMiss(PoolMiss {
            ctx: Some(Ctx::new(1, true, Tier::Ws)),
        })),
        record(Event::PoolRefill(PoolRefill {
            ctx: Some(Ctx::new(1, true, Tier::Ws)),
            added: 1,
            ready: 1,
            dur_ms: 1,
            err: ErrorCode::TlsTimeout as i32,
            errno: 1,
        })),
        record(Event::TlsHandshake(TlsHandshake {
            ctx: Some(Ctx::new(1, true, Tier::Ws)),
            kind: HandshakeKind::Full as i32,
            dur_ns: 1,
            err: ErrorCode::Tls as i32,
            errno: -1,
        })),
        record(Event::RelayInitRetries(RelayInitRetries { n: 1 })),
        record(Event::AcceptError(AcceptError {
            errno: 1,
            backoff_ms: 1,
            err: ErrorCode::Resource as i32,
        })),
        record(Event::FdSnapshot(FdSnapshot {
            open: 1,
            soft_limit: 1,
            sem_avail: 1,
        })),
        record(Event::ProbeResult(ProbeResult {
            kind: ProbeKind::CfDomain as i32,
            target: "t".to_string(),
            ok: true,
            dur_ns: 1,
            err: ErrorCode::Dns as i32,
            err_code: 1,
        })),
        record(Event::LogOverflow(LogOverflow {
            dropped: 1,
            window_ns: 1,
        })),
        record(Event::StartupSummary(StartupSummary {
            version: "v".to_string(),
            listen: "l".to_string(),
            dc_ips: vec![DcIp {
                dc: 1,
                ip: "i".to_string(),
            }],
            tiers: vec!["t".to_string()],
            categories: vec!["c".to_string()],
        })),
        record(Event::PoolDiscard(PoolDiscard {
            ctx: Some(Ctx::new(1, true, Tier::Cfworker)),
            reason: DiscardReason::Stale as i32,
        })),
        record(Event::WarmupComplete(WarmupComplete {
            ready: 1,
            dur_ms: 1,
        })),
        record(Event::AttemptSkipped(AttemptSkipped {
            ctx: Some(Ctx::new(1, true, Tier::Mtproto)),
            tier: Tier::Mtproto as i32,
            reason: Reason::Pinned as i32,
        })),
        record(Event::DomainListFetched(DomainListFetched {
            source: DomainSource::Builtin as i32,
            count: 1,
            err: ErrorCode::Dns as i32,
            err_code: 1,
        })),
        record(Event::Shutdown(Shutdown {
            phase: ShutdownPhase::Forced as i32,
            signal: ShutdownSignal::Term as i32,
        })),
    ]
}

/// Splits `records` into batches of at most [`BATCH_MAX_UNIQUE_CONNS`] distinct
/// connections and computes each batch's header. Records keep their order and
/// are never dropped or reordered; a batch boundary falls where the next record
/// would introduce a seventeenth connection.
pub fn build_batch(records: &[LogRecord]) -> Vec<LogBatch> {
    let mut batches = Vec::new();
    let mut conns: Vec<u64> = Vec::with_capacity(BATCH_MAX_UNIQUE_CONNS);
    let mut start = 0;

    for (i, record) in records.iter().enumerate() {
        if conns.contains(&record.conn_id) {
            continue;
        }
        if conns.len() == BATCH_MAX_UNIQUE_CONNS {
            let closed = std::mem::replace(&mut conns, Vec::with_capacity(BATCH_MAX_UNIQUE_CONNS));
            batches.push(batch_of(&records[start..i], closed));
            start = i;
        }
        conns.push(record.conn_id);
    }

    if start < records.len() {
        batches.push(batch_of(&records[start..], conns));
    }
    batches
}

fn batch_of(records: &[LogRecord], mut conns: Vec<u64>) -> LogBatch {
    let mut header = BatchHeader {
        ts_first_ns: u64::MAX,
        ts_last_ns: 0,
        record_count: records.len() as u32,
        kind_mask: 0,
        dc_mask: 0,
        dc_media_mask: 0,
        conn_ids: Vec::new(),
    };

    for record in records {
        let (tag, dc, is_media) = shape(record);
        if tag != 0 {
            header.kind_mask |= 1u64 << (tag - 16);
        }
        if let Some(bit) = dc.and_then(dc_bit) {
            let mask = 1u32 << bit;
            header.dc_mask |= mask;
            if is_media {
                header.dc_media_mask |= mask;
            }
        }
        header.ts_first_ns = header.ts_first_ns.min(record.ts_ns);
        header.ts_last_ns = header.ts_last_ns.max(record.ts_ns);
    }

    conns.sort_unstable();
    header.conn_ids = conns;

    LogBatch {
        header: Some(header),
        records: records.to_vec(),
    }
}

/// Oneof tag, DC and media flag for a record — a single exhaustive match, so
/// adding an event variant is a compile error here until its mask bits are
/// decided rather than a silent zero.
fn shape(record: &LogRecord) -> (u32, Option<u32>, bool) {
    match &record.event {
        Some(Event::SessionOpened(e)) => tagged(16, &e.ctx),
        Some(Event::SessionClosed(e)) => tagged(17, &e.ctx),
        Some(Event::TierAttempt(e)) => tagged(18, &e.ctx),
        Some(Event::TierFallback(e)) => tagged(19, &e.ctx),
        Some(Event::CooldownArmed(e)) => tagged(20, &e.ctx),
        Some(Event::CooldownCleared(e)) => tagged(21, &e.ctx),
        Some(Event::CooldownSkipped(e)) => tagged(22, &e.ctx),
        Some(Event::PoolHit(e)) => tagged(23, &e.ctx),
        Some(Event::PoolMiss(e)) => tagged(24, &e.ctx),
        Some(Event::PoolRefill(e)) => tagged(25, &e.ctx),
        Some(Event::TlsHandshake(e)) => tagged(26, &e.ctx),
        Some(Event::RelayInitRetries(_)) => (27, None, false),
        Some(Event::AcceptError(_)) => (28, None, false),
        Some(Event::FdSnapshot(_)) => (29, None, false),
        Some(Event::ProbeResult(_)) => (30, None, false),
        Some(Event::LogOverflow(_)) => (31, None, false),
        Some(Event::StartupSummary(_)) => (32, None, false),
        Some(Event::PoolDiscard(e)) => tagged(33, &e.ctx),
        Some(Event::WarmupComplete(_)) => (34, None, false),
        Some(Event::AttemptSkipped(e)) => tagged(35, &e.ctx),
        Some(Event::DomainListFetched(_)) => (36, None, false),
        Some(Event::Shutdown(_)) => (37, None, false),
        None => (0, None, false),
    }
}

/// A record's oneof tag together with the DC and media flag its [`Ctx`] carries,
/// which is what the batch header's masks are made of. A session-scoped event
/// without a context — the schema allows it, no producer writes it — contributes
/// no DC rather than a wrong one.
fn tagged(tag: u32, ctx: &Option<Ctx>) -> (u32, Option<u32>, bool) {
    match ctx {
        Some(ctx) => (tag, Some(ctx.dc), ctx.is_media),
        None => (tag, None, false),
    }
}
