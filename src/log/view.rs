//! The text view: the ring of recent records in RAM and the sink the rendered
//! lines go to.
//!
//! The view is not a second consumer with a task of its own. It is a struct
//! owned by the writer task, and it is fed the record the writer has just taken
//! off the channel, before the segment's own filter decides what to do with it.
//! Three things follow, and they are the reasons it is built this way:
//!
//! * **No lock and no second queue.** The writer is already the stream's single
//!   reader, so the view needs neither a mutex nor a channel of its own, and a
//!   slow terminal cannot make the *segment* fall behind a producer.
//! * **One render per record.** The text is written where the record is
//!   formatted anyway, and the buffer it is written into is reused for the life
//!   of the process rather than allocated per line.
//! * **The ring is free.** Keeping the last few records costs a `VecDeque` push
//!   and a clone that only happens when the ring's own floor keeps the record.
//!
//! What is *not* free is the `[peer]` prefix, and it is the one piece of state
//! here that the records do not carry: `session_opened` holds the client
//! address, every later event of that session does not, so the view remembers
//! the address of the sessions it has seen open and forgets it when they close.
//! That map is bounded, and a stream that overflows it loses prefixes rather
//! than memory.
//!
//! # Ring capacity
//!
//! The ring holds the last [`TEXT_RING_DEFAULT`] records, clamped between
//! [`TEXT_RING_MIN`] and [`TEXT_RING_MAX`]. It exists for the `SIGUSR1` dump:
//! when a router misbehaves, the operator sends the signal and gets the last few
//! hundred records printed through the same sink, without attaching a debugger
//! to a device that has none.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::PathBuf;

use super::render;
use super::schema::{Event, Level, LogRecord};
use super::{Filter, Settings};

/// Last records the view keeps in RAM for the `SIGUSR1` dump.
///
/// Set either here, or at build time: `TG_TEXT_RING=1024 cargo build …`. That
/// is a `option_env!` and not a `build.rs` because the crate deliberately has
/// none — see the module docs in `src/log.rs` — and not a cargo feature, which
/// cannot carry a number.
pub const TEXT_RING_DEFAULT: usize = match option_env!("TG_TEXT_RING") {
    Some(value) => ring_from_env(value),
    None => 512,
};

/// Bounds of the ring, at build time and at run time both. The lower one is a
/// dump too small to be worth the signal; the upper one is a device that may
/// have 64 MB of RAM, where the ring is the largest thing this module owns.
pub const TEXT_RING_MIN: usize = 64;
pub const TEXT_RING_MAX: usize = 4096;

/// `str::parse` is not a `const fn`, so the digits are read by hand. A value
/// that is not a number in range fails the build rather than being quietly
/// replaced: a compile-time knob nobody notices is a knob that is not there.
const fn ring_from_env(value: &str) -> usize {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        panic!("TG_TEXT_RING is set but empty; it must be a number from 64 to 4096");
    }

    let mut parsed: usize = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte < b'0' || byte > b'9' {
            panic!("TG_TEXT_RING must be a decimal number, e.g. TG_TEXT_RING=1024");
        }
        parsed = parsed * 10 + (byte - b'0') as usize;
        index += 1;
    }

    if parsed < TEXT_RING_MIN || parsed > TEXT_RING_MAX {
        panic!("TG_TEXT_RING must be between 64 and 4096");
    }

    parsed
}

/// [`TEXT_RING_DEFAULT`]'s limits applied to a runtime value.
pub fn clamp_ring(capacity: usize) -> usize {
    capacity.clamp(TEXT_RING_MIN, TEXT_RING_MAX)
}

/// Where the rendered lines go.
///
/// Part of [`Settings`] rather than a sink, because the sink holds an open file
/// and `Settings` is cloned: the target is what the operator chose, and the
/// writer task opens it once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextTarget {
    /// The text view is not written anywhere. The ring still fills.
    Off,
    Stderr,
    Stdout,
    /// Appended to, never truncated: a restart must not cost the previous run's
    /// lines.
    File(PathBuf),
}

impl TextTarget {
    /// The value of `--text-log[=…]`: `off`, `stderr`, `stdout`, or a path.
    ///
    /// Anything else is a path, including a bare word: an operator who writes
    /// `--text-log=log.txt` means the file, and one who misspells `stderr` gets
    /// a file called `sterr` rather than a silently disabled view.
    pub fn from_spec(spec: &str) -> Self {
        match spec {
            "off" => Self::Off,
            "stderr" => Self::Stderr,
            "stdout" => Self::Stdout,
            path => Self::File(PathBuf::from(path)),
        }
    }

    pub fn is_off(&self) -> bool {
        matches!(self, Self::Off)
    }
}

impl std::fmt::Display for TextTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => f.write_str("the text view"),
            Self::Stderr => f.write_str("stderr"),
            Self::Stdout => f.write_str("stdout"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// The open text destination. Written by one task, so it needs no lock.
pub enum TextSink {
    Off,
    Stderr,
    Stdout,
    File { file: File, path: PathBuf },
}

impl TextSink {
    /// Opens what `target` names. A path that cannot be opened is a startup
    /// error, for the same reason a `--log-dir` that cannot be created is one:
    /// an operator who asked for a log file and did not get one must hear about
    /// it at startup rather than at the first warning.
    pub fn open(target: &TextTarget) -> io::Result<Self> {
        Ok(match target {
            TextTarget::Off => Self::Off,
            TextTarget::Stderr => Self::Stderr,
            TextTarget::Stdout => Self::Stdout,
            TextTarget::File(path) => Self::File {
                file: OpenOptions::new().create(true).append(true).open(path)?,
                path: path.clone(),
            },
        })
    }

    /// One line, one write. There is no line buffer to lose: the text is what a
    /// power cut is allowed to cost, and it is written as it is rendered.
    pub fn write(&mut self, line: &str) -> io::Result<()> {
        match self {
            Self::Off => Ok(()),
            Self::Stderr => io::stderr().write_all(line.as_bytes()),
            Self::Stdout => io::stdout().write_all(line.as_bytes()),
            Self::File { file, .. } => file.write_all(line.as_bytes()),
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Off | Self::Stderr | Self::Stdout => Ok(()),
            Self::File { file, .. } => file.flush(),
        }
    }

    pub fn is_off(&self) -> bool {
        matches!(self, Self::Off)
    }
}

/// Sessions whose peer the view remembers, for the `[peer]` prefix.
///
/// A concurrent-session count on a 64 MB device is in the hundreds; the cap is
/// there for the case the count is not what it should be — a session whose
/// close record never arrived. Overflow drops the map rather than the oldest
/// entry, because the entries are the prefixes of sessions that are still open
/// and there is no ordering that says which of them is the stale one.
const PEER_MAP_MAX: usize = 1024;

/// A failing sink says so once, then once every this many lines: the failure is
/// usually a full or read-only filesystem, and a message per line would be a
/// message per line about messages.
const SINK_FAILURE_REPORT_EVERY: u64 = 1024;

/// The record stream's human-readable projection, plus the ring behind it.
pub struct View {
    sink: TextSink,
    /// The text's own floor, independent of the segment's and the ring's.
    text: Filter,
    ring_filter: Filter,
    ring: VecDeque<LogRecord>,
    ring_capacity: usize,
    peers: HashMap<u64, String>,
    /// Reused by every render, which is the whole reason rendering takes a
    /// buffer.
    line: String,
    failures: u64,
}

impl View {
    /// Opens the sink `settings` names. The only fallible step here.
    pub fn open(settings: &Settings) -> io::Result<Self> {
        Ok(Self::with_sink(
            TextSink::open(&settings.text_log)?,
            settings.text,
            settings.ring,
            settings.ring_capacity,
        ))
    }

    pub fn with_sink(
        sink: TextSink,
        text: Filter,
        ring_filter: Filter,
        ring_capacity: usize,
    ) -> Self {
        let ring_capacity = clamp_ring(ring_capacity);
        Self {
            sink,
            text,
            ring_filter,
            // Reserved once: a ring that grows under a burst is a reallocation
            // on the writer's path, on a device with very little memory.
            ring: VecDeque::with_capacity(ring_capacity),
            ring_capacity,
            peers: HashMap::new(),
            line: String::with_capacity(256),
            failures: 0,
        }
    }

    /// Feeds one record: the ring if its floor keeps it, the sink if the text
    /// floor does.
    ///
    /// Both floors are this view's own. The record reached this task because
    /// *some* consumer wanted it — the segment, the ring or the text — so a
    /// view with a floor of `warn` sees warnings here that the segment may have
    /// dropped, and a ring at `debug` keeps records the text never prints.
    pub fn show(&mut self, record: &LogRecord) {
        // Learned before the record is rendered and forgotten after it: the
        // session's own close line is the one where the prefix is worth the
        // most, and it is the record that ends the session.
        self.remember(record);

        let level = Level::try_from(record.level);
        // A level this build does not know is kept rather than dropped, exactly
        // as the segment's filter keeps it: the filter exists to keep the view
        // small, not to lose what it cannot classify.
        let kept = |filter: Filter| match level {
            Ok(level) => filter.keeps(level),
            Err(_) => true,
        };

        if kept(self.text) {
            self.write_record(record);
            if matches!(level, Ok(Level::Warn | Level::Error)) {
                self.flush();
            }
        }
        if kept(self.ring_filter) {
            if self.ring.len() == self.ring_capacity {
                self.ring.pop_front();
            }
            self.ring.push_back(record.clone());
        }

        self.forget(record);
    }

    /// Writes everything the ring holds to the sink, oldest first.
    ///
    /// The prefixes come from the live map first and from the ring's own
    /// `session_opened` records second: a session that closed while the ring
    /// watched it is no longer in the map, and a session that opened before the
    /// ring's window is not in the ring.
    pub fn dump(&mut self) {
        let learned = self.peers_in_ring();
        let held = self.ring.len();
        let plural = if held == 1 { "" } else { "s" };
        let header = format!("tg-ws-proxy: ring dump, {held} record{plural}\n");
        write_all(&mut self.sink, &mut self.failures, &header);

        for index in 0..self.ring.len() {
            self.line.clear();
            let record = &self.ring[index];
            let peer = self
                .peers
                .get(&record.conn_id)
                .or_else(|| learned.get(&record.conn_id))
                .map(String::as_str);
            if render::render(record, peer, &mut self.line) {
                write_all(&mut self.sink, &mut self.failures, &self.line);
            }
        }

        self.flush();
    }

    pub fn flush(&mut self) {
        if let Err(error) = self.sink.flush() {
            report(self.failures + 1, error);
            self.failures += 1;
        }
    }

    /// The records the ring holds, for tests and for the future status page.
    pub fn ring(&self) -> impl Iterator<Item = &LogRecord> {
        self.ring.iter()
    }

    /// Where the last few hundred records would go, as the banner says it.
    pub fn sink_name(&self) -> &'static str {
        match self.sink {
            TextSink::Off => "off",
            TextSink::Stderr => "stderr",
            TextSink::Stdout => "stdout",
            TextSink::File { .. } => "file",
        }
    }

    /// Remembers the client address of a session the stream has just opened.
    fn remember(&mut self, record: &LogRecord) {
        match &record.event {
            Some(Event::SessionOpened(opened)) => {
                if record.conn_id == 0 {
                    return;
                }
                let Some(peer) = opened.peer.as_ref() else {
                    return;
                };
                if self.peers.len() >= PEER_MAP_MAX {
                    self.peers.clear();
                }
                self.peers.insert(record.conn_id, render::peer_text(peer));
            }
            // A new run numbers its connections from one again, so every entry
            // in the map is a prefix that would be attached to the wrong
            // session from here on.
            Some(Event::StartupSummary(_)) => self.peers.clear(),
            _ => {}
        }
    }

    /// Forgets a session once its last record has been rendered.
    fn forget(&mut self, record: &LogRecord) {
        if matches!(record.event, Some(Event::SessionClosed(_))) {
            self.peers.remove(&record.conn_id);
        }
    }

    fn peers_in_ring(&self) -> HashMap<u64, String> {
        let mut learned = HashMap::new();
        for record in &self.ring {
            if let Some(Event::SessionOpened(opened)) = &record.event
                && let Some(peer) = opened.peer.as_ref()
            {
                learned
                    .entry(record.conn_id)
                    .or_insert_with(|| render::peer_text(peer));
            }
        }
        learned
    }

    fn write_record(&mut self, record: &LogRecord) {
        self.line.clear();
        let peer = self.peers.get(&record.conn_id).map(String::as_str);
        if render::render(record, peer, &mut self.line) {
            write_all(&mut self.sink, &mut self.failures, &self.line);
        }
    }
}

/// Writes one chunk, counting the failure and reporting it rarely enough that
/// the report cannot become the flood it is reporting: this message goes to
/// stderr, and stderr is also what breaks first on a device out of space.
fn write_all(sink: &mut TextSink, failures: &mut u64, text: &str) {
    if let Err(error) = sink.write(text) {
        *failures += 1;
        report(*failures, error);
    }
}

fn report(failures: u64, error: io::Error) {
    if failures == 1 || failures.is_multiple_of(SINK_FAILURE_REPORT_EVERY) {
        eprintln!("tg-ws-proxy: text log write failed {failures} times, last error: {error}");
    }
}

#[cfg(test)]
mod tests;
