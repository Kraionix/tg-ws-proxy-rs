//! Reading a segment back: the `probe-segment` and `dump-segment` verbs.
//!
//! `--log-dir` writes one redb file per UTC day; these two verbs read one back.
//! They live in the binary rather than in a separate tool because the program
//! that knows the record types, the value framing and the schema hash is this
//! one — and because the machine an operator wants to read a segment *on* is a
//! router, where there is no Rust toolchain to build a reader with. All the
//! storage knowledge stays in [`crate::log::storage`]; this module decides what
//! to print.
//!
//! ```text
//! tg-ws-proxy probe-segment /mnt/usb/tgws-logs
//! tg-ws-proxy dump-segment  /mnt/usb/tgws-logs --date 2026-10-13 --out day.jsonl
//! ```
//!
//! `probe-segment` answers "what is in this directory" with one JSON object per
//! segment and no records; `dump-segment` prints the records, one JSON object
//! per line, with one object per batch above them. JSON Lines on purpose:
//! `jq`, `pandas.read_json` and the tooling in `tools/analysis` all read it
//! without a parser of their own.
//!
//! Field names are the schema's own, and an enum prints under its variant name
//! (`Cfworker`, `TlsTimeout`). A discriminant this build has no name for — a
//! code written by a later binary, which `prost` decodes as the raw integer —
//! is kept as that number rather than dropped or left to fail the read.
//!
//! Neither verb writes to the segment: both go through
//! [`crate::log::storage::iter_batches`], which reads a private copy. A dump is
//! therefore safe on the live day's file, and a hash taken of a segment before
//! and after a read still describes the same bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};

use crate::config::Command;
use crate::log::render::peer_text;
use crate::log::schema::{self, Event, LogBatch, LogRecord, Peer};
use crate::log::storage::iter_batches;

/// One `<date>.redb` file, with the day its name spells.
struct Segment {
    path: PathBuf,
    date: String,
}

/// Runs the verb the operator asked for and returns the exit code for it.
pub fn run(command: &Command) -> ExitCode {
    match command {
        Command::ProbeSegment { dir } => probe(dir),
        Command::DumpSegment {
            dir,
            date,
            out,
            records_only,
        } => dump(dir, date.as_deref(), out.as_deref(), *records_only),
    }
}

/// The segments in `dir`, in date order — the order they were written in.
fn segments(dir: &Path) -> io::Result<Vec<Segment>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        // The extension, not the stem: a read copy (`.<date>.redb.read-<pid>`)
        // is not a segment, and neither is anything else an operator left here.
        if path.extension().is_none_or(|extension| extension != "redb") {
            continue;
        }
        // Owned before the path moves into the struct below: the stem borrows
        // the path, and the struct needs both.
        let Some(date) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        found.push(Segment { path, date });
    }
    found.sort_by(|a, b| a.date.cmp(&b.date));
    Ok(found)
}

fn probe(dir: &Path) -> ExitCode {
    let segments = match segments(dir) {
        Ok(segments) if !segments.is_empty() => segments,
        Ok(_) => {
            crate::direct!("no *.redb segments in {}", dir.display());
            return ExitCode::FAILURE;
        }
        Err(error) => {
            crate::direct!("cannot read {}: {error}", dir.display());
            return ExitCode::FAILURE;
        }
    };

    let mut failed = 0;
    for segment in &segments {
        let bytes = fs::metadata(&segment.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        // Hashed before the read, and read-only (`File::open`): what a segment
        // is, is what a hash of it says it is — the number is only worth
        // printing because reading no longer changes it.
        let digest = match sha256_of(&segment.path) {
            Ok(digest) => string(&digest),
            Err(error) => {
                crate::direct!("cannot hash {}: {error}", segment.path.display());
                null()
            }
        };
        match iter_batches(dir, &segment.date) {
            Ok(batches) => {
                let records: Vec<&LogRecord> =
                    batches.iter().flat_map(|batch| &batch.records).collect();
                let mut events: BTreeMap<String, u64> = BTreeMap::new();
                let mut conns = BTreeSet::new();
                for record in &records {
                    if let Some(event) = &record.event {
                        *events.entry(event_name(event).to_string()).or_default() += 1;
                    }
                    if record.conn_id != 0 {
                        conns.insert(record.conn_id);
                    }
                }
                let first = records.iter().map(|record| record.ts_ns).min();
                let last = records.iter().map(|record| record.ts_ns).max();
                let events = object(
                    &events
                        .iter()
                        .map(|(name, count)| (name.as_str(), number(count)))
                        .collect::<Vec<_>>(),
                );
                println!(
                    "{}",
                    object(&[
                        ("batches", number(batches.len())),
                        ("bytes", number(bytes)),
                        ("conns", number(conns.len())),
                        ("date", string(&segment.date)),
                        ("error", null()),
                        ("events", events),
                        ("file", string(&file_name(segment))),
                        ("first_ns", option_number(first)),
                        ("last_ns", option_number(last)),
                        ("records", number(records.len())),
                        ("sha256", digest),
                        ("type", string("segment")),
                    ])
                );
            }
            Err(error) => {
                failed += 1;
                crate::direct!("{}: {error}", segment.path.display());
                println!(
                    "{}",
                    object(&[
                        ("batches", null()),
                        ("bytes", number(bytes)),
                        ("conns", null()),
                        ("date", string(&segment.date)),
                        ("error", string(&error.to_string())),
                        ("events", null()),
                        ("file", string(&file_name(segment))),
                        ("first_ns", null()),
                        ("last_ns", null()),
                        ("records", null()),
                        ("sha256", digest),
                        ("type", string("segment")),
                    ])
                );
            }
        }
    }
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn dump(dir: &Path, date: Option<&str>, out: Option<&Path>, records_only: bool) -> ExitCode {
    let segments = match segments(dir) {
        Ok(segments) => segments,
        Err(error) => {
            crate::direct!("cannot read {}: {error}", dir.display());
            return ExitCode::FAILURE;
        }
    };
    let selected: Vec<&Segment> = segments
        .iter()
        .filter(|segment| date.is_none_or(|date| date == segment.date))
        .collect();
    if selected.is_empty() {
        match date {
            Some(date) => crate::direct!("no {date}.redb in {}", dir.display()),
            None => crate::direct!("no *.redb segments in {}", dir.display()),
        }
        return ExitCode::FAILURE;
    }

    let mut sink: Box<dyn Write> = match out {
        Some(path) => match File::create(path) {
            Ok(file) => Box::new(BufWriter::new(file)),
            Err(error) => {
                crate::direct!("cannot write {}: {error}", path.display());
                return ExitCode::FAILURE;
            }
        },
        None => Box::new(BufWriter::new(io::stdout())),
    };

    let mut failed = 0;
    let mut written = 0u64;
    for segment in &selected {
        match iter_batches(dir, &segment.date) {
            Ok(batches) => {
                for batch in &batches {
                    if !records_only
                        && let Err(error) = writeln!(sink, "{}", batch_json(segment, batch))
                    {
                        crate::direct!("write failed: {error}");
                        return ExitCode::FAILURE;
                    }
                    for record in &batch.records {
                        if let Err(error) = writeln!(sink, "{}", record_json(segment, record)) {
                            crate::direct!("write failed: {error}");
                            return ExitCode::FAILURE;
                        }
                        written += 1;
                    }
                }
            }
            Err(error) => {
                failed += 1;
                crate::direct!("{}: {error}", segment.path.display());
            }
        }
    }
    if let Err(error) = sink.flush() {
        crate::direct!("write failed: {error}");
        return ExitCode::FAILURE;
    }
    crate::direct!(
        "{written} records from {} segment(s), {failed} unreadable",
        selected.len()
    );
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The file name of a segment, for the one line that names it.
fn file_name(segment: &Segment) -> String {
    segment
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// SHA-256 of a file, read-only, in chunks: this runs on a router, where the
/// whole point is not to hold a segment in memory twice.
fn sha256_of(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

// ── JSON ───────────────────────────────────────────────────────────────────
//
// Written by hand. `serde_json` would be a dependency tree (serde, itoa, ryu)
// and a few hundred kilobytes in a binary that ships to routers, for a shape
// that is fixed by the schema next door — the same trade `render.rs` makes for
// the text view.
//
// Fields are listed alphabetically, which is the order `serde_json`'s map puts
// them in: a dump taken by the separate tool this replaced is byte-for-byte
// comparable with one taken here, which is how the port was checked.

/// `{"key":value,…}`, in the order given.
fn object(fields: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(64);
    out.push('{');
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&string(key));
        out.push(':');
        out.push_str(value);
    }
    out.push('}');
    out
}

/// `[value,…]`, values already rendered.
fn array(values: &[String]) -> String {
    let mut out = String::with_capacity(16);
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(value);
    }
    out.push(']');
    out
}

/// A JSON string, escaped as the format requires.
///
/// Character-wise, so a multi-byte character is copied as itself: JSON is UTF-8
/// and escaping it would only make the file larger and unreadable. The five
/// short escapes are the ones the format defines; every other control character
/// goes out as `\u00xx`.
fn string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn number(value: impl std::fmt::Display) -> String {
    value.to_string()
}

/// The number, or `null` for a day that recorded nothing.
fn option_number(value: Option<u64>) -> String {
    match value {
        Some(value) => number(value),
        None => null(),
    }
}

fn null() -> String {
    "null".to_string()
}

fn bool_of(value: bool) -> String {
    if value {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

fn strings(values: &[String]) -> String {
    array(&values.iter().map(|value| string(value)).collect::<Vec<_>>())
}

fn batch_json(segment: &Segment, batch: &LogBatch) -> String {
    match &batch.header {
        Some(header) => object(&[
            (
                "conns",
                array(&header.conn_ids.iter().map(number).collect::<Vec<_>>()),
            ),
            ("date", string(&segment.date)),
            ("dc_mask", number(header.dc_mask)),
            ("dc_media_mask", number(header.dc_media_mask)),
            ("kind_mask", number(header.kind_mask)),
            ("records", number(header.record_count)),
            ("ts_first_ns", number(header.ts_first_ns)),
            ("ts_last_ns", number(header.ts_last_ns)),
            ("type", string("batch")),
        ]),
        // A batch that reached the file without a header is one this build
        // cannot describe; its records still print.
        None => object(&[
            ("date", string(&segment.date)),
            ("records", number(batch.records.len())),
            ("type", string("batch")),
        ]),
    }
}

fn record_json(segment: &Segment, record: &LogRecord) -> String {
    object(&[
        ("category", category_name(record.category)),
        ("conn", number(record.conn_id)),
        ("date", string(&segment.date)),
        (
            "event",
            match &record.event {
                Some(event) => event_json(event),
                None => null(),
            },
        ),
        ("level", level_name(record.level)),
        ("seq", number(record.seq)),
        ("ts_ns", number(record.ts_ns)),
        ("type", string("record")),
    ])
}

fn level_name(raw: i32) -> String {
    match schema::Level::try_from(raw) {
        Ok(level) => string(level.name()),
        Err(_) => number(raw),
    }
}

fn category_name(raw: i32) -> String {
    match schema::Category::try_from(raw) {
        Ok(category) => string(category.name()),
        Err(_) => number(raw),
    }
}

/// An enum field, under the variant name the schema gives it.
fn enum_json<T: TryFrom<i32> + std::fmt::Debug>(raw: i32) -> String {
    match T::try_from(raw) {
        Ok(value) => string(&format!("{value:?}")),
        Err(_) => number(raw),
    }
}

fn ctx_json(ctx: &Option<schema::Ctx>) -> String {
    match ctx {
        Some(ctx) => object(&[
            ("dc", number(ctx.dc)),
            ("media", bool_of(ctx.is_media)),
            ("tier", enum_json::<schema::Tier>(ctx.tier)),
        ]),
        None => null(),
    }
}

fn peer_json(peer: &Option<Peer>) -> String {
    match peer {
        Some(peer) => object(&[
            ("addr", string(&peer_text(peer))),
            ("encrypted", bool_of(peer.encrypted)),
            ("hashed", bool_of(peer.hashed)),
            ("port", number(peer.port)),
        ]),
        None => null(),
    }
}

/// The event's name, for a summary that counts them. Exhaustive on purpose: a
/// new event is a compile error here until it is named for the summary too.
fn event_name(event: &Event) -> &'static str {
    match event {
        Event::SessionOpened(_) => "SessionOpened",
        Event::SessionClosed(_) => "SessionClosed",
        Event::TierAttempt(_) => "TierAttempt",
        Event::TierFallback(_) => "TierFallback",
        Event::CooldownArmed(_) => "CooldownArmed",
        Event::CooldownCleared(_) => "CooldownCleared",
        Event::CooldownSkipped(_) => "CooldownSkipped",
        Event::PoolHit(_) => "PoolHit",
        Event::PoolMiss(_) => "PoolMiss",
        Event::PoolRefill(_) => "PoolRefill",
        Event::PoolDiscard(_) => "PoolDiscard",
        Event::TlsHandshake(_) => "TlsHandshake",
        Event::RelayInitRetries(_) => "RelayInitRetries",
        Event::AcceptError(_) => "AcceptError",
        Event::FdSnapshot(_) => "FdSnapshot",
        Event::ProbeResult(_) => "ProbeResult",
        Event::LogOverflow(_) => "LogOverflow",
        Event::StartupSummary(_) => "StartupSummary",
        Event::WarmupComplete(_) => "WarmupComplete",
        Event::AttemptSkipped(_) => "AttemptSkipped",
        Event::DomainListFetched(_) => "DomainListFetched",
        Event::Shutdown(_) => "Shutdown",
    }
}

fn event_json(event: &Event) -> String {
    match event {
        Event::SessionOpened(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("event", string("SessionOpened")),
            ("peer", peer_json(&payload.peer)),
        ]),
        Event::SessionClosed(payload) => object(&[
            ("bytes_down", number(payload.bytes_down)),
            ("bytes_up", number(payload.bytes_up)),
            (
                "closed_by",
                enum_json::<schema::ClosedBy>(payload.closed_by),
            ),
            ("ctx", ctx_json(&payload.ctx)),
            ("dur_ms", number(payload.dur_ms)),
            ("event", string("SessionClosed")),
            ("via", string(&payload.via)),
        ]),
        Event::TierAttempt(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("dur_ns", number(payload.dur_ns)),
            ("err", enum_json::<schema::ErrorCode>(payload.err)),
            ("err_code", number(payload.err_code)),
            ("errno", number(payload.errno)),
            ("event", string("TierAttempt")),
            ("host", string(&payload.host)),
            ("ok", bool_of(payload.ok)),
        ]),
        Event::TierFallback(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("event", string("TierFallback")),
            ("from_tier", enum_json::<schema::Tier>(payload.from_tier)),
            ("reason", enum_json::<schema::Reason>(payload.reason)),
            ("to_tier", enum_json::<schema::Tier>(payload.to_tier)),
        ]),
        Event::CooldownArmed(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("dur_s", number(payload.dur_s)),
            ("err", enum_json::<schema::ErrorCode>(payload.err)),
            ("err_code", number(payload.err_code)),
            ("event", string("CooldownArmed")),
            ("key", string(&payload.key_display)),
            ("kind", enum_json::<schema::CooldownKind>(payload.kind)),
        ]),
        Event::CooldownCleared(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("event", string("CooldownCleared")),
            ("key", string(&payload.key_display)),
            ("kind", enum_json::<schema::CooldownKind>(payload.kind)),
        ]),
        Event::CooldownSkipped(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("event", string("CooldownSkipped")),
            ("key", string(&payload.key_display)),
            ("kind", enum_json::<schema::CooldownKind>(payload.kind)),
        ]),
        Event::PoolHit(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("event", string("PoolHit")),
            ("left", number(payload.left)),
        ]),
        Event::PoolMiss(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("event", string("PoolMiss")),
        ]),
        Event::PoolRefill(payload) => object(&[
            ("added", number(payload.added)),
            ("ctx", ctx_json(&payload.ctx)),
            ("dur_ms", number(payload.dur_ms)),
            ("err", enum_json::<schema::ErrorCode>(payload.err)),
            ("errno", number(payload.errno)),
            ("event", string("PoolRefill")),
            ("ready", number(payload.ready)),
        ]),
        Event::PoolDiscard(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("event", string("PoolDiscard")),
            ("reason", enum_json::<schema::DiscardReason>(payload.reason)),
        ]),
        Event::TlsHandshake(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("dur_ns", number(payload.dur_ns)),
            ("err", enum_json::<schema::ErrorCode>(payload.err)),
            ("errno", number(payload.errno)),
            ("event", string("TlsHandshake")),
            ("kind", enum_json::<schema::HandshakeKind>(payload.kind)),
        ]),
        Event::RelayInitRetries(payload) => object(&[
            ("event", string("RelayInitRetries")),
            ("n", number(payload.n)),
        ]),
        Event::AcceptError(payload) => object(&[
            ("backoff_ms", number(payload.backoff_ms)),
            ("err", enum_json::<schema::ErrorCode>(payload.err)),
            ("errno", number(payload.errno)),
            ("event", string("AcceptError")),
        ]),
        Event::FdSnapshot(payload) => object(&[
            ("event", string("FdSnapshot")),
            ("open", number(payload.open)),
            ("sem_avail", number(payload.sem_avail)),
            ("soft_limit", number(payload.soft_limit)),
        ]),
        Event::ProbeResult(payload) => object(&[
            ("dur_ns", number(payload.dur_ns)),
            ("err", enum_json::<schema::ErrorCode>(payload.err)),
            ("err_code", number(payload.err_code)),
            ("event", string("ProbeResult")),
            ("kind", enum_json::<schema::ProbeKind>(payload.kind)),
            ("ok", bool_of(payload.ok)),
            ("target", string(&payload.target)),
        ]),
        Event::LogOverflow(payload) => object(&[
            ("dropped", number(payload.dropped)),
            ("event", string("LogOverflow")),
            ("window_ns", number(payload.window_ns)),
        ]),
        Event::StartupSummary(payload) => object(&[
            ("categories", strings(&payload.categories)),
            (
                "dc_ips",
                array(
                    &payload
                        .dc_ips
                        .iter()
                        .map(|dc_ip| object(&[("dc", number(dc_ip.dc)), ("ip", string(&dc_ip.ip))]))
                        .collect::<Vec<_>>(),
                ),
            ),
            ("event", string("StartupSummary")),
            ("listen", string(&payload.listen)),
            ("tiers", strings(&payload.tiers)),
            ("version", string(&payload.version)),
        ]),
        Event::WarmupComplete(payload) => object(&[
            ("dur_ms", number(payload.dur_ms)),
            ("event", string("WarmupComplete")),
            ("ready", number(payload.ready)),
        ]),
        Event::AttemptSkipped(payload) => object(&[
            ("ctx", ctx_json(&payload.ctx)),
            ("event", string("AttemptSkipped")),
            ("reason", enum_json::<schema::Reason>(payload.reason)),
            ("tier", enum_json::<schema::Tier>(payload.tier)),
        ]),
        Event::DomainListFetched(payload) => object(&[
            ("count", number(payload.count)),
            ("err", enum_json::<schema::ErrorCode>(payload.err)),
            ("err_code", number(payload.err_code)),
            ("event", string("DomainListFetched")),
            ("source", enum_json::<schema::DomainSource>(payload.source)),
        ]),
        Event::Shutdown(payload) => object(&[
            ("event", string("Shutdown")),
            ("phase", enum_json::<schema::ShutdownPhase>(payload.phase)),
            (
                "signal",
                enum_json::<schema::ShutdownSignal>(payload.signal),
            ),
        ]),
    }
}
