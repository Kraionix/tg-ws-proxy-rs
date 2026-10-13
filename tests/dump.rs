//! The segment reader as the binary exposes it: `probe-segment` and
//! `dump-segment`.
//!
//! The unit tests in `src/log/tests.rs` cover the reader (`iter_batches`) and
//! the copy it reads through. What is left is the part only a process can show:
//! that the verbs are reachable from the command line, that what they print is
//! the documented JSON Lines shape, and that pointing them at a segment leaves
//! that segment byte for byte as it was — the property the whole verb exists
//! for, since an operator reads the archive on the stick they archive.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::log::schema::{Category, Event, Level, PoolHit};
use tg_ws_proxy_rs::log::{self, schema};

/// A directory under the system temp dir, removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("tgws-dump-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("a writable temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .expect("the directory exists")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Writes one segment with three records in it, and returns the day it covers.
fn write_segment(dir: &Path) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    // The sink's own floor is what decides whether a record reaches the file,
    // and the events here are debug: a default `info` would leave an empty
    // segment and a test that passes for the wrong reason.
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        &"ab".repeat(32),
        "--log-level",
        "debug",
        "--text-log",
        "off",
    ])
    .expect("the fixture config parses");
    let handle = runtime
        .block_on(async { log::init(Some(dir), config.log_settings(), config.log_options()) })
        .expect("the sink starts");

    for conn in 1..=3u64 {
        handle.emit(
            conn,
            Category::Pool,
            Level::Debug,
            Event::PoolHit(PoolHit {
                ctx: Some(schema::Ctx::new(2, false, schema::Tier::Cfworker)),
                left: 4 - conn as u32,
            }),
        );
    }
    runtime.block_on(handle.shutdown());

    day_of(dir)
}

/// The one `<date>.redb` in `dir`, as its date.
fn day_of(dir: &Path) -> String {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("the directory exists")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".redb"))
        .collect();
    names.sort();
    assert_eq!(names.len(), 1, "expected one segment, found {names:?}");
    names.remove(0).trim_end_matches(".redb").to_string()
}

/// The binary under test, built by cargo for this test run.
fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_tg-ws-proxy"))
        .args(args)
        .output()
        .expect("the binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Every JSON object in `text`, as the tool printed them, one per line.
fn objects(text: &str) -> Vec<serde_json::Value> {
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}")))
        .collect()
}

#[test]
fn dump_segment_prints_the_documented_json_lines_and_changes_nothing() {
    let dir = TempDir::new("dump");
    let date = write_segment(dir.path());
    let path = dir.path().join(format!("{date}.redb"));
    let before = fs::read(&path).expect("the segment exists");

    let (code, stdout, stderr) = run(&["dump-segment", dir.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");

    let printed = objects(&stdout);
    // Three records and the batch above them; the batch object comes first.
    assert_eq!(printed.len(), 4, "printed: {stdout}");
    assert_eq!(printed[0]["type"], "batch");
    assert_eq!(printed[0]["date"], date.as_str());
    assert_eq!(printed[0]["records"], 3);
    assert_eq!(printed[1]["type"], "record");
    assert_eq!(printed[1]["date"], date.as_str());
    assert_eq!(printed[1]["seq"], 1);
    assert_eq!(printed[1]["conn"], 1);
    assert_eq!(printed[1]["level"], "debug");
    assert_eq!(printed[1]["category"], "pool");
    assert_eq!(printed[1]["event"]["event"], "PoolHit");
    // The fixture's own numbers, so a record that printed under the wrong
    // connection would fail here rather than pass on shape alone.
    assert_eq!(printed[1]["event"]["left"], 3);
    assert_eq!(printed[2]["event"]["left"], 2);
    assert_eq!(printed[3]["conn"], 3);
    assert_eq!(printed[3]["event"]["left"], 1);
    assert_eq!(printed[1]["event"]["ctx"]["tier"], "Cfworker");
    assert_eq!(printed[1]["event"]["ctx"]["dc"], 2);
    assert_eq!(printed[1]["event"]["ctx"]["media"], false);
    assert!(printed[1]["ts_ns"].as_u64().expect("a timestamp") > 0);

    // The point of the verb: the archive is exactly as it was.
    let after = fs::read(&path).expect("the segment still exists");
    assert!(before == after, "dump-segment changed the segment");
    assert_eq!(dir.entries(), vec![format!("{date}.redb")]);
}

#[test]
fn probe_segment_summarises_a_directory_and_names_the_file_hash() {
    let dir = TempDir::new("probe");
    let date = write_segment(dir.path());

    let (code, stdout, stderr) = run(&["probe-segment", dir.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");

    let printed = objects(&stdout);
    assert_eq!(printed.len(), 1, "printed: {stdout}");
    assert_eq!(printed[0]["type"], "segment");
    assert_eq!(printed[0]["date"], date.as_str());
    assert_eq!(printed[0]["file"], format!("{date}.redb").as_str());
    assert_eq!(printed[0]["batches"], 1);
    assert_eq!(printed[0]["records"], 3);
    assert_eq!(printed[0]["conns"], 3);
    assert_eq!(printed[0]["events"]["PoolHit"], 3);
    assert_eq!(printed[0]["error"], serde_json::Value::Null);
    assert_eq!(
        printed[0]["sha256"].as_str().expect("a hash").len(),
        64,
        "printed: {stdout}"
    );
    assert!(printed[0]["first_ns"].as_u64().expect("a timestamp") > 0);
}

#[test]
fn a_probe_can_be_narrowed_to_one_day_and_reports_a_missing_one() {
    let dir = TempDir::new("dates");
    let date = write_segment(dir.path());

    let (code, stdout, _) = run(&[
        "dump-segment",
        dir.path().to_str().unwrap(),
        "--date",
        &date,
        "--records-only",
    ]);
    assert_eq!(code, 0);
    let printed = objects(&stdout);
    assert_eq!(printed.len(), 3, "records only: {stdout}");
    assert!(printed.iter().all(|object| object["type"] == "record"));

    let (code, stdout, stderr) = run(&[
        "probe-segment",
        dir.path().to_str().unwrap(),
        "--date",
        "2001-01-01",
    ]);
    // `--date` is a `dump-segment` flag; on `probe-segment` clap must refuse it
    // rather than silently summarise everything.
    assert_ne!(code, 0, "stdout: {stdout}");
    assert!(stderr.contains("unexpected argument"), "stderr: {stderr}");
}

#[test]
fn a_directory_without_segments_is_an_error_and_not_an_empty_answer() {
    let dir = TempDir::new("empty");

    let (code, stdout, stderr) = run(&["probe-segment", dir.path().to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(stderr.contains("no *.redb segments"), "stderr: {stderr}");

    let (code, stdout, stderr) = run(&["dump-segment", dir.path().to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(stderr.contains("no *.redb segments"), "stderr: {stderr}");
}

#[test]
fn a_date_without_a_segment_names_the_file_it_looked_for() {
    let dir = TempDir::new("absent-date");
    write_segment(dir.path());

    let (code, _, stderr) = run(&[
        "dump-segment",
        dir.path().to_str().unwrap(),
        "--date",
        "2001-01-01",
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("no 2001-01-01.redb"), "stderr: {stderr}");
}
