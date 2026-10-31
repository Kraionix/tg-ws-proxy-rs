//! SIGKILL a live writer; the segment must stay readable and recoverable.

mod support;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use logreel_file::{Scan, TailState, probe, segments};
use logreel_store::Store;
use support::{TempDir, batch, rec};

#[test]
fn sigkill_leaves_a_readable_segment() {
    let dir = TempDir::new("sigkill");
    let mut child = Command::new(env!("CARGO_BIN_EXE_crash-writer"))
        .arg(dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn crash writer");

    let deadline = Instant::now() + Duration::from_secs(10);
    let segment = loop {
        if let Ok(files) = segments(dir.path())
            && let Some(file) = files.first()
            && std::fs::metadata(file).map(|meta| meta.len()).unwrap_or(0) > 4096
        {
            break file.clone();
        }
        assert!(Instant::now() < deadline, "writer produced no data");
        std::thread::sleep(Duration::from_millis(5));
    };

    child.kill().expect("SIGKILL");
    child.wait().expect("wait");

    let probe_value = probe(&segment).expect("probe after SIGKILL");
    assert!(probe_value.frames > 10, "frames {}", probe_value.frames);
    assert!(matches!(
        probe_value.tail,
        TailState::Clean | TailState::Truncated { .. }
    ));

    let mut store = logreel_file::FileStore::open(logreel_file::FileStoreConfig::new(dir.path()))
        .expect("reopen");
    store
        .append(&batch(&[rec(2, 0, 0, 5, 1, 1, b"after crash")], b""))
        .expect("append after crash");
    drop(store);

    let mut scan = Scan::open(&segment).expect("scan");
    let mut records = 0;
    loop {
        match scan.next_record() {
            None => break,
            Some(Ok(_)) => records += 1,
            Some(Err(error)) => panic!("{error}"),
        }
    }
    assert!(records > 10, "records {records}");
}
