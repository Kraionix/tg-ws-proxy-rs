//! Facade wiring: each backend and feature reaches the same pipeline.

#![cfg(any(feature = "file", feature = "redb", feature = "ring"))]

use logreel::{DecodeError, Event, Level, Settings, init};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ping(u64);

impl Event for Ping {
    const CODEC_ID: u16 = 4;
    const KINDS: u16 = 1;

    fn kind(&self) -> u16 {
        0
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    fn decode(_kind: u16, bytes: &[u8]) -> Result<Self, DecodeError> {
        let value = u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| DecodeError::new(0, "ping expects 8 bytes"))?,
        );
        Ok(Self(value))
    }
}

fn temp(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("logreel-facade-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let _ = std::fs::remove_file(&path);
    path
}

#[cfg(feature = "file")]
#[test]
fn file_backend_through_the_facade() {
    use logreel::file::{FileStore, FileStoreConfig, probe};

    let directory = temp("file");
    let store = FileStore::open(FileStoreConfig::new(&directory)).expect("store");
    let logger = init::<Ping>(
        Settings::builder().batch_max(2).build(),
        None,
        Box::new(store),
    )
    .expect("init");
    for value in 0..5 {
        assert!(logger.handle().emit(Level::Info, 0, value, Ping(value)));
    }
    let report = logger.shutdown();
    assert_eq!(report.records, 5);
    let files = logreel::file::segments(&directory).expect("segments");
    assert_eq!(files.len(), 1);
    let value = probe(&files[0]).expect("probe");
    assert_eq!(value.records, 5);
    let _ = std::fs::remove_dir_all(&directory);
}

#[cfg(feature = "redb")]
#[test]
fn redb_backend_through_the_facade() {
    use logreel::Store;
    use logreel::redb::RedbStore;

    let path = temp("redb");
    let store = RedbStore::open(&path).expect("store");
    let logger = init::<Ping>(
        Settings::builder().batch_max(2).build(),
        None,
        Box::new(store),
    )
    .expect("init");
    for value in 0..4 {
        assert!(logger.handle().emit(Level::Info, 0, value, Ping(value)));
    }
    let _ = logger.shutdown();
    let store = RedbStore::open(&path).expect("reopen");
    let batches: Vec<_> = store
        .scan()
        .expect("scan")
        .collect::<Result<_, _>>()
        .expect("batches");
    assert_eq!(
        batches.iter().map(|batch| batch.record_count).sum::<u32>(),
        4
    );
    let _ = std::fs::remove_file(&path);
}

#[cfg(feature = "ring")]
#[test]
fn ring_through_the_facade() {
    use logreel::{RingSettings, SharedSink};

    let logger = init::<Ping>(
        Settings::builder()
            .batch_max(1)
            .ring(RingSettings {
                capacity: 4,
                max_bytes: 1024,
                floor: Level::Trace,
            })
            .build(),
        Some(|_: &Ping, out: &mut String| out.push_str("ping")),
        Box::new(SharedSink::new()),
    )
    .expect("init");
    logger.handle().emit(Level::Info, 0, 1, Ping(1));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while logger.handle().dump_ring().is_empty() {
        assert!(std::time::Instant::now() < deadline, "ring stayed empty");
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let _ = logger.shutdown();
}
