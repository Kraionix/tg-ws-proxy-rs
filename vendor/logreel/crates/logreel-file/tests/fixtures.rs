//! Every conformance fixture must pass through the real reader.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use logreel_file::{Scan, TailState, dump_raw, probe};
use logreel_store::ErrorKind;
use serde_json::Value;

struct OwnedRecord {
    level: u8,
    category: u8,
    kind: u16,
    ts_ns: u64,
    seq: u32,
    conn_id: u64,
    payload: Vec<u8>,
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v1")
}

fn expected(name: &str) -> Value {
    let path = fixtures().join("expected").join(format!("{name}.json"));
    serde_json::from_slice(&fs::read(path).expect("expected json")).expect("valid json")
}

fn check_header(name: &str, probe_value: &logreel_file::Probe, expected: &Value) {
    let header = &expected["header"];
    assert_eq!(
        probe_value.header.codec_id,
        header["codec_id"].as_u64().unwrap() as u16,
        "{name}"
    );
    assert_eq!(
        probe_value.header.kind_count,
        header["kind_count"].as_u64().unwrap() as u16,
        "{name}"
    );
    assert_eq!(
        probe_value.header.producer_id,
        header["producer_id"].as_u64().unwrap() as u32,
        "{name}"
    );
    assert_eq!(
        probe_value.header.created_ns,
        header["created_ns"].as_u64().unwrap(),
        "{name}"
    );
    assert_eq!(
        probe_value.header.flags,
        header["flags"].as_u64().unwrap() as u16,
        "{name}"
    );
    assert_eq!(
        format!("{:02x?}", probe_value.header.schema_hash).replace(['[', ']', ',', ' '], ""),
        header["schema_hash"].as_str().unwrap(),
        "{name}"
    );
}

fn check_probe(name: &str, value: &logreel_file::Probe, expected: &Value) {
    let probe_value = &expected["probe"];
    assert_eq!(
        value.frames,
        probe_value["frames"].as_u64().unwrap(),
        "{name}: frames"
    );
    assert_eq!(
        value.records,
        probe_value["records"].as_u64().unwrap(),
        "{name}: records"
    );
    assert_eq!(
        value.valid_end,
        probe_value["valid_end"].as_u64().unwrap(),
        "{name}: valid_end"
    );
    assert_eq!(
        value.truncated_bytes,
        probe_value["truncated_bytes"].as_u64().unwrap(),
        "{name}: truncated_bytes"
    );
    assert_eq!(
        value.tail.as_str(),
        probe_value["tail"].as_str().unwrap(),
        "{name}: tail"
    );
    assert_eq!(
        value.unknown_records,
        probe_value["unknown_records"].as_u64().unwrap(),
        "{name}"
    );
    assert_eq!(
        value.sha256_hex(),
        probe_value["sha256"].as_str().unwrap(),
        "{name}: sha256"
    );
    assert_eq!(
        value.first_ts_ns,
        probe_value["first_ts_ns"].as_u64(),
        "{name}: first_ts"
    );
    assert_eq!(
        value.last_ts_ns,
        probe_value["last_ts_ns"].as_u64(),
        "{name}: last_ts"
    );
    let expected_conns: Vec<u64> = probe_value["conn_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap())
        .collect();
    assert_eq!(value.conn_ids, expected_conns, "{name}: conn ids");
    for (kind, count) in probe_value["kinds"].as_object().unwrap() {
        let kind: u16 = kind.parse().unwrap();
        assert_eq!(
            value.kinds.get(&kind).copied().unwrap_or(0),
            count.as_u64().unwrap(),
            "{name}: kind {kind}"
        );
    }
    check_header(name, value, expected);
}

#[test]
fn fixtures_probe_and_scan_match_expectations() {
    let cases = [
        ("F01", "F01_normal.seg"),
        ("F02", "F02_varints.seg"),
        ("F03", "F03_unknown_kind.seg"),
        ("F04", "F04_schema_mismatch.seg"),
        ("F05", "F05_torn_tail.seg"),
        ("F06", "F06_bad_crc.seg"),
        ("F09", "F09_zstd.seg"),
        ("F10", "F10_producer_zero.seg"),
    ];
    for (name, file) in cases {
        let path = fixtures().join(file);
        let expected = expected(name);
        if name == "F09" && !cfg!(feature = "zstd") {
            let value = probe(&path).expect("probe without zstd");
            assert!(
                matches!(value.tail, TailState::Unsupported { .. }),
                "{name}"
            );
            let mut scan = Scan::open(&path).expect("scan");
            let error = scan
                .next_record()
                .expect("one result")
                .expect_err("unsupported");
            assert_eq!(error.kind(), ErrorKind::Unsupported);
            continue;
        }
        let value = probe(&path).expect("probe");
        check_probe(name, &value, &expected);
        let mut scan = Scan::open(&path).expect("scan");
        let mut records = Vec::new();
        loop {
            match scan.next_record() {
                None => break,
                Some(Ok(record)) => records.push(OwnedRecord {
                    level: record.level,
                    category: record.category,
                    kind: record.kind,
                    ts_ns: record.ts_ns,
                    seq: record.seq,
                    conn_id: record.conn_id,
                    payload: record.payload.to_vec(),
                }),
                Some(Err(error)) => {
                    assert_eq!(
                        expected["probe"]["tail"].as_str().unwrap(),
                        "corrupt",
                        "{name}: unexpected error {error}"
                    );
                    assert_eq!(error.kind(), ErrorKind::Corrupt, "{name}");
                    break;
                }
            }
        }
        let expected_records = expected["records"].as_array().unwrap();
        assert_eq!(
            records.len(),
            expected_records.len(),
            "{name}: record count"
        );
        for (record, expected) in records.iter().zip(expected_records) {
            assert_eq!(u64::from(record.level), expected["level"].as_u64().unwrap());
            assert_eq!(
                u64::from(record.category),
                expected["category"].as_u64().unwrap()
            );
            assert_eq!(u64::from(record.kind), expected["kind"].as_u64().unwrap());
            assert_eq!(record.ts_ns, expected["ts_ns"].as_u64().unwrap());
            assert_eq!(u64::from(record.seq), expected["seq"].as_u64().unwrap());
            assert_eq!(record.conn_id, expected["conn_id"].as_u64().unwrap());
            assert_eq!(
                support::hex(&record.payload),
                expected["payload_hex"].as_str().unwrap()
            );
        }
        if name == "F04" {
            let mut dump = Vec::new();
            dump_raw(&path, &mut dump).expect("raw dump");
            let text = String::from_utf8(dump).expect("utf8");
            assert!(text.contains("payload=6f70656e65643a3432"), "{name}");
        }
    }
}

#[test]
fn refused_files_name_the_failure() {
    for (name, file) in [("F07", "F07_empty.seg"), ("F07b", "F07_bad_magic.seg")] {
        let path = fixtures().join(file);
        let error = probe(&path).expect_err("refused");
        assert!(error.to_string().contains(file), "{name}: {error}");
        assert!(Scan::open(&path).is_err(), "{name}");
    }
}

#[test]
fn torn_tail_stops_at_the_last_good_frame() {
    let path = fixtures().join("F05_torn_tail.seg");
    let mut scan = Scan::open(&path).expect("scan");
    let mut count = 0;
    loop {
        match scan.next_record() {
            None => break,
            Some(Ok(_)) => count += 1,
            Some(Err(error)) => panic!("{error}"),
        }
    }
    assert_eq!(count, 3);
}

#[test]
fn corrupt_crc_stops_with_an_offset() {
    let path = fixtures().join("F06_bad_crc.seg");
    let mut scan = Scan::open(&path).expect("scan");
    assert!(scan.next_record().expect("first").is_ok());
    let error = scan.next_record().expect("second").expect_err("corrupt");
    assert_eq!(error.kind(), ErrorKind::Corrupt);
    assert_eq!(error.offset(), Some(117));
}

#[test]
fn unknown_kind_is_skipped_by_payload_length() {
    let path = fixtures().join("F03_unknown_kind.seg");
    let mut scan = Scan::open(&path).expect("scan");
    let mut kinds = Vec::new();
    loop {
        match scan.next_record() {
            None => break,
            Some(Ok(record)) => kinds.push(record.kind),
            Some(Err(error)) => panic!("{error}"),
        }
    }
    assert_eq!(kinds, vec![0, 1, 0, 0x9001, 1]);
}
