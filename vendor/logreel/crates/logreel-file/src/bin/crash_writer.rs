//! Write frames forever; the crash test kills this process with SIGKILL.

use logreel_file::{FileStore, FileStoreConfig};
use logreel_store::{EncodedBatch, Store};

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn batch() -> EncodedBatch {
    let payload_text = b"crash writer record";
    let ts = 1_700_000_000_000_000_000u64;
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&ts.to_le_bytes());
    payload.extend_from_slice(&ts.to_le_bytes());
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(1);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.push(2);
    payload.push(0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&ts.to_le_bytes());
    put_varint(&mut payload, 1);
    put_varint(&mut payload, 0);
    put_varint(&mut payload, payload_text.len() as u64);
    payload.extend_from_slice(payload_text);
    EncodedBatch::new(
        1,
        [0x11; 16],
        8,
        1,
        ts,
        ts,
        Box::new([]),
        payload.into_boxed_slice(),
    )
}

fn main() {
    let directory = std::env::args().nth(1).expect("directory");
    let mut store = FileStore::open(FileStoreConfig {
        directory: directory.into(),
        producer_id: 1,
        session_nonce: 2,
        keep_days: 7,
        max_total_bytes: 0,
        compress: false,
        zstd_level: 3,
    })
    .expect("open");
    let batch = batch();
    loop {
        store.append(&batch).expect("append");
    }
}
