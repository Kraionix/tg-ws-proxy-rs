//! Shared test helpers: one event domain, one blocking sink.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use logreel_core::{BatchSink, DecodeError, EncodedBatch, Event, StoreError};

/// Small event domain with two kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestEvent {
    Ping(u64),
    Empty,
}

impl Event for TestEvent {
    const CODEC_ID: u16 = 1;
    const SCHEMA_HASH: [u8; 16] = [0x22; 16];
    const KINDS: u16 = 2;

    fn kind(&self) -> u16 {
        match self {
            Self::Ping(_) => 0,
            Self::Empty => 1,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        if let Self::Ping(value) = self {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    fn decode(kind: u16, bytes: &[u8]) -> Result<Self, DecodeError> {
        match kind {
            0 if bytes.len() == 8 => {
                let mut array = [0u8; 8];
                array.copy_from_slice(bytes);
                Ok(Self::Ping(u64::from_le_bytes(array)))
            }
            1 if bytes.is_empty() => Ok(Self::Empty),
            _ => Err(DecodeError::new(kind, "bad payload")),
        }
    }
}

/// A sink that blocks inside every write until released.
#[derive(Clone)]
pub(crate) struct BlockingSink {
    /// Number of batches that reached write_batch.
    pub(crate) entered: Arc<AtomicUsize>,
    /// Batches written after the gate opened.
    pub(crate) batches: Arc<Mutex<Vec<EncodedBatch>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
}

impl BlockingSink {
    /// Create a closed sink.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            entered: Arc::new(AtomicUsize::new(0)),
            batches: Arc::new(Mutex::new(Vec::new())),
            gate: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// Open the gate and wake the writer.
    pub(crate) fn release(&self) {
        let (lock, condvar) = &*self.gate;
        *lock.lock().expect("gate") = true;
        condvar.notify_all();
    }
}

impl BatchSink for BlockingSink {
    fn write_batch(&mut self, batch: &EncodedBatch) -> Result<(), StoreError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let (lock, condvar) = &*self.gate;
        let mut open = lock.lock().expect("gate");
        while !*open {
            open = condvar.wait(open).expect("gate wait");
        }
        drop(open);
        self.batches.lock().expect("batches").push(batch.clone());
        Ok(())
    }
}

impl Default for BlockingSink {
    fn default() -> Self {
        Self::new()
    }
}
