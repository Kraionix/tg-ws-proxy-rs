use crate::Level;

/// One record as it travels through the channel and the writer.
///
/// The event is inline: no box, no trait object, no allocation on the emit
/// path. A large event makes the channel slot large; keep domain values
/// compact.
#[derive(Clone, Debug)]
pub struct Record<E> {
    /// Severity.
    pub level: Level,
    /// Category index into the consumer table.
    pub category: u8,
    /// Absolute kind, copied from the event.
    pub kind: u16,
    /// Unix nanoseconds.
    pub ts_ns: u64,
    /// Per-process sequence number.
    pub seq: u32,
    /// Connection id, 0 when not session scoped.
    pub conn_id: u64,
    /// The typed value.
    pub event: E,
}

impl<E> Record<E> {
    /// Construct a record; mostly useful to backends and tests.
    #[must_use]
    pub fn new(
        level: Level,
        category: u8,
        kind: u16,
        ts_ns: u64,
        seq: u32,
        conn_id: u64,
        event: E,
    ) -> Self {
        Self {
            level,
            category,
            kind,
            ts_ns,
            seq,
            conn_id,
            event,
        }
    }
}
