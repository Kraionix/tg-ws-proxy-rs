use std::collections::VecDeque;

use crate::Level;

/// Ring buffer for post-mortem dumps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingSettings {
    /// Maximum number of retained lines.
    pub capacity: usize,
    /// Maximum retained bytes across all lines.
    pub max_bytes: usize,
    /// Minimum level retained by the ring.
    pub floor: Level,
}

impl Default for RingSettings {
    fn default() -> Self {
        Self {
            capacity: 256,
            max_bytes: 128 * 1024,
            floor: Level::Warn,
        }
    }
}

/// Bounded, byte capped ring of rendered lines.
#[derive(Debug)]
pub(crate) struct Ring {
    settings: RingSettings,
    lines: VecDeque<String>,
    bytes: usize,
    dropped: u64,
}

impl Ring {
    pub(crate) fn new(settings: RingSettings) -> Self {
        Self {
            settings,
            lines: VecDeque::with_capacity(settings.capacity.min(1024)),
            bytes: 0,
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, level: Level, line: &str) {
        if level < self.settings.floor {
            return;
        }
        self.bytes += line.len();
        self.lines.push_back(line.to_owned());
        while self.lines.len() > self.settings.capacity
            || (self.bytes > self.settings.max_bytes && !self.lines.is_empty())
        {
            if let Some(removed) = self.lines.pop_front() {
                self.bytes = self.bytes.saturating_sub(removed.len());
                self.dropped += 1;
            }
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::{Ring, RingSettings};
    use crate::Level;

    #[test]
    fn floor_filters_lines() {
        let mut ring = Ring::new(RingSettings {
            capacity: 4,
            max_bytes: 1024,
            floor: Level::Warn,
        });
        ring.push(Level::Info, "ignored");
        ring.push(Level::Warn, "kept");
        assert_eq!(ring.snapshot(), vec!["kept".to_owned()]);
    }

    #[test]
    fn capacity_drops_oldest() {
        let mut ring = Ring::new(RingSettings {
            capacity: 2,
            max_bytes: 1024,
            floor: Level::Trace,
        });
        ring.push(Level::Info, "one");
        ring.push(Level::Info, "two");
        ring.push(Level::Info, "three");
        assert_eq!(ring.snapshot(), vec!["two".to_owned(), "three".to_owned()]);
        assert_eq!(ring.dropped(), 1);
    }

    #[test]
    fn byte_cap_drops_oldest() {
        let mut ring = Ring::new(RingSettings {
            capacity: 10,
            max_bytes: 5,
            floor: Level::Trace,
        });
        ring.push(Level::Info, "aaaa");
        ring.push(Level::Info, "bbbb");
        assert_eq!(ring.snapshot(), vec!["bbbb".to_owned()]);
    }
}
