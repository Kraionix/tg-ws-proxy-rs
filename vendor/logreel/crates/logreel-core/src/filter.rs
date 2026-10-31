use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use crate::Level;

/// Number of category slots in the filter table.
pub const CATEGORY_COUNT: usize = 32;

const OFF: u8 = u8::MAX;

/// Per-category level filters with a cached maximum.
///
/// The emit path reads one atomic for the maximum and one array slot for the
/// category. A generation counter lets consumers that hold a snapshot (the
/// ring, diagnostics, tests) refresh only when a filter changed.
#[derive(Debug)]
pub struct Filters {
    levels: [AtomicU8; CATEGORY_COUNT],
    min_level: AtomicU8,
    generation: AtomicU32,
}

impl Filters {
    /// All categories at the same floor.
    #[must_use]
    pub fn new(min_level: Level) -> Self {
        Self {
            levels: std::array::from_fn(|_| AtomicU8::new(min_level.as_u8())),
            min_level: AtomicU8::new(min_level.as_u8()),
            generation: AtomicU32::new(1),
        }
    }

    /// Set one category, or disable it with None.
    pub fn set(&self, category: u8, level: Option<Level>) {
        let index = usize::from(category);
        if index >= CATEGORY_COUNT {
            return;
        }
        self.levels[index].store(level.map_or(OFF, Level::as_u8), Ordering::Relaxed);
        self.recompute();
    }

    /// Set every category at once.
    pub fn set_all(&self, level: Option<Level>) {
        let value = level.map_or(OFF, Level::as_u8);
        for slot in &self.levels {
            slot.store(value, Ordering::Relaxed);
        }
        self.recompute();
    }

    fn recompute(&self) {
        let mut floor = OFF;
        for slot in &self.levels {
            let value = slot.load(Ordering::Relaxed);
            if value != OFF {
                floor = floor.min(value);
            }
        }
        self.min_level.store(floor, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// True when a record at this category and level is wanted.
    #[must_use]
    pub fn enabled(&self, category: u8, level: Level) -> bool {
        let floor = self.min_level.load(Ordering::Relaxed);
        if floor == OFF {
            return false;
        }
        let index = usize::from(category);
        if index >= CATEGORY_COUNT {
            return false;
        }
        let value = level.as_u8();
        value >= floor && value >= self.levels[index].load(Ordering::Relaxed)
    }

    /// Current generation; changes on every filter mutation.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation.load(Ordering::Acquire)
    }

    /// Take a snapshot that can be refreshed on generation change.
    #[must_use]
    pub fn snapshot(&self) -> FilterSnapshot {
        FilterSnapshot {
            generation: self.generation(),
            min_level: self.min_level.load(Ordering::Relaxed),
            levels: std::array::from_fn(|index| self.levels[index].load(Ordering::Relaxed)),
        }
    }
}

/// A copy of the filter table, cheap to consult.
#[derive(Clone, Debug)]
pub struct FilterSnapshot {
    generation: u32,
    min_level: u8,
    levels: [u8; CATEGORY_COUNT],
}

impl FilterSnapshot {
    /// Generation this snapshot was taken at.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// True when a record at this category and level is wanted.
    #[must_use]
    pub fn enabled(&self, category: u8, level: Level) -> bool {
        let index = usize::from(category);
        if index >= CATEGORY_COUNT || self.min_level == OFF {
            return false;
        }
        let value = level.as_u8();
        value >= self.min_level && value >= self.levels[index]
    }

    /// Reload from the live table when it changed. Returns true on reload.
    pub fn refresh(&mut self, filters: &Filters) -> bool {
        if filters.generation() == self.generation {
            return false;
        }
        *self = filters.snapshot();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{CATEGORY_COUNT, Filters};
    use crate::Level;

    #[test]
    fn disabled_category_is_rejected() {
        let filters = Filters::new(Level::Info);
        assert!(filters.enabled(0, Level::Info));
        assert!(!filters.enabled(0, Level::Debug));
        filters.set(0, None);
        assert!(!filters.enabled(0, Level::Error));
        assert!(filters.enabled(1, Level::Info));
        filters.set(0, Some(Level::Trace));
        assert!(filters.enabled(0, Level::Trace));
        assert!(!filters.enabled(CATEGORY_COUNT as u8, Level::Error));
    }

    #[test]
    fn floor_caches_the_minimum() {
        let filters = Filters::new(Level::Warn);
        assert!(!filters.enabled(2, Level::Info));
        assert!(filters.enabled(2, Level::Warn));
        filters.set(2, Some(Level::Trace));
        assert!(filters.enabled(2, Level::Info));
        filters.set_all(Some(Level::Trace));
        assert!(filters.enabled(2, Level::Trace));
        filters.set_all(None);
        assert!(!filters.enabled(2, Level::Trace));
        filters.set_all(Some(Level::Error));
        assert!(!filters.enabled(2, Level::Warn));
        assert!(filters.enabled(2, Level::Error));
    }

    #[test]
    fn snapshot_refreshes_on_generation_change() {
        let filters = Filters::new(Level::Info);
        let mut snapshot = filters.snapshot();
        assert!(!snapshot.refresh(&filters));
        assert!(snapshot.enabled(0, Level::Info));
        filters.set(0, None);
        assert!(snapshot.refresh(&filters));
        assert!(!snapshot.enabled(0, Level::Info));
    }
}
