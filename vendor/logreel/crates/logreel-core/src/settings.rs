use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use logreel_store::Durability;

use crate::level::Level;

/// A failure inside the library, not a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalError {
    /// Coarse category.
    pub kind: InternalErrorKind,
    /// Human readable detail.
    pub message: String,
}

/// Category of an [InternalError].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalErrorKind {
    /// The sink rejected a batch.
    Sink,
    /// A configuration problem detected at runtime.
    Config,
}

/// Pipeline configuration.
///
/// Build it with [Settings::builder]. The defaults are deliberately boring:
/// Info floor, 4096 channel slots, 256 records per batch, one second flush,
/// eventual durability.
pub struct Settings {
    /// Minimum level for every category: the producer gate.
    pub min_level: Level,
    /// Minimum level the sink keeps, for every category.
    ///
    /// The producer gate is the union of every consumer; this is the second
    /// table, consulted on the writer thread, that decides what actually
    /// reaches the sink. [Settings::min_level] is the default, and
    /// [SettingsBuilder::sink_min_level] separates the two.
    pub sink_min_level: Level,
    /// Bounded channel capacity in records.
    pub channel_capacity: usize,
    /// Maximum records per batch.
    pub batch_max: usize,
    /// Maximum time a record waits before a flush.
    pub flush_interval: Duration,
    /// Flush immediately when a Warn or Error record arrives.
    pub flush_on_warn: bool,
    /// Durability passed to the sink after each batch.
    pub durability: Durability,
    /// Opaque domain bytes written into every batch.
    pub domain: Box<[u8]>,
    pub(crate) filter_overrides: Vec<(u8, Option<Level>)>,
    pub(crate) sink_filter_overrides: Vec<(u8, Option<Level>)>,
    pub(crate) on_internal: Option<Arc<dyn Fn(InternalError) + Send + Sync>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            min_level: Level::Info,
            sink_min_level: Level::Info,
            channel_capacity: 4096,
            batch_max: 256,
            flush_interval: Duration::from_secs(1),
            flush_on_warn: true,
            durability: Durability::Eventual,
            domain: Box::new([]),
            filter_overrides: Vec::new(),
            sink_filter_overrides: Vec::new(),
            on_internal: None,
        }
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Settings")
            .field("min_level", &self.min_level)
            .field("sink_min_level", &self.sink_min_level)
            .field("channel_capacity", &self.channel_capacity)
            .field("batch_max", &self.batch_max)
            .field("flush_interval", &self.flush_interval)
            .field("flush_on_warn", &self.flush_on_warn)
            .field("durability", &self.durability)
            .field("domain", &self.domain)
            .field("filter_overrides", &self.filter_overrides)
            .field("sink_filter_overrides", &self.sink_filter_overrides)
            .field("on_internal", &self.on_internal.is_some())
            .finish()
    }
}

impl Settings {
    /// Start a builder with the defaults.
    #[must_use]
    pub fn builder() -> SettingsBuilder {
        SettingsBuilder {
            settings: Self::default(),
            sink_floor_explicit: false,
        }
    }
}

/// Fluent builder for [Settings].
#[derive(Debug)]
pub struct SettingsBuilder {
    settings: Settings,
    /// True once [SettingsBuilder::sink_min_level] was called, so
    /// [SettingsBuilder::min_level] stops moving the sink floor with the gate.
    sink_floor_explicit: bool,
}

impl SettingsBuilder {
    /// Global floor.
    ///
    /// Until [SettingsBuilder::sink_min_level] is called this moves the sink
    /// floor too, because "log at debug" means the segment as well as the
    /// gate.
    #[must_use]
    pub fn min_level(mut self, level: Level) -> Self {
        self.settings.min_level = level;
        if !self.sink_floor_explicit {
            self.settings.sink_min_level = level;
        }
        self
    }

    /// Sink floor, independent of the producer gate.
    #[must_use]
    pub fn sink_min_level(mut self, level: Level) -> Self {
        self.settings.sink_min_level = level;
        self.sink_floor_explicit = true;
        self
    }

    /// Override the sink floor for one category, or disable that category.
    #[must_use]
    pub fn sink_filter(mut self, category: u8, level: Option<Level>) -> Self {
        self.settings.sink_filter_overrides.push((category, level));
        self
    }

    /// Bounded channel capacity.
    #[must_use]
    pub fn channel_capacity(mut self, capacity: usize) -> Self {
        self.settings.channel_capacity = capacity;
        self
    }

    /// Maximum records per batch.
    #[must_use]
    pub fn batch_max(mut self, batch_max: usize) -> Self {
        self.settings.batch_max = batch_max;
        self
    }

    /// Maximum delay before a flush.
    #[must_use]
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.settings.flush_interval = interval;
        self
    }

    /// Flush eagerly on Warn and above.
    #[must_use]
    pub fn flush_on_warn(mut self, enabled: bool) -> Self {
        self.settings.flush_on_warn = enabled;
        self
    }

    /// Durability policy.
    #[must_use]
    pub fn durability(mut self, durability: Durability) -> Self {
        self.settings.durability = durability;
        self
    }

    /// Opaque domain bytes.
    #[must_use]
    pub fn domain(mut self, domain: impl Into<Box<[u8]>>) -> Self {
        self.settings.domain = domain.into();
        self
    }

    /// Override one category, or disable it with None.
    #[must_use]
    pub fn filter(mut self, category: u8, level: Option<Level>) -> Self {
        self.settings.filter_overrides.push((category, level));
        self
    }

    /// Observe internal failures.
    #[must_use]
    pub fn on_internal(mut self, callback: impl Fn(InternalError) + Send + Sync + 'static) -> Self {
        self.settings.on_internal = Some(Arc::new(callback));
        self
    }

    /// Finish.
    #[must_use]
    pub fn build(self) -> Settings {
        self.settings
    }
}

#[cfg(test)]
mod tests {
    use super::Settings;
    use crate::Level;
    use logreel_store::Durability;
    use std::time::Duration;

    #[test]
    fn defaults_are_stable() {
        let settings = Settings::default();
        assert_eq!(settings.min_level, Level::Info);
        assert_eq!(settings.sink_min_level, Level::Info);
        assert_eq!(settings.channel_capacity, 4096);
        assert_eq!(settings.batch_max, 256);
        assert_eq!(settings.flush_interval, Duration::from_secs(1));
        assert_eq!(settings.durability, Durability::Eventual);
    }

    #[test]
    fn builder_roundtrip() {
        let settings = Settings::builder()
            .min_level(Level::Debug)
            .sink_min_level(Level::Warn)
            .sink_filter(4, None)
            .channel_capacity(8)
            .batch_max(4)
            .flush_interval(Duration::from_millis(10))
            .flush_on_warn(false)
            .durability(Durability::Immediate)
            .domain(b"dc=2".to_vec())
            .filter(3, None)
            .build();
        assert_eq!(settings.min_level, Level::Debug);
        assert_eq!(settings.sink_min_level, Level::Warn);
        assert_eq!(settings.sink_filter_overrides, vec![(4, None)]);
        assert_eq!(settings.channel_capacity, 8);
        assert_eq!(settings.batch_max, 4);
        assert!(!settings.flush_on_warn);
        assert_eq!(settings.durability, Durability::Immediate);
        assert_eq!(&*settings.domain, b"dc=2");
        assert_eq!(settings.filter_overrides, vec![(3, None)]);
    }
}
