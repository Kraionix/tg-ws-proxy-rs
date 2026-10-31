use std::fmt;

/// Severity of a record.
///
/// Five values, library owned. The numeric value is the byte written to the
/// segment, so the order is part of the format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Level {
    /// Fine grained tracing.
    Trace = 0,
    /// Developer facing detail.
    Debug = 1,
    /// Normal operation.
    #[default]
    Info = 2,
    /// Something degraded but survived.
    Warn = 3,
    /// A request or a task failed.
    Error = 4,
}

impl Level {
    /// Number of levels.
    pub const COUNT: usize = 5;

    /// Parse a wire byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Trace),
            1 => Some(Self::Debug),
            2 => Some(Self::Info),
            3 => Some(Self::Warn),
            4 => Some(Self::Error),
            _ => None,
        }
    }

    /// Wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Upper case name for a consumer that prints a level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Level;

    #[test]
    fn wire_bytes_roundtrip() {
        for value in 0..=4u8 {
            let level = Level::from_u8(value).expect("level");
            assert_eq!(level.as_u8(), value);
            assert_eq!(Level::from_u8(level.as_u8()), Some(level));
        }
        assert_eq!(Level::from_u8(5), None);
    }

    #[test]
    fn ordering_matches_severity() {
        assert!(Level::Trace < Level::Debug);
        assert!(Level::Info < Level::Warn);
        assert!(Level::Error > Level::Warn);
    }
}
