use std::fmt::Write as _;
use std::io::{self, Write as _};

use crate::settings::{TextSettings, TextTarget};
use crate::{Level, Record};

/// Formats the shared prefix, then delegates the body to the consumer.
///
/// Prefix shape: 2026-10-31T12:00:00.000000000Z INFO  [conn=42] body
pub(crate) fn format_record<E>(record: &Record<E>, render: fn(&E, &mut String), out: &mut String) {
    out.clear();
    crate::time::format_utc(record.ts_ns, out);
    out.push(' ');
    let name = record.level.as_str();
    out.push_str(name);
    for _ in name.len()..5 {
        out.push(' ');
    }
    if record.conn_id != 0 {
        let _ = write!(out, " [conn={}]", record.conn_id);
    }
    out.push(' ');
    render(&record.event, out);
}

/// Buffered text projection; one write per batch.
pub(crate) struct TextSink {
    settings: TextSettings,
    buffer: String,
}

impl TextSink {
    pub(crate) fn new(settings: TextSettings) -> Self {
        Self {
            settings,
            buffer: String::with_capacity(8 * 1024),
        }
    }

    pub(crate) fn wants(&self, level: Level) -> bool {
        level >= self.settings.floor
    }

    pub(crate) fn push(&mut self, line: &str) {
        self.buffer.push_str(line);
        self.buffer.push('\n');
    }

    pub(crate) fn commit(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let result = self.settings.target.write_all(self.buffer.as_bytes());
        self.buffer.clear();
        result
    }
}

impl TextTarget {
    pub(crate) fn write_all(self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Stderr => io::stderr().lock().write_all(bytes),
            Self::Stdout => io::stdout().lock().write_all(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::format_record;
    use crate::{Level, Record};

    #[derive(Debug)]
    struct Body(&'static str);

    fn render(value: &Body, out: &mut String) {
        out.push_str(value.0);
    }

    #[test]
    fn prefix_has_timestamp_level_and_connection() {
        let record = Record::new(
            Level::Warn,
            0,
            7,
            1_700_000_000_123_456_789,
            1,
            42,
            Body("disk full"),
        );
        let mut out = String::new();
        format_record(&record, render, &mut out);
        assert_eq!(
            out,
            "2023-11-14T22:13:20.123456789Z WARN  [conn=42] disk full"
        );
    }

    #[test]
    fn connection_is_omitted_when_zero() {
        let record = Record::new(Level::Info, 0, 7, 0, 1, 0, Body("started"));
        let mut out = String::new();
        format_record(&record, render, &mut out);
        assert_eq!(out, "1970-01-01T00:00:00.000000000Z INFO  started");
    }
}
