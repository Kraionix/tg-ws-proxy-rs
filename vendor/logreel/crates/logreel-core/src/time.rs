use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in nanoseconds, clamped at the epoch.
#[must_use]
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64)
}

/// Append an ISO-8601 UTC timestamp with nanosecond precision.
pub fn format_utc(ts_ns: u64, out: &mut String) {
    let seconds = (ts_ns / 1_000_000_000) as i64;
    let nanos = ts_ns % 1_000_000_000;
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = time_of_day / 3_600;
    let minute = (time_of_day % 3_600) / 60;
    let second = time_of_day % 60;
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z"
    );
}

/// Convert days since the Unix epoch to a civil date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + i64::from(month <= 2), month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::format_utc;

    #[test]
    fn epoch_is_formatted() {
        let mut out = String::new();
        format_utc(0, &mut out);
        assert_eq!(out, "1970-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn nanoseconds_and_dates_are_formatted() {
        let mut out = String::new();
        format_utc(1_700_000_000_123_456_789, &mut out);
        assert_eq!(out, "2023-11-14T22:13:20.123456789Z");
    }

    #[test]
    fn leap_day_is_formatted() {
        let mut out = String::new();
        format_utc(1_709_164_800_000_000_000, &mut out);
        assert_eq!(out, "2024-02-29T00:00:00.000000000Z");
    }
}
