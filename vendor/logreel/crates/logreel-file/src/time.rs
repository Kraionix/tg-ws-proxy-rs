//! UTC day arithmetic for segment names and retention.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const NANOS_PER_DAY: u64 = 86_400_000_000_000;

/// Suffix of a segment file name: `YYYY-MM-DD.seg`.
pub const SEGMENT_SUFFIX: &str = ".seg";

/// Current Unix time in nanoseconds, clamped at the epoch.
pub(crate) fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64)
}

/// UTC day number since the Unix epoch.
pub(crate) fn day_from_ns(ns: u64) -> i64 {
    (ns / NANOS_PER_DAY) as i64
}

/// Today's UTC day number.
#[must_use]
pub fn today() -> i64 {
    day_from_ns(now_ns())
}

/// File stem for a day: YYYY-MM-DD.
#[must_use]
pub fn day_name(day: i64) -> String {
    let (year, month, date) = civil_from_days(day);
    format!("{year:04}-{month:02}-{date:02}")
}

/// The date part of a segment file name, if it has one.
///
/// The shape is checked, not the calendar: `2026-13-01.seg` passes here and
/// is rejected by [`day_of_name`]. Callers that only need "is this a segment
/// file" should stop at this function.
#[must_use]
pub fn segment_day(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(SEGMENT_SUFFIX)?;
    let bytes = stem.as_bytes();
    if bytes.len() != 10 {
        return None;
    }
    let shaped = bytes.iter().enumerate().all(|(index, byte)| {
        if index == 4 || index == 7 {
            *byte == b'-'
        } else {
            byte.is_ascii_digit()
        }
    });
    shaped.then_some(stem)
}

/// The day number a `YYYY-MM-DD` name spells, or `None` when it is not one.
///
/// The inverse of [`day_name`], needed where retention does arithmetic on
/// what a file is called.
#[must_use]
pub fn day_of_name(name: &str) -> Option<i64> {
    let mut parts = name.split('-');
    let year = parts.next()?.parse::<i64>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
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

pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::{
        civil_from_days, day_from_ns, day_name, day_of_name, days_from_civil, now_ns, segment_day,
        today,
    };

    #[test]
    fn day_names_roundtrip() {
        for (year, month, day) in [
            (1970, 1, 1),
            (2023, 11, 14),
            (2024, 2, 29),
            (2026, 10, 31),
            (2088, 12, 31),
        ] {
            let number = days_from_civil(year, month, day);
            assert_eq!(day_name(number), format!("{year:04}-{month:02}-{day:02}"));
            assert_eq!(day_of_name(&day_name(number)), Some(number));
        }
    }

    #[test]
    fn epoch_and_day_conversion() {
        assert_eq!(day_from_ns(0), 0);
        assert_eq!(day_from_ns(86_400_000_000_000), 1);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(day_of_name("not-a-day"), None);
        assert_eq!(day_of_name("2026-13-01"), None);
        assert_eq!(
            day_of_name("2026-02-31"),
            Some(days_from_civil(2026, 2, 31))
        );
    }

    #[test]
    fn segment_names_carry_a_day() {
        let day = days_from_civil(2026, 11, 1);
        let name = format!("{}{}", day_name(day), super::SEGMENT_SUFFIX);
        assert_eq!(name, "2026-11-01.seg");
        assert_eq!(segment_day(&name), Some("2026-11-01"));
        assert_eq!(segment_day(&name).and_then(day_of_name), Some(day));
    }

    #[test]
    fn segment_day_rejects_foreign_names() {
        for name in [
            "2026-11-01",
            "2026-11-01.seg.lock",
            "2026-11-01.seg.tmp",
            "20261101.seg",
            "2026-11-1.seg",
            "2026/11/01.seg",
            "2026-11-01.SEG",
            "abc.seg",
            ".seg",
            "",
        ] {
            assert_eq!(segment_day(name), None, "{name:?} is not a segment name");
        }
    }

    #[test]
    fn today_is_the_day_of_now() {
        assert_eq!(today(), day_from_ns(now_ns()));
    }
}
