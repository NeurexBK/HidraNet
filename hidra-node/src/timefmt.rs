//! UTC timestamps from the system clock, in the few shapes the engine
//! writes: whole seconds (`2026-11-23T15:13:29Z`), RFC 3339 with the
//! sub-second digits there are (`2026-11-23T15:13:29.344566+00:00`), and
//! milliseconds since 1970.
//!
//! Written here rather than taken from chrono, which is unmaintained
//! (RUSTSEC-2026-0543): formatting the clock in UTC needs no time zone
//! database and parses nothing.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds and nanoseconds since 1970-01-01T00:00:00Z. A clock set before
/// 1970 reads as 1970.
fn now() -> (i64, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

/// Milliseconds since 1970.
pub fn unix_millis() -> i64 {
    let (s, n) = now();
    s * 1000 + i64::from(n / 1_000_000)
}

/// Now, as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now_seconds() -> String {
    utc_seconds(now().0)
}

/// `secs` seconds before now, as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_seconds_ago(secs: i64) -> String {
    utc_seconds(now().0 - secs)
}

/// Now, as RFC 3339 with every non-zero group of sub-second digits and
/// `+00:00`: the shape `chrono::Utc::now().to_rfc3339()` gave.
pub fn utc_now_rfc3339() -> String {
    let (s, n) = now();
    rfc3339(s, n)
}

/// `secs` since 1970, as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_seconds(secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn rfc3339(secs: i64, nanos: u32) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    let frac = if nanos == 0 {
        String::new()
    } else if nanos % 1_000_000 == 0 {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos % 1_000 == 0 {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{frac}+00:00")
}

/// The UTC date and time `secs` after 1970 began: year, month, day, hour,
/// minute, second (Howard Hinnant's days-to-civil).
fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        m,
        d,
        (rem / 3_600) as u32,
        (rem % 3_600 / 60) as u32,
        (rem % 60) as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_seconds_in_utc() {
        // Checked against Python's datetime.fromtimestamp(s, timezone.utc).
        for (s, want) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_700_000_000, "2023-11-14T22:13:20Z"),
            (1_795_000_000, "2026-11-18T11:06:40Z"),
            (1_798_761_599, "2026-12-31T23:59:59Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
            (-1, "1969-12-31T23:59:59Z"),
        ] {
            assert_eq!(utc_seconds(s), want, "{s}");
        }
    }

    #[test]
    fn rfc3339_shows_the_sub_second_digits_there_are() {
        // As chrono's to_rfc3339 (SecondsFormat::AutoSi, no Z).
        let s = 1_795_000_000;
        assert_eq!(rfc3339(s, 0), "2026-11-18T11:06:40+00:00");
        assert_eq!(rfc3339(s, 120_000_000), "2026-11-18T11:06:40.120+00:00");
        assert_eq!(rfc3339(s, 344_566_000), "2026-11-18T11:06:40.344566+00:00");
        assert_eq!(
            rfc3339(s, 344_566_123),
            "2026-11-18T11:06:40.344566123+00:00"
        );
        assert_eq!(rfc3339(s, 5), "2026-11-18T11:06:40.000000005+00:00");
    }

    #[test]
    fn the_clock_reads_now() {
        let a = unix_millis();
        let n = utc_now_seconds();
        assert_eq!(n.len(), 20);
        assert!(n.ends_with('Z') && n.starts_with("20"), "{n}");
        // Seconds before now sort before now, as the analytics queries
        // compare them as strings.
        assert!(utc_seconds_ago(3_600) < n);
        assert!(utc_now_rfc3339().ends_with("+00:00"));
        assert!(a > 1_700_000_000_000);
    }
}
