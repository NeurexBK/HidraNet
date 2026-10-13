//! RFC 3339 dates, the one shape a node list uses (`2026-10-13T00:00:00Z`),
//! without pulling a date crate in for a single field.

use anyhow::{anyhow, Result};

/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` (or `+00:00`) to seconds since the epoch.
pub fn rfc3339_to_unix(s: &str) -> Result<i64> {
    let s = s.trim();
    let bad = || anyhow!("\"{s}\" is not a date like 2026-10-13T00:00:00Z");
    let (date, rest) = s.split_once('T').ok_or_else(bad)?;
    let time = rest
        .strip_suffix('Z')
        .or_else(|| rest.strip_suffix("+00:00"))
        .ok_or_else(bad)?;
    let time = time.split('.').next().unwrap_or(time);
    let mut d = date.split('-');
    let (y, m, day) = (
        d.next()
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or_else(bad)?,
        d.next()
            .and_then(|x| x.parse::<u32>().ok())
            .ok_or_else(bad)?,
        d.next()
            .and_then(|x| x.parse::<u32>().ok())
            .ok_or_else(bad)?,
    );
    let mut t = time.split(':');
    let (h, mi, sec) = (
        t.next()
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or_else(bad)?,
        t.next()
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or_else(bad)?,
        t.next()
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or_else(bad)?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 {
        return Err(bad());
    }
    Ok(days_from_civil(y, m, day) * 86_400 + h * 3_600 + mi * 60 + sec)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Now, in seconds since the epoch.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates_come_out_right() {
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            rfc3339_to_unix("2000-03-01T00:00:00Z").unwrap(),
            951_868_800
        );
        assert_eq!(
            rfc3339_to_unix("2026-10-13T12:34:56Z").unwrap(),
            1_791_894_896
        );
        assert_eq!(
            rfc3339_to_unix("2026-10-13T12:34:56.250Z").unwrap(),
            1_791_894_896
        );
        assert_eq!(
            rfc3339_to_unix("2026-10-13T12:34:56+00:00").unwrap(),
            1_791_894_896
        );
    }

    #[test]
    fn anything_else_is_refused() {
        for s in [
            "",
            "2026-10-13",
            "2026-10-13 12:00:00",
            "2026-13-01T00:00:00Z",
            "yesterday",
        ] {
            assert!(rfc3339_to_unix(s).is_err(), "{s}");
        }
    }
}
