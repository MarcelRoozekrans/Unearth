//! Timestamp conversion and application helpers shared by the undelete
//! backends, so recovered files keep their original modification (and access)
//! times.
//!
//! Each filesystem stores time differently:
//!
//! * ext uses 32-bit Unix seconds (UTC).
//! * NTFS uses 64-bit Windows `FILETIME` (100 ns ticks since 1601, UTC).
//! * FAT/exFAT use packed "DOS" date+time fields in **local** time; without a
//!   recorded time zone we treat them as UTC, which can be off by the machine's
//!   offset. The date is preserved exactly.

use std::fs::File;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Apply modified/accessed times to a freshly written file. Best effort: any
/// error (e.g. an unsupported platform) is ignored.
pub fn apply(file: &File, modified: Option<SystemTime>, accessed: Option<SystemTime>) {
    if modified.is_none() && accessed.is_none() {
        return;
    }
    let mut times = std::fs::FileTimes::new();
    if let Some(m) = modified {
        times = times.set_modified(m);
    }
    if let Some(a) = accessed {
        times = times.set_accessed(a);
    }
    let _ = file.set_times(times);
}

/// 32-bit Unix seconds (ext) to a `SystemTime`.
pub fn from_unix(secs: u32) -> Option<SystemTime> {
    if secs == 0 {
        None
    } else {
        Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
    }
}

/// Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC) to a `SystemTime`.
pub fn from_filetime(ft: u64) -> Option<SystemTime> {
    if ft == 0 {
        return None;
    }
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600; // 1601-01-01 .. 1970-01-01
    let secs_total = ft / 10_000_000;
    if secs_total < EPOCH_DIFF_SECS {
        return None;
    }
    let unix = secs_total - EPOCH_DIFF_SECS;
    let nanos = (ft % 10_000_000) * 100;
    Some(UNIX_EPOCH + Duration::new(unix, nanos as u32))
}

/// Packed DOS date+time (FAT) to a `SystemTime`, treated as UTC.
///
/// `date`: bits 0-4 day, 5-8 month, 9-15 year since 1980.
/// `time`: bits 0-4 seconds/2, 5-10 minute, 11-15 hour.
pub fn from_dos(date: u16, time: u16) -> Option<SystemTime> {
    if date == 0 {
        return None;
    }
    let day = (date & 0x1F) as i64;
    let month = ((date >> 5) & 0x0F) as i64;
    let year = 1980 + ((date >> 9) & 0x7F) as i64;
    let sec = ((time & 0x1F) * 2) as i64;
    let min = ((time >> 5) & 0x3F) as i64;
    let hour = ((time >> 11) & 0x1F) as i64;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec;
    if secs < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// exFAT packs the date in the high 16 bits and the time in the low 16 bits.
pub fn from_exfat(ts: u32) -> Option<SystemTime> {
    if ts == 0 {
        return None;
    }
    from_dos((ts >> 16) as u16, (ts & 0xFFFF) as u16)
}

/// Days from 1970-01-01 to a civil (proleptic Gregorian) date.
/// Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_roundtrip() {
        let t = from_unix(1_600_000_000).unwrap();
        let d = t.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(d.as_secs(), 1_600_000_000);
    }

    #[test]
    fn dos_epoch_is_1980() {
        // 1980-01-01 00:00:00 => date day=1 month=1 year=0.
        let date = (1 << 5) | 1; // month=1, day=1, year=0
        let t = from_dos(date, 0).unwrap();
        let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 315_532_800); // 1980-01-01 UTC
    }

    #[test]
    fn filetime_unix_epoch() {
        // FILETIME for 1970-01-01 is exactly EPOCH_DIFF_SECS * 10^7.
        let ft = 11_644_473_600u64 * 10_000_000;
        let t = from_filetime(ft).unwrap();
        assert_eq!(t.duration_since(UNIX_EPOCH).unwrap().as_secs(), 0);
    }
}
