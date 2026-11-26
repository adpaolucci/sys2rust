#![forbid(unsafe_code)]

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use sha2::{Digest, Sha256};

/// 100-nanosecond intervals between 1601-01-01T00:00:00Z and 1970-01-01T00:00:00Z.
pub const WINDOWS_TO_UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// Convert a Windows 64-bit FILETIME (100ns ticks since 1601-01-01 UTC) into `DateTime<Utc>`.
pub fn filetime_to_datetime(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 || ft < WINDOWS_TO_UNIX_EPOCH_TICKS {
        return None;
    }
    let delta_ticks = ft - WINDOWS_TO_UNIX_EPOCH_TICKS;
    let secs = i64::try_from(delta_ticks / 10_000_000).ok()?;
    let nanos = u32::try_from((delta_ticks % 10_000_000) * 100).ok()?;
    DateTime::<Utc>::from_timestamp(secs, nanos)
}

/// Convert a `DateTime<Utc>` to Windows 64-bit FILETIME ticks.
pub fn datetime_to_filetime(dt: DateTime<Utc>) -> u64 {
    let secs = dt.timestamp();
    if secs < 0 {
        return 0;
    }
    let sub_nanos = u64::from(dt.timestamp_subsec_nanos());
    let unix_ticks = (secs as u64).saturating_mul(10_000_000).saturating_add(sub_nanos / 100);
    WINDOWS_TO_UNIX_EPOCH_TICKS.saturating_add(unix_ticks)
}

/// Parse a WMI DMTF timestamp (`yyyymmddHHMMSS.mmmmmmsUUU`, e.g. `20261123041530.123456+000`).
pub fn dmtf_to_datetime(s: &str) -> Option<DateTime<Utc>> {
    let trimmed = s.trim();
    if trimmed.len() < 14 {
        return None;
    }
    let year: i32 = trimmed.get(0..4)?.parse().ok()?;
    let month: u32 = trimmed.get(4..6)?.parse().ok()?;
    let day: u32 = trimmed.get(6..8)?.parse().ok()?;
    let hour: u32 = trimmed.get(8..10)?.parse().ok()?;
    let min: u32 = trimmed.get(10..12)?.parse().ok()?;
    let sec: u32 = trimmed.get(12..14)?.parse().ok()?;

    let mut micros: u32 = 0;
    let mut offset_minutes: i64 = 0;

    if trimmed.len() > 14 {
        let rest = &trimmed[14..];
        let after_dot = rest.strip_prefix('.').unwrap_or(rest);
        let sign_pos = after_dot.find(['+', '-']);
        let (frac_part, tz_part) = match sign_pos {
            Some(idx) => (&after_dot[..idx], Some(&after_dot[idx..])),
            None => (after_dot, None),
        };
        let frac_digits: String = frac_part.chars().take(6).filter(|c| c.is_ascii_digit()).collect();
        if !frac_digits.is_empty() {
            let padded = format!("{frac_digits:0<6}");
            micros = padded.parse().unwrap_or(0);
        }
        if let Some(tz) = tz_part
            && tz.len() >= 2
            && !tz[1..].contains('*')
        {
            offset_minutes = tz.parse::<i64>().unwrap_or(0);
        }
    }

    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let time = NaiveTime::from_hms_micro_opt(hour, min, sec, micros)?;
    let naive = NaiveDateTime::new(date, time);
    let delta = chrono::TimeDelta::try_minutes(offset_minutes)?;
    let utc_naive = naive.checked_sub_signed(delta)?;
    Some(Utc.from_utc_datetime(&utc_naive))
}

/// Parse an ISO-8601 / RFC3339 timestamp string cleanly.
pub fn iso8601_to_datetime(s: &str) -> Option<DateTime<Utc>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive));
    }
    None
}

/// Convert a 32-bit DOS/COFF Unix timestamp into `DateTime<Utc>`.
pub fn dos_timestamp_to_datetime(ts: u32) -> Option<DateTime<Utc>> {
    if ts == 0 {
        return None;
    }
    DateTime::<Utc>::from_timestamp(i64::from(ts), 0)
}

/// Decode a UTF-16LE byte slice (strips trailing NULs, safely ignores a trailing odd byte).
pub fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    let s = String::from_utf16_lossy(&units);
    s.trim_end_matches('\0').to_string()
}

/// Decode a NUL-terminated UTF-16LE string up to the first `\0` code unit.
pub fn decode_utf16le_nul(bytes: &[u8]) -> String {
    let mut units = Vec::new();
    for &pair in bytes.as_chunks::<2>().0 {
        let code = u16::from_le_bytes(pair);
        if code == 0 {
            break;
        }
        units.push(code);
    }
    String::from_utf16_lossy(&units)
}

pub fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_i32_le(bytes: &[u8], offset: usize) -> Option<i32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub fn encode_hex_lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Format a 16-byte Windows mixed-endian GUID into canonical `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` uppercase form.
pub fn format_guid_le(bytes: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Map common NTSTATUS values to symbolic names and descriptions.
pub fn format_ntstatus(status: i32) -> (&'static str, String) {
    let u = status as u32;
    let name = match u {
        0x0000_0000 => "STATUS_SUCCESS",
        0x0000_0103 => "STATUS_PENDING",
        0x8000_0005 => "STATUS_BUFFER_OVERFLOW",
        0x8000_0006 => "STATUS_NO_MORE_FILES",
        0xC000_0004 => "STATUS_INFO_LENGTH_MISMATCH",
        0xC000_0005 => "STATUS_ACCESS_VIOLATION",
        0xC000_0008 => "STATUS_INVALID_HANDLE",
        0xC000_000D => "STATUS_INVALID_PARAMETER",
        0xC000_0022 => "STATUS_ACCESS_DENIED",
        0xC000_0023 => "STATUS_BUFFER_TOO_SMALL",
        0xC000_0034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC000_003A => "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC000_0043 => "STATUS_SHARING_VIOLATION",
        0xC000_0139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        _ => "STATUS_UNKNOWN",
    };
    (name, format!("{name} ({u:#010x})"))
}

/// Decode Windows `ACCESS_MASK` values into human-readable permission flags.
pub struct AccessMaskDecoder;

impl AccessMaskDecoder {
    pub fn decode_file_access(mask: u32) -> String {
        let mut flags = Vec::new();
        if mask & 0x0000_0001 != 0 {
            flags.push("READ_DATA");
        }
        if mask & 0x0000_0002 != 0 {
            flags.push("WRITE_DATA");
        }
        if mask & 0x0000_0004 != 0 {
            flags.push("APPEND_DATA");
        }
        if mask & 0x0000_0020 != 0 {
            flags.push("EXECUTE");
        }
        if mask & 0x0001_0000 != 0 {
            flags.push("DELETE");
        }
        if mask & 0x0002_0000 != 0 {
            flags.push("READ_CONTROL");
        }
        if mask & 0x0004_0000 != 0 {
            flags.push("WRITE_DAC");
        }
        if mask & 0x0010_0000 != 0 {
            flags.push("SYNCHRONIZE");
        }
        if mask & 0x1000_0000 != 0 {
            flags.push("GENERIC_ALL");
        }
        if mask & 0x2000_0000 != 0 {
            flags.push("GENERIC_EXECUTE");
        }
        if mask & 0x4000_0000 != 0 {
            flags.push("GENERIC_WRITE");
        }
        if mask & 0x8000_0000 != 0 {
            flags.push("GENERIC_READ");
        }
        if flags.is_empty() {
            format!("{mask:#010x}")
        } else {
            format!("{} ({mask:#010x})", flags.join("|"))
        }
    }

    pub fn decode_process_access(mask: u32) -> String {
        let mut flags = Vec::new();
        if mask & 0x0001 != 0 {
            flags.push("TERMINATE");
        }
        if mask & 0x0010 != 0 {
            flags.push("VM_READ");
        }
        if mask & 0x0020 != 0 {
            flags.push("VM_WRITE");
        }
        if mask & 0x0040 != 0 {
            flags.push("DUP_HANDLE");
        }
        if mask & 0x0400 != 0 {
            flags.push("QUERY_INFO");
        }
        if mask & 0x1000 != 0 {
            flags.push("QUERY_LIMITED_INFO");
        }
        if flags.is_empty() {
            format!("{mask:#010x}")
        } else {
            format!("{} ({mask:#010x})", flags.join("|"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_roundtrip_and_guards() {
        assert!(filetime_to_datetime(0).is_none());
        assert!(filetime_to_datetime(1000).is_none());
        let dt = Utc.with_ymd_and_hms(2026, 11, 23, 4, 30, 0).unwrap();
        let ft = datetime_to_filetime(dt);
        let round = filetime_to_datetime(ft).unwrap();
        assert_eq!(round, dt);
    }

    #[test]
    fn dmtf_and_iso_parsers() {
        let dt = dmtf_to_datetime("20261123041530.500000+000").unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-11-23T04:15:30.500+00:00");

        let dt_off = dmtf_to_datetime("20261123000000.000000-300").unwrap();
        assert_eq!(dt_off, Utc.with_ymd_and_hms(2026, 11, 23, 5, 0, 0).unwrap());

        assert!(iso8601_to_datetime("2026-11-23T04:15:30Z").is_some());
        assert!(iso8601_to_datetime("").is_none());

        // Regression: extreme DMTF offset must return None instead of panicking
        assert!(dmtf_to_datetime("20261123000000.000000+99999999999999999").is_none());
        assert!(dmtf_to_datetime("20261123000000.000000-99999999999999999").is_none());
        assert!(dmtf_to_datetime("99991231235959.000000-999999999999").is_none());
    }

    #[test]
    fn utf16_guid_ntstatus_and_access_mask() {
        let raw = [b'A', 0, b'B', 0, 0, 0, b'C', 0, 0xFF];
        assert_eq!(decode_utf16le_nul(&raw), "AB");
        assert_eq!(decode_utf16le(&[b'X', 0, 0, 0]), "X");

        let guid = [
            0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        assert_eq!(format_guid_le(&guid), "{12345678-9ABC-DEF0-1122-334455667788}");

        let (sym, _) = format_ntstatus(0xC000_0022u32 as i32);
        assert_eq!(sym, "STATUS_ACCESS_DENIED");
        assert!(AccessMaskDecoder::decode_file_access(0x0012_0089).contains("READ_DATA"));
    }
}
