//! 通用工具：ip4 编解码、时间格式化。

/// u32 BE → "a.b.c.d"。
pub fn ip4_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

/// "a.b.c.d" → u32 BE（非法返回 None）。
pub fn ip4_from_string(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut ip: u32 = 0;
    for p in parts {
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        ip = (ip << 8) | n;
    }
    Some(ip)
}

/// 纳秒时间戳 → RFC3339（UTC）。
pub fn ts_to_rfc3339(ts_ns: u64) -> String {
    let secs = (ts_ns / 1_000_000_000) as i64;
    let nanos = (ts_ns % 1_000_000_000) as u32;
    match chrono_like(secs, nanos) {
        Some(s) => s,
        None => format!("{}", ts_ns),
    }
}

// 不引入 chrono：手写 UTC 秒转换（P0 最小实现，够用即可）。
fn chrono_like(secs: i64, nanos: u32) -> Option<String> {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days)?;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        y, m, d, hh, mm, ss, nanos
    ))
}

// Howard Hinnant 的 civil_from_days 算法。
fn civil_from_days(z: i64) -> Option<(i64, u32, u32)> {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    Some((y, m, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip4_roundtrip() {
        assert_eq!(ip4_from_string("192.168.0.1"), Some(0xC0A8_0001));
        assert_eq!(ip4_to_string(0xC0A8_0001), "192.168.0.1");
        assert_eq!(ip4_to_string(0x0A00_0002), "10.0.0.2");
        assert!(ip4_from_string("999.1.1.1").is_none());
        assert!(ip4_from_string("1.2.3").is_none());
    }

    #[test]
    fn ts_format() {
        assert_eq!(ts_to_rfc3339(0), "1970-01-01T00:00:00.000000000Z");
        // 2000-01-01T00:00:00Z = 946684800s
        assert_eq!(
            ts_to_rfc3339(946_684_800 * 1_000_000_000),
            "2000-01-01T00:00:00.000000000Z"
        );
    }
}
