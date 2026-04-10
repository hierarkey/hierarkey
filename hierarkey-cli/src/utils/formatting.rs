// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! Utility functions for formatting data for display in the CLI.
//! Includes functions for formatting booleans, dates, sizes, labels, and user references.

use chrono::{DateTime, Local, Utc};
use chrono_tz::Tz;
use hierarkey_core::Labels;
use hierarkey_server::api::v1::dto::global::AccountRefDto;
use std::env;

/// Formats a boolean as one of two provided strings.
/// Useful for displaying status in tables, e.g. "Yes"/"No", "Active"/"Inactive".
pub fn fmt_bool(b: bool, t_val: &str, f_val: &str) -> String {
    if b { t_val.to_string() } else { f_val.to_string() }
}

/// Clips a string to max characters, adding "..." if clipped.
/// Total returned length is <= max.
pub fn clip(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }

    // Already fits (by chars, not bytes)
    if s.chars().count() <= max {
        return s.to_string();
    }

    // Not enough room for "...", just return max dots
    if max <= 3 {
        return ".".repeat(max);
    }

    let keep = max - 3;
    let mut out = String::with_capacity(max);
    out.extend(s.chars().take(keep));
    out.push_str("...");
    out
}

/// Formats an optional DateTime<Utc>. If None, returns the provided default string.
pub fn fmt_opt_date(dt: Option<DateTime<Utc>>, default: &str) -> String {
    match dt {
        Some(d) => fmt_date(d),
        None => default.to_string(),
    }
}

/// Formats a size in bytes into a human-readable string (B, KB, MB). We don't need more than MB
/// for CLI display.
pub fn fmt_size(size: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;

    if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{size} B")
    }
}

/// Formats a DateTime<Utc> into a string with local timezone abbreviation.
pub fn fmt_date(dt: DateTime<Utc>) -> String {
    fmt_date_with_tz(dt, env::var("TZ").ok().as_deref())
}

/// Formats a DateTime<Utc> into a string with the specified timezone abbreviation, falling back
/// to local time with numeric offset if the timezone is invalid or not provided.
fn fmt_date_with_tz(dt: DateTime<Utc>, tz_str: Option<&str>) -> String {
    if let Some(s) = tz_str
        && let Ok(tz) = s.parse::<Tz>()
    {
        return dt.with_timezone(&tz).format("%Y-%m-%d %H:%M:%S %Z").to_string();
    }

    // Fallback: system local without offset (keeps output width consistent)
    dt.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Formats a DateTime<Utc> as a human-readable age (e.g. "1d 2h", "3h 15m", "45s").
pub fn fmt_age(created_at: DateTime<Utc>) -> String {
    let now = Utc::now();
    let mut secs = now.signed_duration_since(created_at).num_seconds().max(0);

    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;
    const MONTH: i64 = 30 * DAY;
    const YEAR: i64 = 365 * DAY;

    let units: &[(&str, i64)] = &[
        ("y", YEAR),
        ("mo", MONTH),
        ("d", DAY),
        ("h", HOUR),
        ("m", MINUTE),
        ("s", 1),
    ];

    let mut parts: Vec<String> = Vec::with_capacity(2);
    for (suffix, unit_secs) in units {
        if parts.len() == 2 {
            break;
        }
        if secs >= *unit_secs {
            let n = secs / unit_secs;
            secs %= unit_secs;
            parts.push(format!("{n}{suffix}"));
        }
    }

    if parts.is_empty() {
        "0s".to_string()
    } else {
        parts.join(" ")
    }
}

/// Parses a human-friendly TTL string (e.g. "60s", "5m", "2h", "1d") into minutes.
/// Returns an error string if the input is invalid or zero.
pub fn parse_ttl(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("TTL must not be empty".into());
    }

    let (digits, suffix) = s.split_at(s.len() - s.trim_start_matches(|c: char| !c.is_alphabetic()).len());
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid TTL value '{s}': expected a number followed by a unit (e.g. 60s, 5m, 2h, 1d)"))?;

    let minutes: u64 = match suffix {
        "s" => {
            if n == 0 {
                return Err("TTL must be greater than zero".into());
            }
            // Round up: 1s..59s → 1 minute
            n.div_ceil(60)
        }
        "m" | "" => n,
        "h" => n * 60,
        "d" => n * 60 * 24,
        other => return Err(format!("unknown TTL unit '{other}': use s, m, h, or d")),
    };

    if minutes == 0 {
        return Err("TTL must be greater than zero".into());
    }
    if minutes > u32::MAX as u64 {
        return Err(format!("TTL '{s}' is too large"));
    }

    Ok(minutes as u32)
}

/// Formats a set of labels (key-value pairs) into a sorted, comma-separated string.
pub fn fmt_labels(labels: &Labels) -> String {
    if labels.is_empty() {
        return "-".to_string();
    }

    let mut parts: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.sort();
    parts.join(", ")
}

/// Formats a user reference by showing the account name if available, otherwise the account ID.
pub fn fmt_user_ref(u: &AccountRefDto) -> String {
    if !u.account_name.to_string().is_empty() {
        u.account_name.to_string()
    } else {
        u.account_id.to_string() // Assumes this is a short ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ttl_seconds() {
        assert_eq!(parse_ttl("60s").unwrap(), 1);
        assert_eq!(parse_ttl("1s").unwrap(), 1); // rounds up
        assert_eq!(parse_ttl("120s").unwrap(), 2);
        assert_eq!(parse_ttl("90s").unwrap(), 2); // rounds up
    }

    #[test]
    fn test_parse_ttl_minutes() {
        assert_eq!(parse_ttl("1m").unwrap(), 1);
        assert_eq!(parse_ttl("30m").unwrap(), 30);
        assert_eq!(parse_ttl("60m").unwrap(), 60);
    }

    #[test]
    fn test_parse_ttl_hours() {
        assert_eq!(parse_ttl("1h").unwrap(), 60);
        assert_eq!(parse_ttl("2h").unwrap(), 120);
        assert_eq!(parse_ttl("10h").unwrap(), 600);
    }

    #[test]
    fn test_parse_ttl_days() {
        assert_eq!(parse_ttl("1d").unwrap(), 1440);
        assert_eq!(parse_ttl("7d").unwrap(), 10080);
    }

    #[test]
    fn test_parse_ttl_errors() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("0m").is_err());
        assert!(parse_ttl("0s").is_err());
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("10x").is_err());
        assert!(parse_ttl("-1m").is_err());
    }
    use chrono::{TimeZone, Utc};
    use std::collections::HashMap;

    #[test]
    fn test_fmt_bool_true() {
        assert_eq!(fmt_bool(true, "Yes", "No"), "Yes");
        assert_eq!(fmt_bool(true, "Active", "Inactive"), "Active");
        assert_eq!(fmt_bool(true, "✓", "✗"), "✓");
    }

    #[test]
    fn test_fmt_bool_false() {
        assert_eq!(fmt_bool(false, "Yes", "No"), "No");
        assert_eq!(fmt_bool(false, "Active", "Inactive"), "Inactive");
        assert_eq!(fmt_bool(false, "✓", "✗"), "✗");
    }

    #[test]
    fn test_fmt_bool_empty_strings() {
        assert_eq!(fmt_bool(true, "", ""), "");
        assert_eq!(fmt_bool(false, "", ""), "");
    }

    #[test]
    fn test_clip_no_clip_needed() {
        assert_eq!(clip("abc", 3), "abc");
        assert_eq!(clip("abc", 10), "abc");
    }

    #[test]
    fn test_clip_clips_and_adds_suffix() {
        let out = clip("abcdefghijklmnopqrstuvwxyz", 10);
        assert!(out.chars().count() <= 10, "clip() output exceeded max: {}", out.chars().count());
        assert!(out.contains("..."), "clip() should add '...' when clipped");
        assert_eq!(out, "abcdefg...");
    }

    #[test]
    fn test_clip_exact_boundary() {
        assert_eq!(clip("abcd", 4), "abcd");
        assert_eq!(clip("abcde", 4), "a...");
    }

    #[test]
    fn test_clip_small_max() {
        assert_eq!(clip("abcdef", 0), "");
        assert_eq!(clip("abcdef", 1), ".");
        assert_eq!(clip("abcdef", 2), "..");
        assert_eq!(clip("abcdef", 3), "...");
    }

    #[test]
    fn test_clip_empty_string() {
        assert_eq!(clip("", 0), "");
        assert_eq!(clip("", 5), "");
        assert_eq!(clip("", 100), "");
    }

    #[test]
    fn test_clip_unicode_does_not_panic() {
        let result = clip("übergrößenträger", 8);
        assert!(result.chars().count() <= 8);
    }

    #[test]
    fn test_clip_unicode_multibyte() {
        let result = clip("日本語テスト", 5);
        assert!(result.chars().count() <= 5);
        assert_eq!(result, "日本...");
    }

    #[test]
    fn test_clip_emoji() {
        let result = clip("🎉🎊🎁🎈🎂", 4);
        assert!(result.chars().count() <= 4);
        assert_eq!(result, "🎉...");
    }

    #[test]
    fn test_fmt_size_bytes() {
        assert_eq!(fmt_size(0), "0 B");
        assert_eq!(fmt_size(42), "42 B");
        assert_eq!(fmt_size(1023), "1023 B");
    }

    #[test]
    fn test_fmt_size_kb() {
        assert_eq!(fmt_size(1024), "1.00 KB");
        assert_eq!(fmt_size(1536), "1.50 KB");
        assert_eq!(fmt_size(10 * 1024), "10.00 KB");
    }

    #[test]
    fn test_fmt_size_kb_boundary() {
        assert_eq!(fmt_size(1024 * 1024 - 1), "1024.00 KB");
    }

    #[test]
    fn test_fmt_size_mb() {
        assert_eq!(fmt_size(1024 * 1024), "1.00 MB");
        assert_eq!(fmt_size(2 * 1024 * 1024), "2.00 MB");
        assert_eq!(fmt_size(1024 * 1024 + 512 * 1024), "1.50 MB");
    }

    #[test]
    fn test_fmt_size_large_mb() {
        assert_eq!(fmt_size(100 * 1024 * 1024), "100.00 MB");
        assert_eq!(fmt_size(1024 * 1024 * 1024), "1024.00 MB");
    }

    #[test]
    fn test_fmt_date_utc() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 3, 11, 42, 32).unwrap();
        assert_eq!(fmt_date_with_tz(dt, Some("UTC")), "2026-01-03 11:42:32 UTC");
    }

    #[test]
    fn test_fmt_date_amsterdam_winter_time() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 3, 11, 42, 32).unwrap();
        let out = fmt_date_with_tz(dt, Some("Europe/Amsterdam"));
        assert!(out.starts_with("2026-01-03 12:42:32 "), "unexpected formatted time: {out}");
        assert!(out.ends_with("CET"), "expected CET, got: {out}");
    }

    #[test]
    fn test_fmt_date_amsterdam_summer_time() {
        let dt = Utc.with_ymd_and_hms(2026, 7, 15, 11, 42, 32).unwrap();
        let out = fmt_date_with_tz(dt, Some("Europe/Amsterdam"));
        assert!(out.starts_with("2026-07-15 13:42:32 "), "unexpected formatted time: {out}");
        assert!(out.ends_with("CEST"), "expected CEST, got: {out}");
    }

    #[test]
    fn test_fmt_date_new_york() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 3, 17, 0, 0).unwrap();
        let out = fmt_date_with_tz(dt, Some("America/New_York"));
        assert!(out.contains("12:00:00"), "expected noon EST, got: {out}");
        assert!(out.ends_with("EST"), "expected EST, got: {out}");
    }

    #[test]
    fn test_fmt_date_invalid_tz_fallback() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 3, 11, 42, 32).unwrap();
        let out = fmt_date_with_tz(dt, Some("Invalid/Timezone"));
        // Should fall back to local time without offset
        assert!(out.contains("2026-01-03"), "date should be present: {out}");
        assert!(!out.contains('+'), "offset should not be present: {out}");
    }

    #[test]
    fn test_fmt_date_no_tz_fallback() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 3, 11, 42, 32).unwrap();
        let out = fmt_date_with_tz(dt, None);
        assert!(out.contains("2026-01-03"), "date should be present: {out}");
        assert!(!out.contains('+'), "offset should not be present: {out}");
    }

    #[test]
    fn test_fmt_date_midnight() {
        let dt = Utc.with_ymd_and_hms(2026, 12, 31, 0, 0, 0).unwrap();
        assert_eq!(fmt_date_with_tz(dt, Some("UTC")), "2026-12-31 00:00:00 UTC");
    }

    #[test]
    fn test_fmt_date_end_of_day() {
        let dt = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(fmt_date_with_tz(dt, Some("UTC")), "2026-12-31 23:59:59 UTC");
    }

    #[test]
    fn test_fmt_opt_date_some_and_none() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 3, 11, 42, 32).unwrap();
        assert_eq!(fmt_date_with_tz(dt, Some("UTC")), "2026-01-03 11:42:32 UTC");
        assert_eq!(fmt_opt_date(None, "-"), "-");
        assert_eq!(fmt_opt_date(None, "N/A"), "N/A");
    }

    #[test]
    fn test_fmt_opt_date_various_defaults() {
        assert_eq!(fmt_opt_date(None, ""), "");
        assert_eq!(fmt_opt_date(None, "Never"), "Never");
        assert_eq!(fmt_opt_date(None, "Not set"), "Not set");
    }

    #[test]
    fn test_fmt_labels_empty() {
        let labels: Labels = HashMap::new();
        assert_eq!(fmt_labels(&labels), "-");
    }

    #[test]
    fn test_fmt_labels_single() {
        let mut labels: Labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        assert_eq!(fmt_labels(&labels), "env=prod");
    }

    #[test]
    fn test_fmt_labels_multiple_sorted() {
        let mut labels: Labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        labels.insert("app".to_string(), "api".to_string());
        labels.insert("team".to_string(), "backend".to_string());
        // Should be sorted alphabetically by key
        assert_eq!(fmt_labels(&labels), "app=api, env=prod, team=backend");
    }

    #[test]
    fn test_fmt_labels_special_characters() {
        let mut labels: Labels = HashMap::new();
        labels.insert("key-with-dash".to_string(), "value_with_underscore".to_string());
        labels.insert("key.with.dots".to_string(), "value/with/slashes".to_string());
        let result = fmt_labels(&labels);
        assert!(result.contains("key-with-dash=value_with_underscore"));
        assert!(result.contains("key.with.dots=value/with/slashes"));
    }

    #[test]
    fn test_fmt_labels_empty_value() {
        let mut labels: Labels = HashMap::new();
        labels.insert("key".to_string(), "".to_string());
        assert_eq!(fmt_labels(&labels), "key=");
    }
}
