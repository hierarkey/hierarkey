// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use chrono::{DateTime, Utc};
use std::str::FromStr;
use std::time::Duration;

/// Accepts either an absolute timestamp (RFC3339) or a relative duration (e.g. 7d, 12h, 30m).
/// Examples:
///   - "2026-01-27T09:00:00Z"
///   - "7d"
///   - "12h"
#[derive(Debug, Clone)]
pub enum TimeExpr {
    At(DateTime<Utc>),
    Ago(Duration),
}

impl TimeExpr {
    /// Resolve relative durations against "now"
    pub fn resolve(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            TimeExpr::At(dt) => *dt,
            TimeExpr::Ago(d) => now - chrono::Duration::from_std(*d).unwrap_or(chrono::Duration::zero()),
        }
    }
}

impl FromStr for TimeExpr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try RFC3339 timestamp first
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return Ok(TimeExpr::At(dt.with_timezone(&Utc)));
        }

        parse_duration_with_days(s).map(TimeExpr::Ago)
    }
}

/// Parses durations with a simple extension: supports 'd' (days).
/// Accepts: "10s", "15m", "12h", "7d", and combinations like "1h30m".
pub fn parse_duration_with_days(input: &str) -> Result<Duration, String> {
    // Fast path: if no 'd', use humantime directly.
    if !input.contains('d') {
        return humantime::parse_duration(input).map_err(|e| e.to_string());
    }

    // Simple parser for sequences like "7d12h30m"
    // Supported suffixes: d, h, m, s
    let mut total = Duration::from_secs(0);
    let mut num_buf = String::new();

    for ch in input.chars() {
        if ch.is_ascii_digit() {
            num_buf.push(ch);
            continue;
        }

        let n: u64 = num_buf
            .parse()
            .map_err(|_| format!("Invalid duration number in '{input}'"))?;
        num_buf.clear();

        match ch {
            'd' => total = total.saturating_add(Duration::from_secs(n.saturating_mul(24 * 60 * 60))),
            'h' => total = total.saturating_add(Duration::from_secs(n.saturating_mul(60 * 60))),
            'm' => total = total.saturating_add(Duration::from_secs(n.saturating_mul(60))),
            's' => total = total.saturating_add(Duration::from_secs(n)),
            _ => return Err(format!("Invalid duration unit '{ch}' in '{input}' (use d/h/m/s)")),
        }
    }

    if !num_buf.is_empty() {
        return Err(format!("Duration '{input}' ended unexpectedly (missing unit)"));
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::time::Duration;

    #[test]
    fn duration_seconds() {
        assert_eq!(parse_duration_with_days("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn duration_minutes() {
        assert_eq!(parse_duration_with_days("15m").unwrap(), Duration::from_secs(15 * 60));
    }

    #[test]
    fn duration_hours() {
        assert_eq!(parse_duration_with_days("12h").unwrap(), Duration::from_secs(12 * 3600));
    }

    #[test]
    fn duration_days() {
        assert_eq!(parse_duration_with_days("7d").unwrap(), Duration::from_secs(7 * 24 * 3600));
    }

    #[test]
    fn duration_combined() {
        // "1d12h30m" = 86400 + 43200 + 1800 = 131400 seconds
        assert_eq!(
            parse_duration_with_days("1d12h30m").unwrap(),
            Duration::from_secs(86400 + 43200 + 1800)
        );
    }

    #[test]
    fn duration_invalid_unit() {
        assert!(parse_duration_with_days("5x").is_err());
    }

    #[test]
    fn duration_missing_unit() {
        assert!(parse_duration_with_days("42").is_err());
    }

    #[test]
    fn duration_empty_string() {
        assert!(parse_duration_with_days("").is_err());
    }

    #[test]
    fn time_expr_parses_rfc3339() {
        let expr: TimeExpr = "2026-01-27T09:00:00Z".parse().unwrap();
        assert!(matches!(expr, TimeExpr::At(_)));
        if let TimeExpr::At(dt) = expr {
            assert_eq!(dt, Utc.with_ymd_and_hms(2026, 1, 27, 9, 0, 0).unwrap());
        }
    }

    #[test]
    fn time_expr_parses_relative_duration() {
        let expr: TimeExpr = "7d".parse().unwrap();
        assert!(matches!(expr, TimeExpr::Ago(_)));
        if let TimeExpr::Ago(d) = expr {
            assert_eq!(d, Duration::from_secs(7 * 24 * 3600));
        }
    }

    #[test]
    fn time_expr_invalid_is_error() {
        assert!("not-a-date-or-duration".parse::<TimeExpr>().is_err());
        assert!("42".parse::<TimeExpr>().is_err());
    }

    #[test]
    fn resolve_absolute_returns_exact_time() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 27, 9, 0, 0).unwrap();
        let expr = TimeExpr::At(dt);
        let now = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
        assert_eq!(expr.resolve(now), dt);
    }

    #[test]
    fn resolve_relative_subtracts_from_now() {
        let now = Utc.with_ymd_and_hms(2026, 1, 8, 0, 0, 0).unwrap();
        let expr = TimeExpr::Ago(Duration::from_secs(7 * 24 * 3600));
        let expected = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(expr.resolve(now), expected);
    }
}
