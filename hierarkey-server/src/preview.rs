// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use chrono::{Duration, NaiveTime, TimeZone};

/// Returns true when the preview is enabled, and expired.
pub fn preview_expired() -> bool {
    if preview_enabled() && (preview_expiry_date() <= chrono::Utc::now()) {
        return true;
    }
    false
}

/// Returns the expiry date for the preview. If the preview is not enabled, it returns a date far
/// in the future.
pub fn preview_expiry_date() -> chrono::DateTime<chrono::Utc> {
    if !preview_enabled() {
        return chrono::Utc::now() + Duration::days(365 * 100);
    }

    let build_secs = env!("BUILD_TIME_UNIX").parse().unwrap_or(0);
    let build_time = chrono::Utc
        .timestamp_opt(build_secs as i64, 0)
        .single()
        .unwrap_or_else(|| chrono::Utc::now() - Duration::days(1000));

    let expires_raw = build_time + Duration::days(30);
    let expires_date = expires_raw.date_naive();

    let end_of_day = NaiveTime::from_hms_opt(23, 59, 59).unwrap_or_default();
    chrono::Utc.from_utc_datetime(&expires_date.and_time(end_of_day))
}

/// Preview is behind the "preview" feature flag.
pub fn preview_enabled() -> bool {
    cfg!(feature = "preview")
}
