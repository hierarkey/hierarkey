// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::utils::formatting::fmt_date;
use chrono::{DateTime, Utc};
use hierarkey_core::{Labels, resources::Revision};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

/// A wrapper around DateTime<Utc> that provides a custom display format and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UtcDate(pub DateTime<Utc>);

impl std::fmt::Display for UtcDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.format("%Y-%m-%d %H:%M:%S UTC"))
    }
}

impl From<DateTime<Utc>> for UtcDate {
    fn from(dt: DateTime<Utc>) -> Self {
        UtcDate(dt)
    }
}

impl From<UtcDate> for DateTime<Utc> {
    fn from(utc_date: UtcDate) -> Self {
        utc_date.0
    }
}

impl Deref for UtcDate {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A wrapper around Option<DateTime<Utc>> that provides a custom display format and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionalUtcDate(pub Option<DateTime<Utc>>);

impl std::fmt::Display for OptionalUtcDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(dt) => write!(f, "{}", dt.format("%Y-%m-%d %H:%M:%S UTC")),
            None => write!(f, "Never"),
        }
    }
}

impl From<Option<DateTime<Utc>>> for OptionalUtcDate {
    fn from(opt: Option<DateTime<Utc>>) -> Self {
        OptionalUtcDate(opt)
    }
}

/// A wrapper around Option<String> that provides a custom display format and serialization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OptionalString(pub Option<String>);

impl std::fmt::Display for OptionalString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(s) => write!(f, "{s}"),
            None => write!(f, "N/A"),
        }
    }
}

/// Displays a Labels map as a comma-separated list of key=value pairs, sorted by key.
/// If the map is empty, returns "-".
pub fn display_labels(labels: &Labels) -> String {
    if labels.is_empty() {
        "-".to_string()
    } else {
        let mut sorted: Vec<_> = labels.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);

        sorted
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>()
            .join(", ")
    }
}

/// Displays an Option<DateTime<Utc>>, returning the date as string if Some, or "-" if None.
pub fn display_opt_date(o: &Option<DateTime<Utc>>) -> String {
    match o {
        Some(dt) => fmt_date(*dt),
        None => "-".to_string(),
    }
}

/// Displays an Option<String>, returning the string if Some, or "-" if None.
pub fn display_option(o: &Option<String>) -> String {
    match o {
        Some(s) => s.clone(),
        None => "-".to_string(),
    }
}

/// Displays an Option<Revision>, returning the revision as string if Some, or "N/A" if None.
pub fn display_revision(o: &Option<Revision>) -> String {
    match o {
        Some(r) => r.to_string(),
        None => "N/A".to_string(),
    }
}
