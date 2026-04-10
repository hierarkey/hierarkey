// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use chrono::NaiveDate;
use hierarkey_core::license::{EffectiveLicense, Tier};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// DTO for the license status API response.
/// Defined here so both the community CLI and the commercial license handler can share it.
#[derive(Debug, Serialize, Deserialize)]
pub struct LicenseStatusDto {
    pub tier: Tier,
    pub licensee: Option<String>,
    pub license_id: Option<String>,
    pub expires_at: Option<NaiveDate>,
    pub is_community_fallback: bool,
    pub is_expired: bool,
}

/// Minimal license service stub for the community edition.
///
/// Holds the current `EffectiveLicense` (defaults to `EffectiveLicense::community()`).
/// The commercial `LicenseExtension` calls `set_effective` after verifying a license at startup
/// and whenever a license is installed or removed via the API.
pub struct LicenseService {
    effective: Arc<RwLock<EffectiveLicense>>,
}

impl LicenseService {
    pub fn new() -> Self {
        Self {
            effective: Arc::new(RwLock::new(EffectiveLicense::community())),
        }
    }

    /// Return the current effective license.
    pub fn get_effective_license(&self) -> EffectiveLicense {
        self.effective.read().clone()
    }

    /// Install a verified license as the current effective license.
    /// Called by the commercial `LicenseExtension` after signature verification.
    pub fn set_effective(&self, license: EffectiveLicense) {
        *self.effective.write() = license;
    }
}

impl Default for LicenseService {
    fn default() -> Self {
        Self::new()
    }
}
