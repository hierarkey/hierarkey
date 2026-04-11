// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// License tier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Community,
    Commercial,
}

/// Individual features that can be enabled by a commercial license.
/// Community edition never has any features enabled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    /// Full audit logging: event storage, chain integrity, query API, and export.
    Audit,
    /// Federated authentication: OIDC and Kubernetes TokenReview workload identity,
    /// plus linking/unlinking federated identities on service accounts.
    FederatedAuth,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Community => write!(f, "Community"),
            Tier::Commercial => write!(f, "Commercial"),
        }
    }
}

/// The signed payload — all fields of the license except the signature itself.
/// This is the canonical form used for signature verification.
/// IMPORTANT: field order here is significant — serde_json serializes struct fields in
/// declaration order, so the signing payload is always deterministic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub version: u32,
    pub license_id: String,
    pub key_id: String,
    pub tier: Tier,
    pub licensee: String,
    pub issued_at: NaiveDate,
    pub expires_at: NaiveDate,
    /// Features enabled by this license. Uses default + skip_serializing_if so that
    /// old licenses (without this field) round-trip cleanly through signature verification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<Feature>,
}

impl LicensePayload {
    /// Whether this license has expired
    pub fn is_expired(&self) -> bool {
        let today = chrono::Utc::now().date_naive();
        today > self.expires_at
    }
}

/// Full license data including the Ed25519 signature.
/// The `signature` field is a base64url-encoded Ed25519 signature over the
/// canonical JSON serialization of the `LicensePayload` fields (all fields except `signature`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseData {
    #[serde(flatten)]
    pub payload: LicensePayload,
    pub signature: String,
}

/// The effective license after verification and fallback logic.
/// Community fallback is applied when:
/// - No license is present
/// - The license signature is invalid
/// - The license has expired
#[derive(Debug, Clone)]
pub struct EffectiveLicense {
    pub tier: Tier,
    pub licensee: Option<String>,
    pub expires_at: Option<NaiveDate>,
    pub license_id: Option<String>,
    pub is_community_fallback: bool,
    /// Features explicitly enabled by this license. Always empty for community.
    pub features: Vec<Feature>,
    /// Features from a recently-expired license still available during the grace period.
    /// Empty when there is no grace period (no license ever installed, or invalid license).
    pub grace_features: Vec<Feature>,
    /// End of the grace period (inclusive). `None` means no grace period applies.
    /// Set to `expires_at + 7 days` when a valid license has just expired.
    pub grace_period_ends: Option<NaiveDate>,
}

impl EffectiveLicense {
    /// The Community fallback license — no license file needed, no features, no grace period.
    pub fn community() -> Self {
        Self {
            tier: Tier::Community,
            licensee: None,
            expires_at: None,
            license_id: None,
            is_community_fallback: true,
            features: vec![],
            grace_features: vec![],
            grace_period_ends: None,
        }
    }

    /// Returns true if the license explicitly enables the given feature.
    /// Community edition always returns false regardless of the feature requested.
    pub fn has_feature(&self, feature: &Feature) -> bool {
        if self.is_community_fallback {
            return false;
        }
        self.features.contains(feature)
    }

    /// Like `has_feature`, but also returns true during the 7-day grace period after expiry.
    ///
    /// Use this for write operations (e.g. audit log writes) that should continue briefly
    /// after license expiry to avoid data gaps during renewal. Read/query operations should
    /// use the strict `has_feature` instead.
    pub fn has_feature_or_grace(&self, feature: &Feature) -> bool {
        if self.has_feature(feature) {
            return true;
        }
        if let Some(ends) = self.grace_period_ends
            && chrono::Utc::now().date_naive() <= ends
            && self.grace_features.contains(feature)
        {
            return true;
        }
        false
    }
}
