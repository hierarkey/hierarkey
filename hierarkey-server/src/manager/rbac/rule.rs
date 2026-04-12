// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::short_id::ShortId;
use crate::rbac::spec::RuleSpec;
use crate::rbac::{
    AccountPattern, NamespacePattern, Permission, PolicyEffect, RuleId, SecretPattern, Target, TargetKind, WhereExpr,
};
use crate::service::account::AccountId;
use chrono::{DateTime, Utc};
use hierarkey_core::{CkError, Metadata};
use std::str::FromStr;

// --------------------------------------------------------------------------------------------

/// A Rule defines a permission granted or denied to a target.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: RuleId,
    pub short_id: ShortId,
    pub spec: RuleSpec,
    pub metadata: Metadata,
    pub created_at: DateTime<Utc>,
    pub created_by: AccountId,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<AccountId>,
    /// Row HMAC carried from the DB row - not exposed via API, used for integrity checks.
    pub row_hmac: Option<String>,
}

// --------------------------------------------------------------------------------------------

/// RuleRow represents the DB row for a Rule. We need a bit of conversion between this and Rule.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RuleRow {
    pub id: RuleId,
    pub short_id: ShortId,

    pub raw_spec: Option<String>, // complete raw spec
    pub spec_version: i32,        // for future-proofing if we change the spec format

    pub effect: PolicyEffect, // allow | deny
    pub permission: String,   // secret:read | namespace:* | all

    pub target_kind: TargetKind,     // secret | namespace | account | all
    pub pattern_raw: Option<String>, // the raw pattern string (e.g. "/prod/**" or "john.*")

    pub condition: Option<serde_json::Value>, // stored as JSON in the DB, deserialized into WhereExpr in Rule

    pub metadata: Metadata, // Optional metadata like labels, annotations, description etc.

    pub created_at: DateTime<Utc>,
    pub created_by: AccountId,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<AccountId>,

    /// BLAKE3-keyed HMAC over the security-critical fields of this row.
    /// `None` when the column was not selected or the row predates HMAC enforcement.
    #[sqlx(default)]
    pub row_hmac: Option<String>,
}

impl TryFrom<RuleRow> for Rule {
    type Error = CkError;

    fn try_from(r: RuleRow) -> Result<Self, Self::Error> {
        let permission = Permission::from_str(&r.permission)?;

        let base = r.pattern_raw.unwrap_or_default();

        let target = match r.target_kind {
            TargetKind::All => Target::All,
            TargetKind::Platform => Target::Platform,
            TargetKind::Namespace => Target::Namespace(NamespacePattern::from_str(&base)?),
            TargetKind::Secret => Target::Secret(SecretPattern::from_str(&base)?),
            TargetKind::Account => Target::Account(AccountPattern::from_str(&base)?),
        };

        let condition: Option<WhereExpr> = match r.condition {
            None => None,
            Some(v) => Some(serde_json::from_value(v)?),
        };

        Ok(Rule {
            id: r.id,
            short_id: r.short_id,
            spec: RuleSpec {
                effect: r.effect,
                permission,
                target,
                condition,
            },
            metadata: r.metadata,
            created_at: r.created_at,
            created_by: r.created_by,
            updated_at: r.updated_at,
            updated_by: r.updated_by,
            row_hmac: r.row_hmac,
        })
    }
}
