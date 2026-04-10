// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::short_id::ShortId;
use crate::manager::rbac::rule::Rule;
use crate::rbac::RoleId;
use crate::service::account::AccountId;
use chrono::{DateTime, Utc};
use hierarkey_core::Metadata;

pub struct AccountBindings {
    pub roles: Vec<RoleWithRules>,
    pub direct_rules: Vec<Rule>,
}

/// A Role is a named group of rules.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RoleRow {
    pub id: RoleId,
    pub short_id: ShortId,
    pub name: String, // e.g. "platform:admin"
    pub metadata: Metadata,
    pub is_system: bool,

    pub created_at: DateTime<Utc>,
    pub created_by: AccountId,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<AccountId>,
}

/// A Role is a named group of rules.
#[derive(Debug, Clone)]
pub struct Role {
    pub id: RoleId,
    pub short_id: ShortId,
    pub name: String, // e.g. "platform:admin"
    pub metadata: Metadata,
    pub is_system: bool,

    pub created_at: DateTime<Utc>,
    pub created_by: AccountId,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<AccountId>,
}

impl From<&RoleRow> for Role {
    fn from(row: &RoleRow) -> Self {
        Self {
            id: row.id,
            short_id: row.short_id.clone(),
            name: row.name.clone(),
            metadata: row.metadata.clone(),
            is_system: row.is_system,
            created_at: row.created_at,
            created_by: row.created_by,
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoleWithRules {
    pub role: Role,
    pub rules: Vec<Rule>,
}
