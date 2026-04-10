// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::global::AccountRefDto;
use crate::manager::rbac::rule::Rule;
use crate::service::rbac::RuleListItem;
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};

/// Data Transfer Object (DTO) for representing a Target Resource in the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetResourceDto {
    pub kind: String,
    pub pattern: String,
    pub match_kind: String,
}

impl std::fmt::Display for TargetResourceDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{} ({})", self.kind, self.pattern, self.match_kind)
    }
}

/// Data Transfer Object (DTO) for representing a Rule in the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDto {
    pub id: String,

    pub effect: String,
    pub permission: String,
    pub target: String,
    pub condition: Option<String>,

    pub description: Option<String>,

    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: AccountRefDto,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_by: Option<AccountRefDto>,
}

impl From<&Rule> for RuleDto {
    fn from(r: &Rule) -> Self {
        Self {
            id: r.short_id.to_string(),
            effect: r.spec.effect.to_string(),
            permission: r.spec.permission.to_string(),
            target: r.spec.target.to_string(),
            condition: r.spec.condition.as_ref().map(|c| c.to_string()),
            description: r.metadata.description(),
            created_at: r.created_at,
            created_by: AccountRefDto {
                account_id: r.created_by.to_string(),
                account_name: AccountName::unknown(),
            },
            updated_at: r.updated_at,
            updated_by: r.updated_by.map(|uid| AccountRefDto {
                account_id: uid.to_string(),
                account_name: AccountName::unknown(),
            }),
        }
    }
}

impl RuleDto {
    pub fn with_actors(mut self, created_by: Option<AccountRefDto>, updated_by: Option<AccountRefDto>) -> Self {
        if let Some(a) = created_by {
            self.created_by = a;
        }
        if let Some(a) = updated_by {
            self.updated_by = Some(a);
        }
        self
    }
}

/// Data Transfer Object (DTO) for representing a Rule in a list context, including the count of associated accounts and roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleListItemDto {
    pub id: String,
    pub effect: String,
    pub permission: String,
    pub target: String,
    pub account_count: u32,
    pub role_count: u32,
}

impl From<&RuleListItem> for RuleListItemDto {
    fn from(item: &RuleListItem) -> Self {
        let r = &item.rule;
        Self {
            id: r.short_id.to_string(),
            effect: r.spec.effect.to_string(),
            permission: r.spec.permission.to_string(),
            target: r.spec.target.to_string(),
            account_count: item.account_count as u32,
            role_count: item.role_count as u32,
        }
    }
}
