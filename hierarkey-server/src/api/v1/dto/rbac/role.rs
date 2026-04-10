// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::v1::dto::global::AccountRefDto;
use crate::api::v1::dto::rbac::rule::RuleDto;
use crate::manager::rbac::role::{Role, RoleWithRules};
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};

/// Data Transfer Object (DTO) for representing a Role in the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDto {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: AccountRefDto,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_by: Option<AccountRefDto>,
}

impl From<&Role> for RoleDto {
    fn from(role: &Role) -> Self {
        Self {
            id: role.short_id.to_string(),
            name: role.name.clone(),
            description: role.metadata.description(),
            is_system: role.is_system,
            created_at: role.created_at,
            created_by: AccountRefDto {
                account_id: role.created_by.to_string(),
                account_name: AccountName::unknown(),
            },
            updated_at: role.updated_at,
            updated_by: role.updated_by.map(|uid| AccountRefDto {
                account_id: uid.to_string(),
                account_name: AccountName::unknown(),
            }),
        }
    }
}

impl RoleDto {
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

/// Data Transfer Object (DTO) for representing a Role in a list context, including the count of associated rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleListItemDto {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub role_count: u32,
}

impl From<&RoleWithRules> for RoleListItemDto {
    fn from(rwr: &RoleWithRules) -> Self {
        Self {
            id: rwr.role.short_id.to_string(),
            name: rwr.role.name.clone(),
            description: rwr.role.metadata.description(),
            is_system: rwr.role.is_system,
            role_count: rwr.rules.len() as u32,
        }
    }
}

/// Data Transfer Object (DTO) for representing a Role along with its associated Rules in the API.
#[derive(Serialize, Deserialize)]
pub struct RoleWithRulesDto {
    pub role: RoleDto,
    pub rules: Vec<RuleDto>,
}

impl From<&RoleWithRules> for RoleWithRulesDto {
    fn from(rwr: &RoleWithRules) -> Self {
        Self {
            role: RoleDto::from(&rwr.role),
            rules: rwr.rules.iter().map(RuleDto::from).collect(),
        }
    }
}
