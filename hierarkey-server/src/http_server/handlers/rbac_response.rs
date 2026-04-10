// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub mod role;

#[derive(Serialize, Deserialize)]
pub struct RoleResponse {
    pub id: RoleId,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: AccountId,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_by: Option<AccountId>,
}

impl From<&Role> for RoleResponse {
    fn from(role: &Role) -> Self {
        Self {
            id: role.id.clone(),
            name: role.name.clone(),
            description: role.description.clone(),
            is_system: role.is_system,
            created_at: role.created_at,
            created_by: role.created_by.clone(),
            updated_at: role.updated_at,
            updated_by: role.updated_by.clone(),
        }
    }
}