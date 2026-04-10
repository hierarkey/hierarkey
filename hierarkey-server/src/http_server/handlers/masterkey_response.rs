// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::manager::account::AccountId;
use crate::manager::masterkey::{MasterKey, MasterKeyStatus, MasterKeyUsage, MasterkeyId};
use crate::service::masterkey::keyring::KeyStatus;
use hierarkey_core::Labels;
use serde::{Deserialize, Serialize};

// ----------------------------------------------------------------------------------------
#[derive(Deserialize, Serialize, Debug)]
pub struct MasterKeyStatusListResponse {
    pub entries: Vec<MasterKeyStatusResponse>,
    pub total: usize,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct MasterKeyStatusResponse {
    pub master_key: MasterKeyResponse,
    pub keyring: KeyStatus,
    /// Number of KEKs currently wrapped under this master key.
    /// Populated for Active and Draining keys; None for Pending and Retired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kek_count: Option<usize>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct MasterKeyResponse {
    pub id: MasterkeyId,
    pub short_id: String,
    pub name: String,
    pub usage: MasterKeyUsage,
    pub status: MasterKeyStatus,
    pub description: Option<String>,
    pub labels: Labels,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by_id: Option<AccountId>,
    pub created_by_name: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_by_id: Option<AccountId>,
    pub updated_by_name: Option<String>,
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
    pub retired_by_id: Option<AccountId>,
    pub retired_by_name: Option<String>,
}

impl From<&MasterKey> for MasterKeyResponse {
    fn from(master_key: &MasterKey) -> Self {
        Self {
            id: master_key.id,
            short_id: master_key.short_id.to_string(),
            name: master_key.name.to_string(),
            usage: master_key.usage,
            status: master_key.status,
            description: master_key.metadata.description().clone(),
            labels: master_key.metadata.labels().clone(),
            created_at: master_key.created_at,
            created_by_id: master_key.created_by,
            created_by_name: None,
            updated_at: master_key.updated_at,
            updated_by_id: master_key.updated_by,
            updated_by_name: None,
            retired_at: master_key.retired_at,
            retired_by_id: master_key.retired_by,
            retired_by_name: None,
        }
    }
}

impl MasterKeyResponse {
    pub fn with_actors(
        mut self,
        created_by_name: Option<String>,
        updated_by_name: Option<String>,
        retired_by_name: Option<String>,
    ) -> Self {
        self.created_by_name = created_by_name;
        self.updated_by_name = updated_by_name;
        self.retired_by_name = retired_by_name;
        self
    }
}
