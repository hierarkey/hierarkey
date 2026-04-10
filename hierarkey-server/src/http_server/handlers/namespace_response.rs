// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::keys::KekId;
use crate::manager::masterkey::MasterkeyId;
use crate::manager::namespace::{KekAssignment, Namespace, NamespaceId, NamespaceKekState};
use hierarkey_core::{Labels, resources::Revision};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct NamespaceSearchResponse {
    pub entries: Vec<NamespaceResponse>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KekAssignmentResponse {
    pub namespace_id: NamespaceId,
    pub revision: Revision,
    pub is_active: bool,
    pub kek_id: KekId,
    pub kek_short_id: String,
    pub masterkey_id: MasterkeyId,
    pub masterkey_short_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub description: Option<String>,
    pub labels: Labels,
}

impl From<KekAssignment> for KekAssignmentResponse {
    fn from(value: KekAssignment) -> Self {
        KekAssignmentResponse {
            namespace_id: value.namespace_id,
            revision: value.revision,
            is_active: value.is_active,
            kek_id: value.kek_id,
            kek_short_id: value.kek_short_id.to_string(),
            created_at: value.created_at,
            description: value.metadata.description(),
            labels: value.metadata.labels(),
            masterkey_id: value.masterkey_id,
            masterkey_short_id: value.masterkey_short_id.to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SecretSummaryResponse {
    pub total: usize,
    pub latest_enabled: usize,
    pub disabled: usize,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct NamespaceResponse {
    pub id: NamespaceId,
    pub short_id: String,
    pub namespace: String,
    pub status: String,
    pub description: Option<String>,
    pub labels: Labels,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Account name of the creator, if known.
    pub created_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Account name of the last modifier, if known.
    pub updated_by: Option<String>,
    pub active_kek_revision: Option<Revision>,
    pub latest_kek_revision: Revision,
    pub keks: Vec<KekAssignmentResponse>,
    pub secret_summary: Option<SecretSummaryResponse>,
}

impl NamespaceResponse {
    pub fn new_from_search(nsk: &NamespaceKekState) -> Self {
        Self::new_impl(
            &nsk.namespace,
            Vec::new(),
            nsk.active_kek_revision,
            nsk.latest_kek_revision,
            Some(SecretSummaryResponse {
                total: nsk.total_secrets,
                latest_enabled: 0,
                disabled: 0,
            }),
        )
    }

    pub fn new(namespace: &Namespace, keks: Vec<KekAssignment>) -> Self {
        let active_kek_revision = keks.iter().find(|kek| kek.is_active).map(|kek| kek.revision);

        let latest_kek_revision = keks.iter().map(|kek| kek.revision).max().unwrap_or(Revision::Number(1));

        Self::new_impl(namespace, keks, active_kek_revision, latest_kek_revision, None)
    }

    fn new_impl(
        namespace: &Namespace,
        keks: Vec<KekAssignment>,
        active_kek_revision: Option<Revision>,
        latest_kek_revision: Revision,
        secret_summary_response: Option<SecretSummaryResponse>,
    ) -> Self {
        NamespaceResponse {
            id: namespace.id,
            short_id: namespace.short_id.to_string(),
            namespace: namespace.namespace.to_string(),
            status: namespace.status.to_string(),
            description: namespace.metadata.description(),
            labels: namespace.metadata.labels(),
            created_at: namespace.created_at,
            created_by: None,
            updated_at: namespace.updated_at,
            updated_by: None,
            active_kek_revision,
            latest_kek_revision,
            keks: keks.into_iter().map(KekAssignmentResponse::from).collect(),
            secret_summary: secret_summary_response,
        }
    }

    pub fn with_actors(mut self, created_by: Option<String>, updated_by: Option<String>) -> Self {
        self.created_by = created_by;
        self.updated_by = updated_by;
        self
    }
}
