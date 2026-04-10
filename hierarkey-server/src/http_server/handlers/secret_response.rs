// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::keys::KekId;
use crate::manager::namespace::NamespaceId;
use crate::manager::secret::{Secret, SecretId, SecretRevision, SecretRevisionId};
use hierarkey_core::api::search::query::SecretType;
use hierarkey_core::{Labels, resources::Revision};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct SecretSearchResponse {
    pub entries: Vec<SecretResponse>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SecretRevisionResponse {
    pub id: SecretRevisionId,
    pub revision: Revision,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub description: Option<String>,
    pub kek_id: KekId,
    pub dek_alg: String,
    pub secret_alg: String,
    pub labels: Labels,
    pub length: usize,
}

impl From<SecretRevision> for SecretRevisionResponse {
    fn from(value: SecretRevision) -> Self {
        SecretRevisionResponse {
            id: value.id,
            revision: value.revision,
            created_at: value.created_at,
            description: value.metadata.description().clone(),
            kek_id: value.kek_id,
            dek_alg: value.dek_alg.to_string(),
            secret_alg: value.secret_alg.to_string(),
            labels: value.metadata.labels().clone(),
            length: value.encrypted_secret.ciphertext_len(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SecretResponse {
    pub id: SecretId,
    pub short_id: String,
    pub namespace_id: NamespaceId,
    pub ref_ns: String,
    pub ref_key: String,
    pub status: String,
    pub latest_revision: Revision,
    pub active_revision: Revision,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Account name of the creator, if known.
    pub created_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Account name of the last modifier, if known.
    pub updated_by: Option<String>,
    pub description: Option<String>,
    pub labels: Labels,
    pub secret_type: SecretType,
    pub revisions: Vec<SecretRevisionResponse>,
    /// Plaintext length of the active revision (only populated in search results)
    pub active_revision_length: Option<usize>,
}

impl SecretResponse {
    pub fn new(secret: Secret, revisions: Vec<SecretRevision>) -> Self {
        SecretResponse {
            id: secret.id,
            short_id: secret.short_id.to_string(),
            namespace_id: secret.namespace_id,
            ref_ns: secret.ref_ns,
            ref_key: secret.ref_key,
            status: secret.status.to_string(),
            latest_revision: secret.latest_revision,
            active_revision: secret.active_revision,
            created_at: secret.created_at,
            created_by: None,
            updated_at: secret.updated_at,
            updated_by: None,
            description: secret.metadata.description().clone(),
            labels: secret.metadata.labels().clone(),
            secret_type: secret.metadata.secret_type(),
            revisions: revisions.into_iter().map(SecretRevisionResponse::from).collect(),
            active_revision_length: secret.active_revision_length.map(|l| l.max(0) as usize),
        }
    }

    pub fn with_actors(mut self, created_by: Option<String>, updated_by: Option<String>) -> Self {
        self.created_by = created_by;
        self.updated_by = updated_by;
        self
    }
}
