// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::keys::{EncryptedDek, KekId};
use crate::global::resource::ResourceStatus;
use crate::global::short_id::ShortId;
use crate::global::uuid_id::Identifier;
use crate::manager::namespace::NamespaceId;
use crate::manager::secret::algorithm::SecretAlgorithm;
use crate::manager::secret::encrypted_data::EncryptedData;
pub(crate) use crate::manager::secret::secret_data::SecretData;
use crate::{ResolveOne, uuid_id};
use chrono::{DateTime, Utc};
use hierarkey_core::api::search::query::SecretSearchRequest;
use hierarkey_core::resources::KeyString;
use hierarkey_core::resources::NamespaceString;
use hierarkey_core::resources::SecretRef;
use hierarkey_core::{CkResult, Metadata, resources::Revision};
use serde::Serialize;
use std::sync::Arc;

uuid_id!(SecretId, "sec_");
uuid_id!(SecretRevisionId, "rev_");

pub mod algorithm;
pub mod encrypted_data;
#[cfg(test)]
pub mod memory_store;
pub mod secret_data;
pub mod sql_store;

// ---------------------------------------------------------------------------------------------

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct SecretSearchQuery {
//     pub ns_prefix: Option<String>,
//     pub key_prefix: Option<String>,
//     pub labels: Labels,
//     pub label_operator: LabelOperator,
//     pub status: Option<ResourceStatus>,
//     pub limit: Option<usize>,
//     pub offset: Option<usize>,
// }

// ---------------------------------------------------------------------------------------------

/// Encrypted secret stored in the database. It contains generic information, not revision data
#[derive(sqlx::FromRow, Clone, Debug, Serialize)]
pub struct Secret {
    /// Unique ID of the secret/revision pair
    pub id: SecretId,
    /// Short human-friendly ID
    pub short_id: ShortId,
    // Namespace of the key
    pub namespace_id: NamespaceId,
    // Namespace of the secret path (ie: /prod from /prod:app1/webtoken)
    pub ref_ns: String,
    /// Key of the secret path (ie: app1/webtoken from /prod:app1/webtoken)
    pub ref_key: String,
    /// Status of the secret
    #[sqlx(try_from = "String")]
    pub status: ResourceStatus,
    /// This is the active reversion (often the latest revision, but not necessary)
    pub active_revision: Revision,
    /// Latest known revision
    pub latest_revision: Revision,
    /// Generic metadata of the secret
    pub metadata: Metadata,
    /// Timestamp of the creation of this secret
    pub created_at: DateTime<Utc>,
    /// Account UUID of the creator
    pub created_by: Option<uuid::Uuid>,
    /// Timestamp of the last update of this secret
    pub updated_at: Option<DateTime<Utc>>,
    /// Account UUID of the last modifier
    pub updated_by: Option<uuid::Uuid>,
    /// Timestamp of the destruction of this secret
    pub deleted_at: Option<DateTime<Utc>>,
    /// Plaintext length of the active revision (populated by search queries via JOIN; None otherwise)
    #[sqlx(default)]
    pub active_revision_length: Option<i32>,
}

// ---------------------------------------------------------------------------------------------

/// Secret revision struct. It contains the actual secret, DEK and additional metadata
#[derive(sqlx::FromRow, Clone, Debug)]
pub struct SecretRevision {
    /// Unique ID of the secret/revision pair
    pub id: SecretRevisionId,
    /// ID of the secret it points to
    pub secret_id: SecretId,
    /// Revision (1 or higher)
    pub revision: Revision,
    /// Encrypted secret
    #[sqlx(try_from = "Vec<u8>")]
    pub encrypted_secret: EncryptedData,
    /// Encrypted DEK
    #[sqlx(try_from = "Vec<u8>")]
    pub encrypted_dek: EncryptedDek,
    /// KEK version used to encrypt the DEK
    pub kek_id: KekId,
    /// Algorith used to encrypt the secret
    pub secret_alg: SecretAlgorithm,
    /// Algorithm used to encrypt the DEK
    pub dek_alg: SecretAlgorithm,
    /// Metadata of the secret revision (note: commit_message: reason: etc)
    pub metadata: Metadata,
    /// Timestamp of the creation of this revision of the secret
    pub created_at: DateTime<Utc>,
    /// Timestamp of deletion of this revision of the secret
    pub deleted_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------------------------
pub struct SecretDto {
    pub secret_id: SecretId,
    pub namespace_id: NamespaceId,
    pub secret_ref: SecretRef,
    pub status: ResourceStatus,
    pub metadata: Metadata,
    pub created_by: Option<uuid::Uuid>,
}

pub struct RevisionDto {
    pub secret_revision_id: SecretRevisionId,
    pub encrypted_secret: EncryptedData,
    pub encrypted_dek: EncryptedDek,
    pub kek_id: KekId,
    pub secret_alg: SecretAlgorithm,
    pub dek_alg: SecretAlgorithm,
    pub metadata: Metadata,
}

/// Response includes the cursor for the next page
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    /// List of secrets found
    pub secrets: Vec<Secret>,
    /// Cursor for the next page (not used yet)
    pub next_cursor: Option<String>,
    /// Total number of secrets matching the query
    pub total: usize,
    /// Whether there are more results available
    pub has_more: bool,
    /// Limit used in the query
    pub limit: usize,
    /// Offset used in the query
    pub offset: usize,
}

#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    async fn create_first_revision(&self, sd: &SecretDto, rd: &RevisionDto) -> CkResult<(Secret, SecretRevision)>;
    async fn create_next_revision(&self, secret_id: SecretId, rd: &RevisionDto) -> CkResult<SecretRevision>;
    async fn update(
        &self,
        secret_id: SecretId,
        metadata: &Metadata,
        updated_by: Option<uuid::Uuid>,
    ) -> CkResult<Secret>;

    async fn find_by_id(&self, secret_id: SecretId) -> CkResult<Option<Secret>>;
    /// Like `find_by_id` but also returns secrets with status=deleted (for restore operations).
    async fn find_by_id_any(&self, secret_id: SecretId) -> CkResult<Option<Secret>>;
    async fn find_by_ref(&self, namespace_id: NamespaceId, ref_key: &KeyString) -> CkResult<Option<Secret>>;

    async fn find_revision(&self, secret_id: SecretId, revision: Revision) -> CkResult<Option<SecretRevision>>;
    async fn find_revision_by_id(&self, secret_revision_id: SecretRevisionId) -> CkResult<Option<SecretRevision>>;

    async fn get_revisions(&self, secret_id: SecretId) -> CkResult<Vec<SecretRevision>>;
    async fn get_by_namespace(&self, namespace_id: NamespaceId) -> CkResult<Vec<Secret>>;
    async fn count_secrets(&self, namespace_id: NamespaceId) -> CkResult<usize>;
    async fn count_secrets_by_status(&self, namespace_id: NamespaceId, status: ResourceStatus) -> CkResult<usize>;

    async fn update_revision_metadata(
        &self,
        secret_revision_id: SecretRevisionId,
        metadata: &Metadata,
    ) -> CkResult<SecretRevision>;

    async fn set_status(&self, secret_id: SecretId, status: ResourceStatus) -> CkResult<bool>;
    async fn set_active_revision(&self, secret_revision_id: SecretRevisionId) -> CkResult<bool>;
    async fn set_active_revision_by_rev(&self, secret_id: SecretId, revision: Revision) -> CkResult<bool>;

    async fn search(&self, query: &SecretSearchRequest) -> CkResult<SearchResponse>;
    /// Like `search` but returns all matching results without pagination.
    /// Used internally for RBAC-filtered listing.
    async fn search_all(&self, query: &SecretSearchRequest) -> CkResult<Vec<Secret>>;

    // async fn reveal(&self, secret_id: SecretId, revision: Option<Revision>) -> CkResult<SecretData>;
    // async fn rotate(&self, secret_id: SecretId, metadata: Metadata) -> CkResult<SecretRevision>;
    async fn delete(&self, secret_id: SecretId) -> CkResult<bool>;

    async fn resolve_short_secret_id(&self, prefix: &str) -> CkResult<ResolveOne<SecretId>>;

    /// List all non-deleted revisions for a namespace that are NOT using the given KEK.
    async fn list_revisions_not_using_kek(
        &self,
        namespace_id: NamespaceId,
        active_kek_id: KekId,
    ) -> CkResult<Vec<SecretRevision>>;

    /// Update the encrypted DEK and KEK reference on a secret revision in-place.
    async fn update_revision_dek(
        &self,
        secret_revision_id: SecretRevisionId,
        new_kek_id: KekId,
        new_encrypted_dek: EncryptedDek,
    ) -> CkResult<()>;
}

// ---------------------------------------------------------------------------------------------

pub struct SecretManager {
    store: Arc<dyn SecretStore>,
}

impl SecretManager {
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        Self { store }
    }

    pub async fn update(&self, ctx: &CallContext, secret_id: SecretId, metadata: Metadata) -> CkResult<Secret> {
        let updated_by = match &ctx.actor {
            crate::audit_context::Actor::Account(id) => Some(id.0),
            _ => None,
        };
        self.store.update(secret_id, &metadata, updated_by).await
    }

    pub async fn annotate(
        &self,
        _ctx: &CallContext,
        secret_revision_id: SecretRevisionId,
        metadata: Metadata,
    ) -> CkResult<SecretRevision> {
        self.store.update_revision_metadata(secret_revision_id, &metadata).await
    }

    pub async fn create_first_revision(
        &self,
        _ctx: &CallContext,
        sd: &SecretDto,
        rd: &RevisionDto,
    ) -> CkResult<(Secret, SecretRevision)> {
        self.store.create_first_revision(sd, rd).await
    }

    pub async fn create_next_revision(
        &self,
        _ctx: &CallContext,
        secret_id: SecretId,
        rd: &RevisionDto,
    ) -> CkResult<SecretRevision> {
        self.store.create_next_revision(secret_id, rd).await
    }

    pub async fn find_by_id(&self, secret_id: SecretId) -> CkResult<Option<Secret>> {
        self.store.find_by_id(secret_id).await
    }

    pub async fn find_by_id_any(&self, secret_id: SecretId) -> CkResult<Option<Secret>> {
        self.store.find_by_id_any(secret_id).await
    }

    pub async fn get_all_by_namespace(&self, namespace_id: NamespaceId) -> CkResult<Vec<Secret>> {
        self.store.get_by_namespace(namespace_id).await
    }

    pub async fn get_revisions(&self, secret_id: SecretId) -> CkResult<Vec<SecretRevision>> {
        self.store.get_revisions(secret_id).await
    }

    pub async fn set_status(&self, _ctx: &CallContext, secret_id: SecretId, status: ResourceStatus) -> CkResult<bool> {
        self.store.set_status(secret_id, status).await
    }

    pub async fn set_active_revision(
        &self,
        _ctx: &CallContext,
        secret_revision_id: SecretRevisionId,
    ) -> CkResult<bool> {
        self.store.set_active_revision(secret_revision_id).await
    }

    pub async fn find_revision(&self, secret_id: SecretId, revision: Revision) -> CkResult<Option<SecretRevision>> {
        self.store.find_revision(secret_id, revision).await
        // match revision {
        //     Some(rev) => ,
        //     None => {
        //         // Get active revision
        //         let secret = self.store.get_by_id(secret_id).await?;
        //         let secret = match secret {
        //             Some(s) => s,
        //             None => return Ok(None),
        //         };
        //         self.store.get_revision(secret_id, secret.active_revision).await
        //     }
        // }
    }

    pub async fn find_revision_by_id(&self, secret_revision_id: SecretRevisionId) -> CkResult<Option<SecretRevision>> {
        self.store.find_revision_by_id(secret_revision_id).await
    }

    pub async fn exists(&self, secret_id: SecretId) -> CkResult<bool> {
        let sect = self.store.find_by_id(secret_id).await?;
        Ok(sect.is_some())
    }

    pub async fn list(
        &self,
        _namespace: Option<&NamespaceString>,
        _limit: Option<usize>,
        _offset: Option<usize>,
    ) -> CkResult<SearchResponse> {
        let q = SecretSearchRequest::default();
        self.store.search(&q).await
    }

    pub async fn find_by_ref(&self, namespace_id: NamespaceId, key: &KeyString) -> CkResult<Option<Secret>> {
        self.store.find_by_ref(namespace_id, key).await
    }

    pub async fn count_secrets(&self, namespace_id: NamespaceId) -> CkResult<usize> {
        self.store.count_secrets(namespace_id).await
    }

    pub async fn count_secrets_by_status(&self, namespace_id: NamespaceId, status: ResourceStatus) -> CkResult<usize> {
        self.store.count_secrets_by_status(namespace_id, status).await
    }

    pub async fn delete(&self, _ctx: &CallContext, secret_id: SecretId) -> CkResult<bool> {
        self.store.delete(secret_id).await
    }

    pub async fn resolve_short_secret_id(&self, prefix: &str) -> CkResult<ResolveOne<SecretId>> {
        self.store.resolve_short_secret_id(prefix).await
    }

    pub async fn search(&self, query: &SecretSearchRequest) -> CkResult<SearchResponse> {
        self.store.search(query).await
    }

    pub async fn search_all(&self, query: &SecretSearchRequest) -> CkResult<Vec<Secret>> {
        self.store.search_all(query).await
    }

    pub async fn list_revisions_not_using_kek(
        &self,
        namespace_id: NamespaceId,
        active_kek_id: KekId,
    ) -> CkResult<Vec<SecretRevision>> {
        self.store
            .list_revisions_not_using_kek(namespace_id, active_kek_id)
            .await
    }

    pub async fn update_revision_dek(
        &self,
        secret_revision_id: SecretRevisionId,
        new_kek_id: KekId,
        new_encrypted_dek: EncryptedDek,
    ) -> CkResult<()> {
        self.store
            .update_revision_dek(secret_revision_id, new_kek_id, new_encrypted_dek)
            .await
    }
}
