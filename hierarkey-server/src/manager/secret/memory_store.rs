// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ResolveOne;
use crate::global::keys::{EncryptedDek, KekId};
use crate::global::resource::ResourceStatus;
use crate::manager::namespace::NamespaceId;
use crate::manager::secret::{
    RevisionDto, SearchResponse, Secret, SecretDto, SecretId, SecretRevision, SecretRevisionId, SecretStore,
};
use hierarkey_core::api::search::query::SecretSearchRequest;
use hierarkey_core::resources::KeyString;
use hierarkey_core::{CkError, CkResult, Metadata, resources::Revision};
use parking_lot::Mutex;
use std::collections::HashMap;

/// In memory secret store
pub struct InMemorySecretStore {
    // Stores the secrets (generic information, non-revision specific)
    secret_store: Mutex<HashMap<SecretId, Secret>>,
    /// Secret revisions (encrypted secrets + accompanying data)
    revision_store: Mutex<HashMap<SecretRevisionId, SecretRevision>>,
}

impl Default for InMemorySecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self {
            secret_store: Mutex::new(HashMap::new()),
            revision_store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl SecretStore for InMemorySecretStore {
    async fn create_first_revision(&self, sd: &SecretDto, rd: &RevisionDto) -> CkResult<(Secret, SecretRevision)> {
        // Add secret (general info)
        let secret_id = SecretId::new();
        let now = chrono::Utc::now();

        let secret = Secret {
            id: secret_id,
            short_id: crate::global::short_id::ShortId::generate("sec_", 12),
            namespace_id: sd.namespace_id,
            ref_key: sd.secret_ref.key.to_string(),
            ref_ns: sd.secret_ref.namespace.to_string(),
            status: sd.status,
            active_revision: Revision::Number(1),
            latest_revision: Revision::Number(1),
            metadata: sd.metadata.clone(),
            created_at: now,
            created_by: sd.created_by,
            updated_at: None,
            updated_by: None,
            deleted_at: None,
            active_revision_length: None,
        };

        let mut store = self.secret_store.lock();
        store.insert(secret_id, secret.clone());

        // Add initial revision
        let mut revision_store = self.revision_store.lock();

        let revision_id = SecretRevisionId::new();
        let secret_revision = SecretRevision {
            id: revision_id,
            secret_id,
            revision: Revision::Number(1),
            encrypted_secret: rd.encrypted_secret.clone(),
            encrypted_dek: rd.encrypted_dek.clone(),
            kek_id: rd.kek_id,
            secret_alg: rd.secret_alg,
            dek_alg: rd.dek_alg,
            metadata: rd.metadata.clone(),
            created_at: now,
            deleted_at: None,
        };
        revision_store.insert(revision_id, secret_revision.clone());

        Ok((secret, secret_revision))
    }

    async fn update(
        &self,
        secret_id: SecretId,
        metadata: &Metadata,
        updated_by: Option<uuid::Uuid>,
    ) -> CkResult<Secret> {
        let mut store = self.secret_store.lock();

        let secret = store.get_mut(&secret_id).ok_or_else(|| CkError::ResourceNotFound {
            kind: "secret",
            id: secret_id.to_string(),
        })?;

        secret.metadata = metadata.clone();
        secret.updated_at = Some(chrono::Utc::now());
        secret.updated_by = updated_by;

        Ok(secret.clone())
    }

    async fn create_next_revision(&self, secret_id: SecretId, rd: &RevisionDto) -> CkResult<SecretRevision> {
        let mut secret_store = self.secret_store.lock();
        let mut revision_store = self.revision_store.lock();

        let secret = secret_store
            .get_mut(&secret_id)
            .ok_or_else(|| CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            })?;

        let current_max_revision = revision_store
            .values()
            .filter(|r| r.secret_id == secret_id)
            .map(|r| r.revision)
            .max()
            .unwrap_or(Revision::Number(0));

        let Some(max_rev) = current_max_revision.as_number() else {
            return Err(CkError::InvariantViolation {
                what: "invalid revision type stored in memory".to_string(),
            });
        };

        let revision = Revision::Number(max_rev + 1);

        let now = chrono::Utc::now();

        let secret_revision = SecretRevision {
            id: rd.secret_revision_id,
            secret_id,
            revision,
            encrypted_secret: rd.encrypted_secret.clone(),
            encrypted_dek: rd.encrypted_dek.clone(),
            kek_id: rd.kek_id,
            secret_alg: rd.secret_alg,
            dek_alg: rd.dek_alg,
            metadata: rd.metadata.clone(),
            created_at: now,
            deleted_at: None,
        };

        revision_store.insert(rd.secret_revision_id, secret_revision.clone());
        secret.latest_revision = revision;
        secret.updated_at = Some(now);

        Ok(secret_revision)
    }

    async fn find_by_id(&self, secret_id: SecretId) -> CkResult<Option<Secret>> {
        let store = self.secret_store.lock();
        Ok(store.get(&secret_id).filter(|s| s.deleted_at.is_none()).cloned())
    }

    async fn find_by_id_any(&self, secret_id: SecretId) -> CkResult<Option<Secret>> {
        let store = self.secret_store.lock();
        Ok(store.get(&secret_id).cloned())
    }

    async fn find_by_ref(&self, namespace_id: NamespaceId, ref_key: &KeyString) -> CkResult<Option<Secret>> {
        let ref_key = ref_key.to_string();

        let store = self.secret_store.lock();
        Ok(store
            .values()
            .find(|s| s.namespace_id == namespace_id && s.ref_key == ref_key)
            .cloned())
    }

    async fn find_revision(&self, secret_id: SecretId, revision: Revision) -> CkResult<Option<SecretRevision>> {
        let revisions = self.revision_store.lock();
        Ok(revisions
            .values()
            .find(|r| r.secret_id == secret_id && r.revision == revision)
            .cloned())
    }

    async fn get_revisions(&self, secret_id: SecretId) -> CkResult<Vec<SecretRevision>> {
        let revisions = self.revision_store.lock();

        let mut result: Vec<_> = revisions
            .values()
            .filter(|r| r.secret_id == secret_id)
            .cloned()
            .collect();
        result.sort_by_key(|r| r.revision);

        Ok(result)
    }

    async fn get_by_namespace(&self, namespace_id: NamespaceId) -> CkResult<Vec<Secret>> {
        let store = self.secret_store.lock();
        Ok(store
            .values()
            .filter(|s| s.namespace_id == namespace_id)
            .cloned()
            .collect())
    }

    async fn count_secrets(&self, namespace_id: NamespaceId) -> CkResult<usize> {
        let store = self.secret_store.lock();
        Ok(store
            .values()
            .filter(|s| s.namespace_id == namespace_id && s.status != ResourceStatus::Deleted)
            .count())
    }

    async fn count_secrets_by_status(&self, namespace_id: NamespaceId, status: ResourceStatus) -> CkResult<usize> {
        let store = self.secret_store.lock();
        Ok(store
            .values()
            .filter(|s| s.namespace_id == namespace_id && s.status == status)
            .count())
    }

    async fn find_revision_by_id(&self, secret_revision_id: SecretRevisionId) -> CkResult<Option<SecretRevision>> {
        let revisions = self.revision_store.lock();
        Ok(revisions.get(&secret_revision_id).cloned())
    }

    async fn update_revision_metadata(
        &self,
        secret_revision_id: SecretRevisionId,
        metadata: &Metadata,
    ) -> CkResult<SecretRevision> {
        let mut revisions = self.revision_store.lock();

        let revision = revisions
            .get_mut(&secret_revision_id)
            .ok_or_else(|| CkError::ResourceNotFound {
                kind: "secret revision",
                id: secret_revision_id.to_string(),
            })?;

        revision.metadata = metadata.clone();

        Ok(revision.clone())
    }

    async fn set_status(&self, secret_id: SecretId, status: ResourceStatus) -> CkResult<bool> {
        let mut store = self.secret_store.lock();

        if let Some(secret) = store.get_mut(&secret_id) {
            secret.status = status;
            secret.updated_at = Some(chrono::Utc::now());
            if status == ResourceStatus::Deleted {
                secret.deleted_at = Some(chrono::Utc::now());
            } else {
                secret.deleted_at = None;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn set_active_revision(&self, secret_revision_id: SecretRevisionId) -> CkResult<bool> {
        let mut secrets = self.secret_store.lock();
        let revisions = self.revision_store.lock();

        let Some(secret_revision) = revisions.get(&secret_revision_id) else {
            return Err(CkError::ResourceNotFound {
                kind: "secret revision",
                id: secret_revision_id.to_string(),
            });
        };

        if let Some(secret) = secrets.get_mut(&secret_revision.secret_id) {
            secret.active_revision = secret_revision.revision;
            secret.updated_at = Some(chrono::Utc::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn set_active_revision_by_rev(&self, secret_id: SecretId, revision: Revision) -> CkResult<bool> {
        let mut secrets = self.secret_store.lock();
        let revisions = self.revision_store.lock();

        if !revisions
            .values()
            .any(|r| r.secret_id == secret_id && r.revision == revision)
        {
            return Err(CkError::ResourceNotFound {
                kind: "secret_revision",
                id: format!("secret_id: {secret_id}, revision: {revision}"),
            });
        }

        if let Some(secret) = secrets.get_mut(&secret_id) {
            secret.active_revision = revision;
            secret.updated_at = Some(chrono::Utc::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn search(&self, _query: &SecretSearchRequest) -> CkResult<SearchResponse> {
        Err(CkError::Custom("InMemorySecretStore::search is not implemented".to_string()))
    }

    async fn search_all(&self, query: &SecretSearchRequest) -> CkResult<Vec<Secret>> {
        let store = self.secret_store.lock();
        let scope = &query.scope;

        let mut results: Vec<Secret> = store
            .values()
            .filter(|s| s.deleted_at.is_none())
            .filter(|s| {
                if scope.all_namespaces || (scope.namespaces.is_empty() && scope.namespace_prefixes.is_empty()) {
                    return true;
                }
                if scope.namespaces.contains(&s.ref_ns) {
                    return true;
                }
                scope
                    .namespace_prefixes
                    .iter()
                    .any(|p| s.ref_ns.starts_with(p.as_str()))
            })
            .cloned()
            .collect();

        results.sort_by(|a, b| a.ref_key.cmp(&b.ref_key));
        Ok(results)
    }

    async fn delete(&self, secret_id: SecretId) -> CkResult<bool> {
        let mut secrets = self.secret_store.lock();

        if let Some(secret) = secrets.get_mut(&secret_id) {
            secret.status = ResourceStatus::Deleted;
            secret.deleted_at = Some(chrono::Utc::now());
            secret.updated_at = Some(chrono::Utc::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn resolve_short_secret_id(&self, prefix: &str) -> CkResult<ResolveOne<SecretId>> {
        let secrets = self.secret_store.lock();
        let prefix_lower = prefix.to_lowercase();
        let matches: Vec<SecretId> = secrets
            .values()
            .filter(|s| s.deleted_at.is_none() && s.short_id.to_string().to_lowercase().starts_with(&prefix_lower))
            .map(|s| s.id)
            .collect();
        match matches.len() {
            0 => Ok(ResolveOne::None),
            1 => Ok(ResolveOne::One(matches[0])),
            n => Ok(ResolveOne::Many(Some(n))),
        }
    }

    async fn list_revisions_not_using_kek(
        &self,
        namespace_id: NamespaceId,
        active_kek_id: KekId,
    ) -> CkResult<Vec<SecretRevision>> {
        let secrets = self.secret_store.lock();
        let revisions = self.revision_store.lock();

        let ns_secret_ids: std::collections::HashSet<SecretId> = secrets
            .values()
            .filter(|s| s.namespace_id == namespace_id && s.deleted_at.is_none())
            .map(|s| s.id)
            .collect();

        let result = revisions
            .values()
            .filter(|r| ns_secret_ids.contains(&r.secret_id) && r.kek_id != active_kek_id && r.deleted_at.is_none())
            .cloned()
            .collect();

        Ok(result)
    }

    async fn update_revision_dek(
        &self,
        secret_revision_id: SecretRevisionId,
        new_kek_id: KekId,
        new_encrypted_dek: EncryptedDek,
    ) -> CkResult<()> {
        let mut revisions = self.revision_store.lock();
        let revision = revisions
            .get_mut(&secret_revision_id)
            .ok_or_else(|| CkError::ResourceNotFound {
                kind: "secret_revision",
                id: secret_revision_id.to_string(),
            })?;
        revision.kek_id = new_kek_id;
        revision.encrypted_dek = new_encrypted_dek;
        Ok(())
    }
}
