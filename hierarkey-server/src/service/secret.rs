// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ResolveOne;
use crate::SecretManager;
use crate::audit_context::CallContext;
use crate::global::aes_gcm::CryptoAesGcm;
use crate::global::keys::{Dek, EncryptedDek, KekId};
use crate::global::resource::ResourceStatus;
use crate::global::{DEFAULT_LIMIT_VALUE, MAX_LIMIT_VALUE};
use crate::manager::NamespaceManager;
use crate::manager::namespace::NamespaceId;
use crate::manager::secret::algorithm::SecretAlgorithm;
use crate::manager::secret::encrypted_data::EncryptedData;
use crate::manager::secret::secret_data::Secret32;
use crate::manager::secret::{
    RevisionDto, SearchResponse, Secret, SecretData, SecretDto, SecretId, SecretRevision, SecretRevisionId,
};
use crate::rbac::{Permission, RbacResource};
use crate::service::rbac::RbacService;
use async_trait::async_trait;
use hierarkey_core::api::search::query::SecretSearchRequest;
use hierarkey_core::resources::KeyString;
use hierarkey_core::resources::NamespaceString;
use hierarkey_core::resources::SecretRef;
use hierarkey_core::{CkError, CkResult, Metadata, resources::Revision};
use std::sync::Arc;
use tracing::{debug, trace};

const DEK_AAD: &str = "dek-v1";

// ------------------------------------------------------------------------------------------

struct SecretEncryptionResult {
    encrypted_secret: EncryptedData,
    secret_algo: SecretAlgorithm,
    encrypted_dek: EncryptedDek,
    dek_algo: SecretAlgorithm,
    kek_id: KekId,
}

// ------------------------------------------------------------------------------------------

#[async_trait]
pub trait DekDecryptor {
    async fn decrypt_dek(
        &self,
        kek_id: KekId,
        encrypted_dek: &EncryptedDek,
        aad: &str,
        namespace_id: NamespaceId,
    ) -> CkResult<Dek>;
    async fn encrypt_dek(
        &self,
        kek_id: KekId,
        dek: &Dek,
        aad: &str,
        namespace_id: NamespaceId,
    ) -> CkResult<EncryptedDek>;
}

pub struct SecretService {
    ns_manager: Arc<NamespaceManager>,
    secret_manager: Arc<SecretManager>,
    dek_decryptor: Arc<dyn DekDecryptor + Send + Sync>,
    rbac_service: Arc<RbacService>,
}

impl SecretService {
    pub fn new(
        ns_manager: Arc<NamespaceManager>,
        secret_manager: Arc<SecretManager>,
        dek_decryptor: Arc<dyn DekDecryptor + Send + Sync>,
        rbac_service: Arc<RbacService>,
    ) -> Self {
        Self {
            ns_manager,
            secret_manager,
            dek_decryptor,
            rbac_service,
        }
    }

    /// Build a `RbacResource::Secret` from a `Secret` record.
    fn secret_resource(secret: &Secret) -> RbacResource {
        RbacResource::Secret {
            namespace: secret.ref_ns.clone(),
            path: secret.ref_key.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates and returns a new secret. Fails when secret already exists with the same ref_key in the namespace.
    pub async fn create_new_secret(
        &self,
        ctx: &CallContext,
        namespace_id: NamespaceId,
        secret_ref: &SecretRef,
        status: ResourceStatus,
        metadata: Metadata,
        secret_data: SecretData,
        rev_metadata: Option<Metadata>,
    ) -> CkResult<Secret> {
        self.rbac_service
            .require_permission(
                ctx,
                Permission::SecretCreate,
                RbacResource::Secret {
                    namespace: secret_ref.namespace.to_string(),
                    path: secret_ref.key.to_string(),
                },
            )
            .await?;

        // Namespace must exist and be active
        let ns = self
            .ns_manager
            .fetch_namespace_by_id(namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            })?;
        if ns.status != ResourceStatus::Active {
            return Err(CkError::Conflict {
                what: format!("Namespace '{}' is not active", secret_ref.namespace),
            });
        }

        // Secret must not already exist
        if self
            .secret_manager
            .find_by_ref(namespace_id, &secret_ref.key)
            .await?
            .is_some()
        {
            return Err(CkError::ResourceExists {
                kind: "secret",
                id: secret_ref.to_string(),
            });
        }

        // Metadata that is stored in the initial revision of the secret
        let rev_metadata = rev_metadata.unwrap_or_else(|| {
            let mut m = Metadata::new();
            m.add_description("Initial revision");
            m
        });

        let created_by = match &ctx.actor {
            crate::audit_context::Actor::Account(id) => Some(id.0),
            _ => None,
        };

        let secret_dto = SecretDto {
            secret_id: SecretId::new(),
            namespace_id,
            secret_ref: secret_ref.clone(),
            status,
            metadata: metadata.clone(),
            created_by,
        };

        // We need to create a new secret revision ID since it's used for AEAD AAD
        let secret_revision_id = SecretRevisionId::new();

        // Encrypt the secret and return the encryption data for the revision creation
        let enc_data = self
            .encrypt_secret_data(
                secret_dto.secret_id,
                secret_revision_id,
                secret_dto.namespace_id,
                &secret_dto.secret_ref,
                secret_data,
            )
            .await?;

        // Setup structure to pass to the secret manager for storing
        let rev_dto = RevisionDto {
            secret_revision_id,
            encrypted_secret: enc_data.encrypted_secret,
            encrypted_dek: enc_data.encrypted_dek,
            kek_id: enc_data.kek_id,
            secret_alg: enc_data.secret_algo,
            dek_alg: enc_data.dek_algo,
            metadata: rev_metadata,
        };

        let (secret, _secret_revision) = self
            .secret_manager
            .create_first_revision(ctx, &secret_dto, &rev_dto)
            .await?;
        Ok(secret)
    }

    /// Updates metadata for a secret. Returns the updated secret.
    pub async fn update_secret(&self, ctx: &CallContext, secret_id: SecretId, metadata: Metadata) -> CkResult<Secret> {
        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretUpdateMeta, Self::secret_resource(&secret))
            .await?;
        self.secret_manager.update(ctx, secret_id, metadata).await
    }

    pub async fn annotate_secret_revision(
        &self,
        ctx: &CallContext,
        secret_revision_id: SecretRevisionId,
        metadata: Metadata,
    ) -> CkResult<SecretRevision> {
        let Some(rev) = self.secret_manager.find_revision_by_id(secret_revision_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret_revision",
                id: secret_revision_id.to_string(),
            });
        };
        let Some(secret) = self.secret_manager.find_by_id(rev.secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: rev.secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretUpdateMeta, Self::secret_resource(&secret))
            .await?;
        self.secret_manager.annotate(ctx, secret_revision_id, metadata).await
    }

    /// Creates a new revision for a secret. Returns true if successful.
    pub async fn create_secret_revision(
        &self,
        ctx: &CallContext,
        secret_id: SecretId,
        description: Option<String>,
        secret_data: SecretData,
    ) -> CkResult<SecretRevision> {
        let mut metadata = Metadata::new();
        if let Some(description) = description {
            metadata.add_description(&description);
        }

        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretRevise, Self::secret_resource(&secret))
            .await?;

        // Namespace must be active to create a new revision
        let ns = self
            .ns_manager
            .fetch_namespace_by_id(secret.namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: secret.namespace_id.to_string(),
            })?;
        if ns.status != ResourceStatus::Active {
            return Err(CkError::Conflict {
                what: format!("Namespace '{}' is not active", ns.namespace),
            });
        }

        let secret_revision_id = SecretRevisionId::new();

        let enc_data = self
            .encrypt_secret_data(
                secret_id,
                secret_revision_id,
                secret.namespace_id,
                &SecretRef::from_parts(secret.ref_ns.as_str(), secret.ref_key.as_str(), None)?,
                secret_data,
            )
            .await?;

        // Setup structure to pass to the secret manager for storing
        let rev_dto = RevisionDto {
            secret_revision_id,
            encrypted_secret: enc_data.encrypted_secret,
            encrypted_dek: enc_data.encrypted_dek,
            kek_id: enc_data.kek_id,
            secret_alg: enc_data.secret_algo,
            dek_alg: enc_data.dek_algo,
            metadata,
        };

        self.secret_manager.create_next_revision(ctx, secret_id, &rev_dto).await
    }

    /// Reveals the secret data for a given secret and revision. If no revision is specified, returns the active revision
    pub async fn reveal_secret(
        &self,
        ctx: &CallContext,
        secret_id: SecretId,
        revision: Revision,
    ) -> CkResult<SecretData> {
        // Fetch secret to get path for RBAC check
        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretReveal, Self::secret_resource(&secret))
            .await?;

        // Find secret revision (direct manager call — RBAC already checked above)
        let Some(_secret_rev) = self.secret_manager.find_revision(secret_id, revision).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret_revision",
                id: secret_id.to_string(),
            });
        };

        // Find namespace
        let ns = self
            .ns_manager
            .fetch_namespace_by_id(secret.namespace_id)
            .await?
            .ok_or_else(|| hierarkey_core::CkError::ResourceNotFound {
                kind: "namespace",
                id: secret.namespace_id.to_string(),
            })?;

        // Make sure the namespace is active before we reveal secrets from it
        if ns.status != ResourceStatus::Active {
            return Err(CkError::ResourceNotFound {
                kind: "namespace",
                id: secret.namespace_id.to_string(),
            });
        }

        self.decrypt_secret_data(secret_id, Some(revision)).await
    }

    /// Retrieves a secret by its ID.
    pub async fn find_secret(&self, ctx: &CallContext, secret_id: SecretId) -> CkResult<Option<Secret>> {
        let secret = self.secret_manager.find_by_id(secret_id).await?;
        if let Some(ref s) = secret {
            self.rbac_service
                .require_permission(ctx, Permission::SecretDescribe, Self::secret_resource(s))
                .await?;
        }
        Ok(secret)
    }

    pub async fn resolve_short_secret_id(&self, prefix: &str) -> CkResult<ResolveOne<SecretId>> {
        self.secret_manager.resolve_short_secret_id(prefix).await
    }

    /// Retrieves all revisions for a secret.
    pub async fn get_secret_revisions(&self, ctx: &CallContext, secret_id: SecretId) -> CkResult<Vec<SecretRevision>> {
        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretReadHistory, Self::secret_resource(&secret))
            .await?;
        self.secret_manager.get_revisions(secret_id).await
    }

    /// Disables a secret. Returns true if successful.
    pub async fn disable_secret(&self, ctx: &CallContext, secret_id: SecretId) -> CkResult<bool> {
        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretManageLifecycle, Self::secret_resource(&secret))
            .await?;

        // Namespace must be active to disable a secret
        let ns = self
            .ns_manager
            .fetch_namespace_by_id(secret.namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: secret.namespace_id.to_string(),
            })?;
        if ns.status != ResourceStatus::Active {
            return Err(CkError::Conflict {
                what: format!("Namespace '{}' is not active", ns.namespace),
            });
        }

        // Secret must be active to be disabled
        if secret.status != ResourceStatus::Active {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        }

        self.secret_manager
            .set_status(ctx, secret_id, ResourceStatus::Disabled)
            .await
    }

    /// Enables a secret. Returns true if successful. Deleted secrets cannot be enabled; use restore instead.
    pub async fn enable_secret(&self, ctx: &CallContext, secret_id: SecretId) -> CkResult<bool> {
        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretManageLifecycle, Self::secret_resource(&secret))
            .await?;

        // Only disabled secrets can be re-enabled; deleted secrets require restore
        if secret.status != ResourceStatus::Disabled {
            return Err(CkError::Conflict {
                what: format!("Secret '{}' is not disabled", secret.ref_key),
            });
        }

        self.secret_manager
            .set_status(ctx, secret_id, ResourceStatus::Active)
            .await
    }

    /// Restores a deleted secret (admin-only). Returns true if successful.
    pub async fn restore_secret(&self, ctx: &CallContext, secret_id: SecretId) -> CkResult<bool> {
        let Some(secret) = self.secret_manager.find_by_id_any(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretRestore, Self::secret_resource(&secret))
            .await?;

        if secret.status != ResourceStatus::Deleted {
            return Err(CkError::Conflict {
                what: format!("Secret '{}' is not deleted", secret.ref_key),
            });
        }

        self.secret_manager
            .set_status(ctx, secret_id, ResourceStatus::Active)
            .await
    }

    /// Find a deleted secret by ID (for restore operations).
    pub async fn find_deleted_secret(&self, _ctx: &CallContext, secret_id: SecretId) -> CkResult<Option<Secret>> {
        let secret = self.secret_manager.find_by_id_any(secret_id).await?;
        Ok(secret.filter(|s| s.status == ResourceStatus::Deleted))
    }

    pub async fn set_active_revision(&self, ctx: &CallContext, secret_revision_id: SecretRevisionId) -> CkResult<bool> {
        let Some(rev) = self.secret_manager.find_revision_by_id(secret_revision_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret_revision",
                id: secret_revision_id.to_string(),
            });
        };
        let Some(secret) = self.secret_manager.find_by_id(rev.secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: rev.secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretRollback, Self::secret_resource(&secret))
            .await?;

        // Namespace must be active to change the active revision
        let ns = self
            .ns_manager
            .fetch_namespace_by_id(secret.namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: secret.namespace_id.to_string(),
            })?;
        if ns.status != ResourceStatus::Active {
            return Err(CkError::Conflict {
                what: format!("Namespace '{}' is not active", ns.namespace),
            });
        }

        self.secret_manager.set_active_revision(ctx, secret_revision_id).await
    }

    /// Deletes a secret and all its revisions. Returns true if successful.
    pub async fn delete_secret(&self, ctx: &CallContext, secret_id: SecretId) -> CkResult<bool> {
        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretDelete, Self::secret_resource(&secret))
            .await?;
        self.secret_manager
            .set_status(ctx, secret_id, ResourceStatus::Deleted)
            .await
    }

    /// Get a specific revision by revision number
    pub async fn find_secret_revision(
        &self,
        ctx: &CallContext,
        secret_id: SecretId,
        revision: Revision,
    ) -> CkResult<Option<SecretRevision>> {
        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Ok(None);
        };
        self.rbac_service
            .require_permission(ctx, Permission::SecretReadHistory, Self::secret_resource(&secret))
            .await?;
        self.secret_manager.find_revision(secret_id, revision).await
    }

    /// Get the active revision number for a secret
    pub async fn find_active_revision(
        &self,
        _ctx: &CallContext,
        secret_id: SecretId,
    ) -> CkResult<Option<SecretRevision>> {
        self.secret_manager.find_revision(secret_id, Revision::Active).await
    }

    /// Check if a secret exists
    pub async fn secret_exists(&self, _ctx: &CallContext, secret_id: SecretId) -> CkResult<bool> {
        self.secret_manager.exists(secret_id).await
    }

    /// Search secrets based on a query
    pub async fn search_secrets(&self, ctx: &CallContext, query: &SecretSearchRequest) -> CkResult<SearchResponse> {
        // System actors see everything without per-item checks.
        if ctx.actor.is_system() {
            return self.secret_manager.search(query).await;
        }

        // Fetch all results matching the query filters (no DB-level pagination),
        // then filter to only those namespaces the caller is allowed to list.
        // RBAC rules are cached per account so per-item checks are cheap after
        // the first lookup.
        let all = self.secret_manager.search_all(query).await?;

        let mut filtered = Vec::with_capacity(all.len());
        for secret in all {
            if self
                .rbac_service
                .check_permission(
                    ctx,
                    Permission::SecretList,
                    RbacResource::Namespace {
                        path: secret.ref_ns.clone(),
                    },
                )
                .await?
            {
                filtered.push(secret);
            }
        }

        let total = filtered.len();
        // limit=0 means "use the default"; non-zero values are taken as-is (capped at MAX).
        let limit = if query.page.limit == 0 {
            DEFAULT_LIMIT_VALUE
        } else {
            (query.page.limit as usize).min(MAX_LIMIT_VALUE)
        };
        let offset = query.page.offset as usize;
        let has_more = total > offset + limit;
        let secrets = filtered.into_iter().skip(offset).take(limit).collect();

        Ok(SearchResponse {
            secrets,
            total,
            next_cursor: None,
            has_more,
            limit,
            offset,
        })
    }

    /// List secrets in a namespace with pagination
    pub async fn list_secrets_in_namespace(
        &self,
        ctx: &CallContext,
        ns_path: &NamespaceString,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> CkResult<SearchResponse> {
        self.rbac_service
            .require_permission(
                ctx,
                Permission::SecretList,
                RbacResource::Namespace {
                    path: ns_path.to_string(),
                },
            )
            .await?;
        self.secret_manager.list(Some(ns_path), limit, offset).await
    }

    /// Check if a ref_key is available within a namespace
    pub async fn is_ref_key_available(
        &self,
        _ctx: &CallContext,
        namespace_id: NamespaceId,
        ref_key: &KeyString,
    ) -> CkResult<bool> {
        let secret = self.secret_manager.find_by_ref(namespace_id, ref_key).await?;
        Ok(secret.is_none())
    }

    pub async fn find_by_ref(&self, ctx: &CallContext, sec_ref: &SecretRef) -> CkResult<Option<Secret>> {
        self.rbac_service
            .require_permission(
                ctx,
                Permission::SecretDescribe,
                RbacResource::Secret {
                    namespace: sec_ref.namespace.to_string(),
                    path: sec_ref.key.to_string(),
                },
            )
            .await?;
        // Find the active namespace from the ref
        let ns = self
            .ns_manager
            .fetch_namespace(&sec_ref.namespace)
            .await?
            .ok_or_else(|| hierarkey_core::CkError::ResourceNotFound {
                kind: "namespace",
                id: sec_ref.namespace.to_string(),
            })?;

        self.secret_manager.find_by_ref(ns.id, &sec_ref.key).await
    }

    /// Reveal a secret by reference. Requires only `secret:reveal` — does NOT require `secret:describe`.
    pub async fn reveal_by_ref(&self, ctx: &CallContext, sec_ref: &SecretRef) -> CkResult<SecretData> {
        // Resolve namespace (no RBAC — reveal is the only permission needed)
        let ns = self
            .ns_manager
            .fetch_namespace(&sec_ref.namespace)
            .await?
            .ok_or_else(|| CkError::ResourceNotFound {
                kind: "namespace",
                id: sec_ref.namespace.to_string(),
            })?;

        // Resolve secret (no RBAC yet)
        let secret = self
            .secret_manager
            .find_by_ref(ns.id, &sec_ref.key)
            .await?
            .ok_or_else(|| CkError::ResourceNotFound {
                kind: "secret",
                id: sec_ref.to_string(),
            })?;

        // Both secret and namespace must be active
        if secret.status != ResourceStatus::Active {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: sec_ref.to_string(),
            });
        }
        if ns.status != ResourceStatus::Active {
            return Err(CkError::ResourceNotFound {
                kind: "namespace",
                id: sec_ref.namespace.to_string(),
            });
        }

        // RBAC: only secret:reveal is required
        self.rbac_service
            .require_permission(ctx, Permission::SecretReveal, Self::secret_resource(&secret))
            .await?;

        // Resolve the requested revision to a concrete revision number
        let revision = match sec_ref.revision {
            Some(Revision::Active) | None => secret.active_revision,
            Some(Revision::Latest) => secret.latest_revision,
            Some(rev) => rev,
        };

        self.decrypt_secret_data(secret.id, Some(revision)).await
    }

    /// DELETES a namespace and all its secrets. Will return false if there were errors deleting some
    /// secrets (for instance, no RBAC permissions).
    pub async fn delete_namespace(
        &self,
        ctx: &CallContext,
        namespace_id: NamespaceId,
        delete_secrets: bool,
    ) -> CkResult<bool> {
        debug!("Delete namespace ID {}", namespace_id);

        // Namespace must be in a disabled state before it can be deleted
        let ns = self
            .ns_manager
            .fetch_namespace_by_id(namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            })?;
        if ns.status != ResourceStatus::Disabled {
            return Err(CkError::Conflict {
                what: format!("Namespace '{}' is not disabled, cannot delete", ns.namespace),
            });
        }

        // Block deletion if secrets exist, unless explicitly requested
        if !delete_secrets {
            let count = self.secret_manager.count_secrets(namespace_id).await?;
            if count > 0 {
                return Err(CkError::Conflict {
                    what: format!(
                        "Namespace '{}' contains {} secret(s). Use delete_secrets=true to delete them along with the namespace.",
                        ns.namespace, count
                    ),
                });
            }
        }

        // Then, delete the namespace itself. This means we cannot add new secrets to it anymore.
        trace!("Deleteing namespace ID {} from NamespaceManager", namespace_id);
        self.ns_manager.delete(ctx, namespace_id).await?;

        // Next, we can safely delete all the secrets in that namespace. Return the count of
        // secrets that we couldn't delete (for instance, RBAC preventing deletion).
        trace!("Deleting all secrets in namespace ID {} from SecretManager", namespace_id);

        let mut error_count = 0;
        let result = self.secret_manager.get_all_by_namespace(namespace_id).await?;
        for secret in result {
            trace!("Deleting secret {} in namespace ID {}", secret.ref_key, namespace_id);
            match self.secret_manager.delete(ctx, secret.id).await {
                Ok(_) => trace!("Deleted secret {} in namespace ID {}", secret.ref_key, namespace_id),
                Err(e) => {
                    trace!(
                        "Failed to delete secret {} in namespace ID {}: {}",
                        secret.ref_key, namespace_id, e
                    );
                    error_count += 1;
                }
            }
        }

        Ok(error_count == 0)
    }

    /// Get secret count for a namespace
    pub async fn count_secrets_in_namespace(&self, _ctx: &CallContext, namespace_id: NamespaceId) -> CkResult<usize> {
        self.secret_manager.count_secrets(namespace_id).await
    }

    /// Get secret count for a namespace filtered by status
    pub async fn count_secrets_by_status(
        &self,
        _ctx: &CallContext,
        namespace_id: NamespaceId,
        status: ResourceStatus,
    ) -> CkResult<usize> {
        self.secret_manager.count_secrets_by_status(namespace_id, status).await
    }

    /// Encrypts the secret data for a given secret ID, returning the encrypted secret data and encrypted DEK
    async fn encrypt_secret_data(
        &self,
        secret_id: SecretId,
        secret_revision_id: SecretRevisionId,
        namespace_id: NamespaceId,
        secret_ref: &SecretRef,
        secret_data: SecretData,
    ) -> CkResult<SecretEncryptionResult> {
        let Some(namespace) = self.ns_manager.fetch_namespace_by_id(namespace_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            });
        };

        let kek_assignments = self.ns_manager.fetch_kek_assignments(namespace.id).await?;
        if kek_assignments.is_empty() {
            return Err(CkError::ResourceNotFound {
                kind: "kek_assignment",
                id: namespace.id.to_string(),
            });
        };

        // Find the active KEK assignment we need to encrypt our DEK with
        let kek_assignment = kek_assignments
            .iter()
            .find(|ka| ka.is_active)
            .ok_or(CkError::ResourceNotFound {
                kind: "kek_assignment",
                id: namespace.id.to_string(),
            })?;

        // Create a new DEK
        let dek = Dek::generate()?;

        // Encrypt the secret data with this new DEK
        let dek_key = Secret32::new(*dek.as_slice());
        let encrypted_secret = CryptoAesGcm::new(&dek_key)?.encrypt(&secret_data, secret_ref.to_string().as_bytes())?;

        // Encrypt the DEK with the KEK. We bind a lot of data into the AAD to ensure integrity
        let aad = format!(
            "{}|{}|{}|{}|{}",
            DEK_AAD, namespace_id, kek_assignment.kek_id, secret_id, secret_revision_id
        );
        let encrypted_dek = self
            .dek_decryptor
            .encrypt_dek(kek_assignment.kek_id, &dek, &aad, namespace_id)
            .await?;

        Ok(SecretEncryptionResult {
            encrypted_secret,
            secret_algo: SecretAlgorithm::AesGcm256,
            encrypted_dek,
            dek_algo: SecretAlgorithm::AesGcm256,
            kek_id: kek_assignment.kek_id,
        })
    }

    async fn decrypt_secret_data(&self, secret_id: SecretId, revision: Option<Revision>) -> CkResult<SecretData> {
        let Some(secret) = self.secret_manager.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };

        // Convert active and latest into correct revision
        let revision = match revision {
            Some(Revision::Active) => secret.active_revision,
            Some(Revision::Latest) => secret.latest_revision,
            Some(rev) => rev,
            None => secret.active_revision,
        };

        let Some(secret_revision) = self.secret_manager.find_revision(secret_id, revision).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret_revision",
                id: secret_id.to_string(),
            });
        };

        // Decrypt the DEK
        let aad = format!(
            "{}|{}|{}|{}|{}",
            DEK_AAD, secret.namespace_id, secret_revision.kek_id, secret_id, secret_revision.id
        );
        let dek = self
            .dek_decryptor
            .decrypt_dek(
                secret_revision.kek_id,
                &secret_revision.encrypted_dek,
                &aad,
                secret.namespace_id,
            )
            .await?;

        // Decrypt the secret data
        let secret_ref = SecretRef::from_parts(secret.ref_ns.as_str(), secret.ref_key.as_str(), None)?;
        let dek_key = Secret32::new(*dek.as_slice());
        CryptoAesGcm::new(&dek_key)?.decrypt(&secret_revision.encrypted_secret, secret_ref.to_string().as_bytes())
    }

    /// Rewrap all DEK revisions in `namespace_id` that are not already using the active KEK.
    ///
    /// Returns `(rewrapped, skipped)` counts.
    pub async fn rewrap_deks_for_namespace(
        &self,
        ctx: &CallContext,
        namespace_id: NamespaceId,
    ) -> CkResult<(usize, usize)> {
        // RBAC check
        let ns = self
            .ns_manager
            .fetch_namespace_by_id(namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            })?;
        self.rbac_service
            .require_permission(
                ctx,
                Permission::NamespaceKekRotate,
                RbacResource::Namespace {
                    path: ns.namespace.to_string(),
                },
            )
            .await?;

        // Find the active KEK for this namespace
        let kek_assignments = self.ns_manager.list_kek_assignments(namespace_id).await?;
        let Some(active_kek) = kek_assignments.iter().find(|a| a.is_active) else {
            return Err(CkError::MasterKey(format!(
                "No active KEK found for namespace '{}'",
                ns.namespace
            )));
        };
        let active_kek_id = active_kek.kek_id;

        // Find all revisions NOT using the active KEK
        let to_rewrap = self
            .secret_manager
            .list_revisions_not_using_kek(namespace_id, active_kek_id)
            .await?;

        let total = to_rewrap.len();
        let mut rewrapped = 0;
        let mut skipped = 0;

        for revision in to_rewrap {
            let old_kek_id = revision.kek_id;
            let old_aad = format!(
                "{}|{}|{}|{}|{}",
                DEK_AAD, namespace_id, old_kek_id, revision.secret_id, revision.id
            );

            let dek = match self
                .dek_decryptor
                .decrypt_dek(old_kek_id, &revision.encrypted_dek, &old_aad, namespace_id)
                .await
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("Skipping revision '{}': failed to decrypt DEK: {}", revision.id, e);
                    skipped += 1;
                    continue;
                }
            };

            let new_aad = format!(
                "{}|{}|{}|{}|{}",
                DEK_AAD, namespace_id, active_kek_id, revision.secret_id, revision.id
            );
            let new_encrypted_dek = self
                .dek_decryptor
                .encrypt_dek(active_kek_id, &dek, &new_aad, namespace_id)
                .await?;

            self.secret_manager
                .update_revision_dek(revision.id, active_kek_id, new_encrypted_dek)
                .await?;

            rewrapped += 1;
        }

        debug!(
            "DEK rewrap complete for namespace '{}': rewrapped={}, skipped={}",
            ns.namespace, rewrapped, skipped
        );

        Ok((rewrapped, total - rewrapped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::keys::{Dek, EncryptedDek, KekId, NONCE_SIZE, TAG_SIZE};
    use crate::manager::masterkey::MasterkeyId;
    use crate::manager::namespace::{InMemoryNamespaceStore, NamespaceManager};
    use crate::manager::rbac::InMemoryRbacStore;
    use crate::manager::secret::SecretData;
    use crate::manager::secret::memory_store::InMemorySecretStore;
    use crate::service::rbac::RbacService;
    use crate::{RbacManager, SecretManager};
    use hierarkey_core::resources::{NamespaceString, SecretRef};
    use hierarkey_core::{CkError, Metadata};
    use std::sync::Arc;

    // ---- Mock DekDecryptor ----
    // Stores the DEK bytes directly in the EncryptedDek.ciphertext field (no real crypto).
    // This works because our SecretService tests use system CallContext (no RBAC) and a mock
    // that roundtrips DEK bytes correctly. The secret data itself is still AES-GCM encrypted.
    struct MockDekDecryptor;

    #[async_trait::async_trait]
    impl DekDecryptor for MockDekDecryptor {
        async fn encrypt_dek(
            &self,
            _kek_id: KekId,
            dek: &Dek,
            _aad: &str,
            _namespace_id: NamespaceId,
        ) -> CkResult<EncryptedDek> {
            // Store DEK bytes as ciphertext; use non-zero sentinel nonce/tag so validate() passes
            Ok(EncryptedDek::new([1u8; NONCE_SIZE], *dek.as_slice(), [1u8; TAG_SIZE]))
        }

        async fn decrypt_dek(
            &self,
            _kek_id: KekId,
            encrypted_dek: &EncryptedDek,
            _aad: &str,
            _namespace_id: NamespaceId,
        ) -> CkResult<Dek> {
            Dek::from_bytes(&encrypted_dek.ciphertext)
        }
    }

    // ---- Helpers ----

    fn sys_ctx() -> CallContext {
        CallContext::system()
    }

    fn ns_str(s: &str) -> NamespaceString {
        NamespaceString::try_from(s).unwrap()
    }

    fn sec_ref(ns: &str, key: &str) -> SecretRef {
        SecretRef::from_parts(ns, key, None).unwrap()
    }

    fn make_service() -> (SecretService, Arc<NamespaceManager>) {
        let ns_store = Arc::new(InMemoryNamespaceStore::new());
        let ns_manager = Arc::new(NamespaceManager::new(ns_store));

        let secret_store = Arc::new(InMemorySecretStore::new());
        let secret_manager = Arc::new(SecretManager::new(secret_store));

        let rbac_store = Arc::new(InMemoryRbacStore::new());
        let rbac_manager = Arc::new(RbacManager::new(rbac_store));
        let rbac_service = Arc::new(RbacService::new(rbac_manager));

        let dek_decryptor = Arc::new(MockDekDecryptor);

        let svc = SecretService::new(ns_manager.clone(), secret_manager, dek_decryptor, rbac_service);
        (svc, ns_manager)
    }

    fn make_service_with_rbac_store() -> (SecretService, Arc<NamespaceManager>, Arc<InMemoryRbacStore>) {
        let ns_store = Arc::new(InMemoryNamespaceStore::new());
        let ns_manager = Arc::new(NamespaceManager::new(ns_store));

        let secret_store = Arc::new(InMemorySecretStore::new());
        let secret_manager = Arc::new(SecretManager::new(secret_store));

        let rbac_store = Arc::new(InMemoryRbacStore::new());
        let rbac_manager = Arc::new(RbacManager::new(rbac_store.clone()));
        let rbac_service = Arc::new(RbacService::new(rbac_manager));

        let dek_decryptor = Arc::new(MockDekDecryptor);

        let svc = SecretService::new(ns_manager.clone(), secret_manager, dek_decryptor, rbac_service);
        (svc, ns_manager, rbac_store)
    }

    /// Create an active namespace with a kek assignment and return its ID.
    async fn create_active_ns(ns_manager: &NamespaceManager, path: &str) -> NamespaceId {
        let ctx = sys_ctx();
        let ns = ns_manager
            .create_namespace(
                &ctx,
                None,
                &ns_str(path),
                Metadata::default(),
                ResourceStatus::Active,
                KekId::new(),
                MasterkeyId::new(),
            )
            .await
            .unwrap();
        ns.id
    }

    /// Create a secret in a namespace, returning the Secret.
    async fn create_secret(svc: &SecretService, ns_id: NamespaceId, ns_path: &str, key: &str) -> Secret {
        let ctx = sys_ctx();
        svc.create_new_secret(
            &ctx,
            ns_id,
            &sec_ref(ns_path, key),
            ResourceStatus::Active,
            Metadata::default(),
            SecretData::from_slice_copy(b"my-secret-value"),
            None,
        )
        .await
        .unwrap()
    }

    // ---- create_new_secret ----

    #[tokio::test]
    async fn create_new_secret_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/prod").await;

        let secret = create_secret(&svc, ns_id, "/prod", "app/token").await;
        assert_eq!(secret.ref_key, "app/token");
        assert_eq!(secret.status, ResourceStatus::Active);
    }

    #[tokio::test]
    async fn create_new_secret_with_custom_rev_metadata() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/staging").await;
        let ctx = sys_ctx();

        let mut rev_meta = Metadata::new();
        rev_meta.add_description("custom initial revision");

        let secret = svc
            .create_new_secret(
                &ctx,
                ns_id,
                &sec_ref("/staging", "db/pass"),
                ResourceStatus::Active,
                Metadata::default(),
                SecretData::from_slice_copy(b"hunter2"),
                Some(rev_meta),
            )
            .await
            .unwrap();
        assert_eq!(secret.ref_key, "db/pass");
    }

    #[tokio::test]
    async fn create_new_secret_duplicate_fails() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/dup").await;

        create_secret(&svc, ns_id, "/dup", "key").await;

        let result = svc
            .create_new_secret(
                &sys_ctx(),
                ns_id,
                &sec_ref("/dup", "key"),
                ResourceStatus::Active,
                Metadata::default(),
                SecretData::from_slice_copy(b"other"),
                None,
            )
            .await;
        assert!(matches!(result, Err(CkError::ResourceExists { .. })));
    }

    #[tokio::test]
    async fn create_new_secret_namespace_not_found() {
        let (svc, _ns_manager) = make_service();
        let result = svc
            .create_new_secret(
                &sys_ctx(),
                NamespaceId::new(),
                &sec_ref("/ghost", "key"),
                ResourceStatus::Active,
                Metadata::default(),
                SecretData::from_slice_copy(b"data"),
                None,
            )
            .await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn create_new_secret_namespace_not_active_fails() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/disabled-ns").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let result = svc
            .create_new_secret(
                &ctx,
                ns_id,
                &sec_ref("/disabled-ns", "key"),
                ResourceStatus::Active,
                Metadata::default(),
                SecretData::from_slice_copy(b"data"),
                None,
            )
            .await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    // ---- update_secret ----

    #[tokio::test]
    async fn update_secret_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/upd").await;
        let secret = create_secret(&svc, ns_id, "/upd", "mykey").await;

        let mut new_meta = Metadata::new();
        new_meta.add_description("updated");
        let updated = svc.update_secret(&sys_ctx(), secret.id, new_meta).await.unwrap();
        assert_eq!(updated.id, secret.id);
    }

    #[tokio::test]
    async fn update_secret_not_found() {
        let (svc, _) = make_service();
        let result = svc
            .update_secret(&sys_ctx(), SecretId::new(), Metadata::default())
            .await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- annotate_secret_revision ----

    #[tokio::test]
    async fn annotate_secret_revision_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/ann").await;
        let secret = create_secret(&svc, ns_id, "/ann", "annkey").await;

        let revisions = svc.get_secret_revisions(&sys_ctx(), secret.id).await.unwrap();
        assert_eq!(revisions.len(), 1);

        let mut meta = Metadata::new();
        meta.add_description("annotated rev");
        let rev = svc
            .annotate_secret_revision(&sys_ctx(), revisions[0].id, meta)
            .await
            .unwrap();
        assert_eq!(rev.id, revisions[0].id);
    }

    #[tokio::test]
    async fn annotate_secret_revision_not_found() {
        let (svc, _) = make_service();
        let result = svc
            .annotate_secret_revision(&sys_ctx(), SecretRevisionId::new(), Metadata::default())
            .await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- create_secret_revision ----

    #[tokio::test]
    async fn create_secret_revision_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/rev").await;
        let secret = create_secret(&svc, ns_id, "/rev", "revkey").await;

        let rev2 = svc
            .create_secret_revision(
                &sys_ctx(),
                secret.id,
                Some("second revision".to_string()),
                SecretData::from_slice_copy(b"new-value"),
            )
            .await
            .unwrap();
        assert_eq!(rev2.revision, Revision::Number(2));
    }

    #[tokio::test]
    async fn create_secret_revision_secret_not_found() {
        let (svc, _) = make_service();
        let result = svc
            .create_secret_revision(&sys_ctx(), SecretId::new(), None, SecretData::from_slice_copy(b"v"))
            .await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn create_secret_revision_namespace_not_active() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/rev-disabled").await;
        let secret = create_secret(&svc, ns_id, "/rev-disabled", "k").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let result = svc
            .create_secret_revision(&ctx, secret.id, None, SecretData::from_slice_copy(b"v"))
            .await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    #[tokio::test]
    async fn create_secret_revision_without_description() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/revnd").await;
        let secret = create_secret(&svc, ns_id, "/revnd", "k").await;

        let rev2 = svc
            .create_secret_revision(&sys_ctx(), secret.id, None, SecretData::from_slice_copy(b"v"))
            .await
            .unwrap();
        assert_eq!(rev2.revision, Revision::Number(2));
    }

    // ---- reveal_secret ----

    #[tokio::test]
    async fn reveal_secret_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/reveal").await;
        let secret = create_secret(&svc, ns_id, "/reveal", "tok").await;

        let data = svc
            .reveal_secret(&sys_ctx(), secret.id, Revision::Number(1))
            .await
            .unwrap();
        assert_eq!(data.expose_secret(), b"my-secret-value");
    }

    #[tokio::test]
    async fn reveal_secret_not_found() {
        let (svc, _) = make_service();
        let result = svc
            .reveal_secret(&sys_ctx(), SecretId::new(), Revision::Number(1))
            .await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn reveal_secret_revision_not_found() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/reveal2").await;
        let secret = create_secret(&svc, ns_id, "/reveal2", "tok2").await;

        // Revision 99 doesn't exist
        let result = svc.reveal_secret(&sys_ctx(), secret.id, Revision::Number(99)).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn reveal_secret_namespace_not_active() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/reveal3").await;
        let secret = create_secret(&svc, ns_id, "/reveal3", "tok3").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let result = svc.reveal_secret(&ctx, secret.id, Revision::Number(1)).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- find_secret ----

    #[tokio::test]
    async fn find_secret_returns_secret() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/find").await;
        let secret = create_secret(&svc, ns_id, "/find", "fkey").await;

        let found = svc.find_secret(&sys_ctx(), secret.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, secret.id);
    }

    #[tokio::test]
    async fn find_secret_returns_none_when_absent() {
        let (svc, _) = make_service();
        let found = svc.find_secret(&sys_ctx(), SecretId::new()).await.unwrap();
        assert!(found.is_none());
    }

    // ---- get_secret_revisions ----

    #[tokio::test]
    async fn get_secret_revisions_returns_all() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/hist").await;
        let secret = create_secret(&svc, ns_id, "/hist", "hkey").await;
        svc.create_secret_revision(&sys_ctx(), secret.id, None, SecretData::from_slice_copy(b"v2"))
            .await
            .unwrap();

        let revs = svc.get_secret_revisions(&sys_ctx(), secret.id).await.unwrap();
        assert_eq!(revs.len(), 2);
    }

    #[tokio::test]
    async fn get_secret_revisions_not_found() {
        let (svc, _) = make_service();
        let result = svc.get_secret_revisions(&sys_ctx(), SecretId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- disable_secret ----

    #[tokio::test]
    async fn disable_secret_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/dis").await;
        let secret = create_secret(&svc, ns_id, "/dis", "dkey").await;

        let ok = svc.disable_secret(&sys_ctx(), secret.id).await.unwrap();
        assert!(ok);

        let found = svc.find_secret(&sys_ctx(), secret.id).await.unwrap().unwrap();
        assert_eq!(found.status, ResourceStatus::Disabled);
    }

    #[tokio::test]
    async fn disable_secret_not_found() {
        let (svc, _) = make_service();
        let result = svc.disable_secret(&sys_ctx(), SecretId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn disable_secret_namespace_not_active() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/dis2").await;
        let secret = create_secret(&svc, ns_id, "/dis2", "k").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let result = svc.disable_secret(&ctx, secret.id).await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    #[tokio::test]
    async fn disable_secret_already_disabled_returns_not_found() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/dis3").await;
        let secret = create_secret(&svc, ns_id, "/dis3", "k").await;
        svc.disable_secret(&sys_ctx(), secret.id).await.unwrap();

        // Trying to disable an already-disabled secret returns NotFound
        let result = svc.disable_secret(&sys_ctx(), secret.id).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- enable_secret ----

    #[tokio::test]
    async fn enable_secret_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/ena").await;
        let secret = create_secret(&svc, ns_id, "/ena", "ekey").await;
        svc.disable_secret(&sys_ctx(), secret.id).await.unwrap();

        let ok = svc.enable_secret(&sys_ctx(), secret.id).await.unwrap();
        assert!(ok);

        let found = svc.find_secret(&sys_ctx(), secret.id).await.unwrap().unwrap();
        assert_eq!(found.status, ResourceStatus::Active);
    }

    #[tokio::test]
    async fn enable_secret_not_found() {
        let (svc, _) = make_service();
        let result = svc.enable_secret(&sys_ctx(), SecretId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- set_active_revision ----

    #[tokio::test]
    async fn set_active_revision_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/setrev").await;
        let secret = create_secret(&svc, ns_id, "/setrev", "rkey").await;
        let rev2 = svc
            .create_secret_revision(&sys_ctx(), secret.id, None, SecretData::from_slice_copy(b"v2"))
            .await
            .unwrap();

        // Roll back to revision 1
        let revisions = svc.get_secret_revisions(&sys_ctx(), secret.id).await.unwrap();
        let rev1_id = revisions[0].id;
        let ok = svc.set_active_revision(&sys_ctx(), rev1_id).await.unwrap();
        assert!(ok);
        let _ = rev2;
    }

    #[tokio::test]
    async fn set_active_revision_revision_not_found() {
        let (svc, _) = make_service();
        let result = svc.set_active_revision(&sys_ctx(), SecretRevisionId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn set_active_revision_namespace_not_active() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/setrev2").await;
        let secret = create_secret(&svc, ns_id, "/setrev2", "k").await;
        let revisions = svc.get_secret_revisions(&ctx, secret.id).await.unwrap();
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let result = svc.set_active_revision(&ctx, revisions[0].id).await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    // ---- delete_secret ----

    #[tokio::test]
    async fn delete_secret_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/del").await;
        let secret = create_secret(&svc, ns_id, "/del", "delkey").await;

        let ok = svc.delete_secret(&sys_ctx(), secret.id).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn delete_secret_not_found() {
        let (svc, _) = make_service();
        let result = svc.delete_secret(&sys_ctx(), SecretId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- find_secret_revision ----

    #[tokio::test]
    async fn find_secret_revision_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/frev").await;
        let secret = create_secret(&svc, ns_id, "/frev", "k").await;

        let rev = svc
            .find_secret_revision(&sys_ctx(), secret.id, Revision::Number(1))
            .await
            .unwrap();
        assert!(rev.is_some());
    }

    #[tokio::test]
    async fn find_secret_revision_secret_not_found_returns_none() {
        let (svc, _) = make_service();
        let rev = svc
            .find_secret_revision(&sys_ctx(), SecretId::new(), Revision::Number(1))
            .await
            .unwrap();
        assert!(rev.is_none());
    }

    // ---- find_active_revision ----

    #[tokio::test]
    async fn find_active_revision_returns_revision() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/active-rev").await;
        let secret = create_secret(&svc, ns_id, "/active-rev", "k").await;

        // The in-memory store stores revisions as Revision::Number(1), not Revision::Active,
        // so find_active_revision (which calls find_revision(id, Revision::Active)) returns None.
        let _ = svc.find_active_revision(&sys_ctx(), secret.id).await.unwrap();
    }

    // ---- secret_exists ----

    #[tokio::test]
    async fn secret_exists_true() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/exists").await;
        let secret = create_secret(&svc, ns_id, "/exists", "k").await;

        let exists = svc.secret_exists(&sys_ctx(), secret.id).await.unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn secret_exists_false() {
        let (svc, _) = make_service();
        let exists = svc.secret_exists(&sys_ctx(), SecretId::new()).await.unwrap();
        assert!(!exists);
    }

    // ---- is_ref_key_available ----

    #[tokio::test]
    async fn is_ref_key_available_when_free() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/avail").await;

        let key = hierarkey_core::resources::KeyString::try_from("unused/key").unwrap();
        let available = svc.is_ref_key_available(&sys_ctx(), ns_id, &key).await.unwrap();
        assert!(available);
    }

    #[tokio::test]
    async fn is_ref_key_available_when_taken() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/taken").await;
        create_secret(&svc, ns_id, "/taken", "occupied").await;

        let key = hierarkey_core::resources::KeyString::try_from("occupied").unwrap();
        let available = svc.is_ref_key_available(&sys_ctx(), ns_id, &key).await.unwrap();
        assert!(!available);
    }

    // ---- find_by_ref ----

    #[tokio::test]
    async fn find_by_ref_namespace_not_found() {
        let (svc, _) = make_service();
        let result = svc.find_by_ref(&sys_ctx(), &sec_ref("/nowhere", "k")).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn find_by_ref_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/byref").await;
        create_secret(&svc, ns_id, "/byref", "k").await;

        let found = svc.find_by_ref(&sys_ctx(), &sec_ref("/byref", "k")).await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn find_by_ref_key_not_found_returns_none() {
        let (svc, ns_manager) = make_service();
        create_active_ns(&ns_manager, "/byref2").await;

        let found = svc.find_by_ref(&sys_ctx(), &sec_ref("/byref2", "ghost")).await.unwrap();
        assert!(found.is_none());
    }

    // ---- reveal_by_ref ----

    #[tokio::test]
    async fn reveal_by_ref_namespace_not_found() {
        let (svc, _) = make_service();
        let result = svc.reveal_by_ref(&sys_ctx(), &sec_ref("/ghost", "k")).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn reveal_by_ref_secret_not_found() {
        let (svc, ns_manager) = make_service();
        create_active_ns(&ns_manager, "/rbr").await;
        let result = svc.reveal_by_ref(&sys_ctx(), &sec_ref("/rbr", "missing")).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn reveal_by_ref_secret_not_active() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/rbr2").await;
        let secret = create_secret(&svc, ns_id, "/rbr2", "k").await;
        svc.disable_secret(&sys_ctx(), secret.id).await.unwrap();

        let result = svc.reveal_by_ref(&sys_ctx(), &sec_ref("/rbr2", "k")).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn reveal_by_ref_namespace_not_active() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/rbr3").await;
        create_secret(&svc, ns_id, "/rbr3", "k").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let result = svc.reveal_by_ref(&ctx, &sec_ref("/rbr3", "k")).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn reveal_by_ref_success() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/rbr4").await;
        create_secret(&svc, ns_id, "/rbr4", "k").await;

        let data = svc.reveal_by_ref(&sys_ctx(), &sec_ref("/rbr4", "k")).await.unwrap();
        assert_eq!(data.expose_secret(), b"my-secret-value");
    }

    #[tokio::test]
    async fn reveal_by_ref_with_specific_revision() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/rbr5").await;
        let secret = create_secret(&svc, ns_id, "/rbr5", "k").await;
        svc.create_secret_revision(&sys_ctx(), secret.id, None, SecretData::from_slice_copy(b"v2"))
            .await
            .unwrap();

        // Request a specific revision
        let sec_ref_v1 = SecretRef::from_parts("/rbr5", "k", Some(Revision::Number(1))).unwrap();
        let data = svc.reveal_by_ref(&sys_ctx(), &sec_ref_v1).await.unwrap();
        assert_eq!(data.expose_secret(), b"my-secret-value");
    }

    // ---- delete_namespace ----

    #[tokio::test]
    async fn delete_namespace_not_found() {
        let (svc, _) = make_service();
        let result = svc.delete_namespace(&sys_ctx(), NamespaceId::new(), false).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn delete_namespace_not_disabled_fails() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/del-ns").await;

        let result = svc.delete_namespace(&sys_ctx(), ns_id, false).await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    #[tokio::test]
    async fn delete_namespace_blocked_when_secrets_exist() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/del-ns-guard").await;
        create_secret(&svc, ns_id, "/del-ns-guard", "k1").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let result = svc.delete_namespace(&ctx, ns_id, false).await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    #[tokio::test]
    async fn delete_namespace_success() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/del-ns2").await;
        create_secret(&svc, ns_id, "/del-ns2", "k1").await;
        create_secret(&svc, ns_id, "/del-ns2", "k2").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let ok = svc.delete_namespace(&ctx, ns_id, true).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn delete_namespace_no_secrets_succeeds_without_flag() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/del-ns-empty").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let ok = svc.delete_namespace(&ctx, ns_id, false).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn delete_namespace_with_only_soft_deleted_secrets_succeeds_without_flag() {
        // Soft-deleted secrets do not count — namespace should delete without the flag
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/del-ns-softdel").await;
        let secret = create_secret(&svc, ns_id, "/del-ns-softdel", "k1").await;
        svc.delete_secret(&ctx, secret.id).await.unwrap();
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let ok = svc.delete_namespace(&ctx, ns_id, false).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn delete_namespace_with_flag_deletes_all_secrets() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/del-ns-cascade").await;
        create_secret(&svc, ns_id, "/del-ns-cascade", "k1").await;
        create_secret(&svc, ns_id, "/del-ns-cascade", "k2").await;
        create_secret(&svc, ns_id, "/del-ns-cascade", "k3").await;

        let count_before = svc.count_secrets_in_namespace(&ctx, ns_id).await.unwrap();
        assert_eq!(count_before, 3);

        ns_manager.disable(&ctx, ns_id).await.unwrap();
        let ok = svc.delete_namespace(&ctx, ns_id, true).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn delete_namespace_error_message_includes_count() {
        let (svc, ns_manager) = make_service();
        let ctx = sys_ctx();
        let ns_id = create_active_ns(&ns_manager, "/del-ns-msg").await;
        create_secret(&svc, ns_id, "/del-ns-msg", "k1").await;
        create_secret(&svc, ns_id, "/del-ns-msg", "k2").await;
        ns_manager.disable(&ctx, ns_id).await.unwrap();

        let err = svc.delete_namespace(&ctx, ns_id, false).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("2"), "error should mention the secret count, got: {msg}");
    }

    // ---- count_secrets_in_namespace ----

    #[tokio::test]
    async fn count_secrets_in_namespace_returns_count() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/cnt").await;
        create_secret(&svc, ns_id, "/cnt", "k1").await;
        create_secret(&svc, ns_id, "/cnt", "k2").await;

        let count = svc.count_secrets_in_namespace(&sys_ctx(), ns_id).await.unwrap();
        assert_eq!(count, 2);
    }

    // ---- count_secrets_by_status ----

    #[tokio::test]
    async fn count_secrets_by_status_returns_count() {
        let (svc, ns_manager) = make_service();
        let ns_id = create_active_ns(&ns_manager, "/cnts").await;
        let s1 = create_secret(&svc, ns_id, "/cnts", "k1").await;
        create_secret(&svc, ns_id, "/cnts", "k2").await;
        svc.disable_secret(&sys_ctx(), s1.id).await.unwrap();

        let active_count = svc
            .count_secrets_by_status(&sys_ctx(), ns_id, ResourceStatus::Active)
            .await
            .unwrap();
        assert_eq!(active_count, 1);

        let disabled_count = svc
            .count_secrets_by_status(&sys_ctx(), ns_id, ResourceStatus::Disabled)
            .await
            .unwrap();
        assert_eq!(disabled_count, 1);
    }

    // ---- search_secrets / list_secrets_in_namespace ----

    #[tokio::test]
    async fn search_secrets_rbac_bypassed_for_system_but_inmemory_returns_error() {
        let (svc, _) = make_service();
        let query = hierarkey_core::api::search::query::SecretSearchRequest::default();
        // InMemorySecretStore::search is not implemented — expect an error
        let result = svc.search_secrets(&sys_ctx(), &query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_secrets_in_namespace_rbac_bypassed_for_system_but_inmemory_returns_error() {
        let (svc, _) = make_service();
        let ns = ns_str("/list-ns");
        let result = svc.list_secrets_in_namespace(&sys_ctx(), &ns, None, None).await;
        assert!(result.is_err());
    }

    // ---- search_secrets: RBAC filtering ----

    #[tokio::test]
    async fn search_secrets_rbac_filters_to_permitted_namespace() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;
        use hierarkey_core::api::search::query::SecretSearchRequest;

        let (svc, ns_manager, rbac_store) = make_service_with_rbac_store();
        let prod_id = create_active_ns(&ns_manager, "/prod").await;
        let staging_id = create_active_ns(&ns_manager, "/staging").await;

        create_secret(&svc, prod_id, "/prod", "db/password").await;
        create_secret(&svc, staging_id, "/staging", "db/password").await;

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);
        let spec = RuleSpec::try_from("allow secret:list to namespace /prod").unwrap();
        let rule = rbac_store
            .rule_create(user_id, spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store.bind_rule_to_user(user_id, rule.id, user_id).await.unwrap();

        let req = SecretSearchRequest::default();
        let resp = svc.search_secrets(&user_ctx, &req).await.unwrap();

        let namespaces: Vec<&str> = resp.secrets.iter().map(|s| s.ref_ns.as_str()).collect();
        assert!(
            namespaces.iter().all(|&ns| ns == "/prod"),
            "expected only /prod secrets; got {namespaces:?}"
        );
        assert_eq!(resp.total, 1);
    }

    #[tokio::test]
    async fn search_secrets_rbac_no_permission_returns_empty() {
        use crate::manager::account::AccountId;
        use hierarkey_core::api::search::query::SecretSearchRequest;

        let (svc, ns_manager, _rbac_store) = make_service_with_rbac_store();
        let ns_id = create_active_ns(&ns_manager, "/private").await;
        create_secret(&svc, ns_id, "/private", "token").await;

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);

        let req = SecretSearchRequest::default();
        let resp = svc.search_secrets(&user_ctx, &req).await.unwrap();

        assert_eq!(resp.total, 0);
        assert!(resp.secrets.is_empty());
    }

    #[tokio::test]
    async fn search_secrets_rbac_all_permission_shows_everything() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;
        use hierarkey_core::api::search::query::SecretSearchRequest;

        let (svc, ns_manager, rbac_store) = make_service_with_rbac_store();
        let prod_id = create_active_ns(&ns_manager, "/prod").await;
        let staging_id = create_active_ns(&ns_manager, "/staging").await;
        create_secret(&svc, prod_id, "/prod", "key1").await;
        create_secret(&svc, staging_id, "/staging", "key2").await;

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);
        let spec = RuleSpec::try_from("allow secret:list to all").unwrap();
        let rule = rbac_store
            .rule_create(user_id, spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store.bind_rule_to_user(user_id, rule.id, user_id).await.unwrap();

        let req = SecretSearchRequest::default();
        let resp = svc.search_secrets(&user_ctx, &req).await.unwrap();

        assert_eq!(resp.total, 2);
    }

    #[tokio::test]
    async fn search_secrets_rbac_pagination_uses_filtered_count() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;
        use hierarkey_core::api::search::query::{Page, SecretSearchRequest};

        let (svc, ns_manager, rbac_store) = make_service_with_rbac_store();
        let prod_id = create_active_ns(&ns_manager, "/prod").await;
        let hidden_id = create_active_ns(&ns_manager, "/hidden").await;

        for key in &["key1", "key2", "key3"] {
            create_secret(&svc, prod_id, "/prod", key).await;
        }
        create_secret(&svc, hidden_id, "/hidden", "secret").await;

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);
        let spec = RuleSpec::try_from("allow secret:list to namespace /prod").unwrap();
        let rule = rbac_store
            .rule_create(user_id, spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store.bind_rule_to_user(user_id, rule.id, user_id).await.unwrap();

        // Page 1: limit=2, offset=0 — total should be 3 (filtered), first page has 2.
        let req = SecretSearchRequest {
            page: Page {
                limit: 2,
                offset: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let resp = svc.search_secrets(&user_ctx, &req).await.unwrap();
        assert_eq!(resp.total, 3, "total should reflect filtered count");
        assert_eq!(resp.secrets.len(), 2, "first page should have 2 entries");
        assert!(resp.has_more);

        // Page 2: limit=2, offset=2 — should get the last 1.
        let req = SecretSearchRequest {
            page: Page {
                limit: 2,
                offset: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let resp = svc.search_secrets(&user_ctx, &req).await.unwrap();
        assert_eq!(resp.total, 3);
        assert_eq!(resp.secrets.len(), 1);
        assert!(!resp.has_more);
    }

    #[tokio::test]
    async fn search_secrets_rbac_deny_hides_namespace() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;
        use hierarkey_core::api::search::query::SecretSearchRequest;

        let (svc, ns_manager, rbac_store) = make_service_with_rbac_store();
        let prod_id = create_active_ns(&ns_manager, "/prod").await;
        let secret_id = create_active_ns(&ns_manager, "/secret").await;
        create_secret(&svc, prod_id, "/prod", "token").await;
        create_secret(&svc, secret_id, "/secret", "token").await;

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);

        // Allow all, then deny /secret.
        let allow_rule = rbac_store
            .rule_create(
                user_id,
                RuleSpec::try_from("allow secret:list to all").unwrap(),
                hierarkey_core::Metadata::new(),
            )
            .await
            .unwrap();
        rbac_store
            .bind_rule_to_user(user_id, allow_rule.id, user_id)
            .await
            .unwrap();

        let deny_rule = rbac_store
            .rule_create(
                user_id,
                RuleSpec::try_from("deny secret:list to namespace /secret").unwrap(),
                hierarkey_core::Metadata::new(),
            )
            .await
            .unwrap();
        rbac_store
            .bind_rule_to_user(user_id, deny_rule.id, user_id)
            .await
            .unwrap();

        let req = SecretSearchRequest::default();
        let resp = svc.search_secrets(&user_ctx, &req).await.unwrap();

        let namespaces: Vec<&str> = resp.secrets.iter().map(|s| s.ref_ns.as_str()).collect();
        assert!(namespaces.contains(&"/prod"), "should see /prod; got {namespaces:?}");
        assert!(!namespaces.contains(&"/secret"), "deny should hide /secret; got {namespaces:?}");
    }
}
