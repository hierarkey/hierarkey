// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ResolveOne;
use crate::audit_context::CallContext;
use crate::global::keys::KekId;
use crate::global::resource::ResourceStatus;
use crate::global::{DEFAULT_LIMIT_VALUE, DEFAULT_OFFSET_VALUE, MAX_LIMIT_VALUE};
use crate::manager::NamespaceManager;
use crate::manager::masterkey::MasterkeyId;
use crate::manager::namespace::{KekAssignment, Namespace, NamespaceId, NamespaceKekState};
use crate::rbac::{Permission, RbacResource};
use crate::service::rbac::RbacService;
use async_trait::async_trait;
use hierarkey_core::resources::NamespaceString;
use hierarkey_core::{CkError, CkResult, Metadata};
use serde::Deserialize;
use std::sync::Arc;
use tracing::trace;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Activity {
    Any,
    #[default]
    Active,
    Disabled,
    Deleted,
}

#[derive(Debug, Deserialize)]
pub struct NamespaceSearchQuery {
    pub q: Option<String>,
    #[serde(default)]
    pub status: Vec<ResourceStatus>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

// ------------------------------------------------------------------------------------------------

#[async_trait]
pub trait KekEncryptable: Send + Sync {
    async fn generate_encrypted_kek(&self, namespace_id: NamespaceId) -> CkResult<(KekId, MasterkeyId)>;
}

pub struct NamespaceService {
    namespace_manager: Arc<NamespaceManager>,
    kek_encryptor: Arc<dyn KekEncryptable>,
    rbac_service: Arc<RbacService>,
}

impl NamespaceService {
    pub fn new(
        namespace_manager: Arc<NamespaceManager>,
        kek_encryptor: Arc<dyn KekEncryptable>,
        rbac_service: Arc<RbacService>,
    ) -> Self {
        Self {
            namespace_manager,
            kek_encryptor,
            rbac_service,
        }
    }

    async fn require_on_namespace(&self, ctx: &CallContext, permission: Permission, ns: &Namespace) -> CkResult<()> {
        self.rbac_service
            .require_permission_with_labels(
                ctx,
                permission,
                RbacResource::Namespace {
                    path: ns.namespace.to_string(),
                },
                ns.metadata.labels(),
            )
            .await
    }

    pub async fn fetch_by_namespace(
        &self,
        ctx: &CallContext,
        ns_path: &NamespaceString,
    ) -> CkResult<Option<Namespace>> {
        self.rbac_service
            .require_permission(
                ctx,
                Permission::NamespaceDescribe,
                RbacResource::Namespace {
                    path: ns_path.to_string(),
                },
            )
            .await?;
        self.namespace_manager.fetch_namespace(ns_path).await
    }

    pub async fn resolve_short_namespace_id(&self, prefix: &str) -> CkResult<ResolveOne<NamespaceId>> {
        self.namespace_manager.resolve_short_namespace_id(prefix).await
    }

    pub async fn fetch(&self, ctx: &CallContext, namespace_id: NamespaceId) -> CkResult<Option<Namespace>> {
        let ns = self.namespace_manager.fetch_namespace_by_id(namespace_id).await?;
        if let Some(ref namespace) = ns {
            self.require_on_namespace(ctx, Permission::NamespaceDescribe, namespace)
                .await?;
        }
        Ok(ns)
    }

    pub async fn create(
        &self,
        ctx: &CallContext,
        ns_path: &NamespaceString,
        metadata: Metadata,
        status: ResourceStatus,
    ) -> CkResult<Namespace> {
        self.rbac_service
            .require_permission(
                ctx,
                Permission::NamespaceCreate,
                RbacResource::Namespace {
                    path: ns_path.to_string(),
                },
            )
            .await?;

        // Since we add the namespace ID to the AAD of the encryption, we need to generate it first
        let namespace_id = NamespaceId::new();

        let (kek_id, masterkey_id) = self.kek_encryptor.generate_encrypted_kek(namespace_id).await?;

        self.namespace_manager
            .create_namespace(ctx, Some(namespace_id), ns_path, metadata, status, kek_id, masterkey_id)
            .await
    }

    pub async fn update(
        &self,
        ctx: &CallContext,
        namespace_id: NamespaceId,
        metadata: Metadata,
    ) -> CkResult<Namespace> {
        let ns = self
            .namespace_manager
            .fetch_namespace_by_id(namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            })?;
        self.require_on_namespace(ctx, Permission::NamespaceUpdateMeta, &ns)
            .await?;
        self.namespace_manager
            .update_namespace(ctx, namespace_id, metadata)
            .await
    }

    pub async fn disable(&self, ctx: &CallContext, namespace_id: NamespaceId) -> CkResult<bool> {
        let ns = self
            .namespace_manager
            .fetch_namespace_by_id(namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            })?;
        self.require_on_namespace(ctx, Permission::NamespaceDelete, &ns).await?;

        if ns.status != ResourceStatus::Active {
            return Err(CkError::Conflict {
                what: format!("Namespace '{}' is not active, cannot disable", ns.namespace),
            });
        }

        self.namespace_manager.disable(ctx, namespace_id).await
    }

    pub async fn enable(&self, ctx: &CallContext, namespace_id: NamespaceId) -> CkResult<bool> {
        let ns = self
            .namespace_manager
            .fetch_namespace_by_id(namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            })?;
        self.require_on_namespace(ctx, Permission::NamespaceDelete, &ns).await?;

        if ns.status != ResourceStatus::Disabled {
            return Err(CkError::Conflict {
                what: format!("Namespace '{}' is not disabled, cannot enable", ns.namespace),
            });
        }

        self.namespace_manager.enable(ctx, namespace_id).await
    }

    pub async fn delete(&self, ctx: &CallContext, namespace_id: NamespaceId) -> CkResult<bool> {
        let ns = self
            .namespace_manager
            .fetch_namespace_by_id(namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            })?;
        self.require_on_namespace(ctx, Permission::NamespaceDelete, &ns).await?;

        if ns.status != ResourceStatus::Disabled {
            return Err(CkError::Conflict {
                what: format!("Namespace '{}' is not disabled, cannot delete", ns.namespace),
            });
        }

        self.namespace_manager.delete(ctx, namespace_id).await
    }

    pub async fn rotate_kek(
        &self,
        ctx: &CallContext,
        namespace_id: NamespaceId,
        metadata: Metadata,
    ) -> CkResult<KekAssignment> {
        let ns = self
            .namespace_manager
            .fetch_namespace_by_id(namespace_id)
            .await?
            .ok_or(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            })?;
        self.require_on_namespace(ctx, Permission::NamespaceKekRotate, &ns)
            .await?;

        let (new_kek_id, new_masterkey_id) = self.kek_encryptor.generate_encrypted_kek(namespace_id).await?;
        self.namespace_manager
            .rotate_kek(namespace_id, new_kek_id, new_masterkey_id, metadata)
            .await
    }

    pub async fn has_status(
        &self,
        _ctx: &CallContext,
        namespace_id: NamespaceId,
        status: ResourceStatus,
    ) -> CkResult<bool> {
        let Some(ns) = self.namespace_manager.fetch_namespace_by_id(namespace_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            });
        };

        Ok(ns.status == status)
    }

    pub async fn search(
        &self,
        ctx: &CallContext,
        query: &NamespaceSearchQuery,
    ) -> CkResult<(Vec<NamespaceKekState>, usize)> {
        trace!("Searching namespaces with query: {:?}", query);

        // System actors see everything without per-item checks.
        if ctx.actor.is_system() {
            return self.namespace_manager.search(query).await;
        }

        // Fetch all results matching the query filters (no DB-level pagination),
        // then filter by what the caller is actually allowed to list.
        let all = self.namespace_manager.search_all(query).await?;

        let mut filtered = Vec::with_capacity(all.len());
        for entry in all {
            if self
                .rbac_service
                .check_permission_with_labels(
                    ctx,
                    Permission::NamespaceList,
                    RbacResource::Namespace {
                        path: entry.namespace.namespace.to_string(),
                    },
                    entry.namespace.metadata.labels(),
                )
                .await?
            {
                filtered.push(entry);
            }
        }

        let total = filtered.len();
        let offset = query.offset.unwrap_or(DEFAULT_OFFSET_VALUE);
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT_VALUE).min(MAX_LIMIT_VALUE);
        let entries = filtered.into_iter().skip(offset).take(limit).collect();

        Ok((entries, total))
    }

    pub async fn fetch_kek_assignments(
        &self,
        _ctx: &CallContext,
        namespace_id: NamespaceId,
    ) -> CkResult<Vec<KekAssignment>> {
        self.namespace_manager.fetch_kek_assignments(namespace_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RbacManager;
    use crate::audit_context::CallContext;
    use crate::global::resource::ResourceStatus;
    use crate::manager::namespace::{InMemoryNamespaceStore, NamespaceManager};
    use crate::manager::rbac::InMemoryRbacStore;
    use crate::service::rbac::RbacService;

    // ---- Mock KekEncryptable ----

    struct MockKekEncryptor;

    #[async_trait]
    impl KekEncryptable for MockKekEncryptor {
        async fn generate_encrypted_kek(&self, _namespace_id: NamespaceId) -> CkResult<(KekId, MasterkeyId)> {
            Ok((KekId::new(), MasterkeyId::new()))
        }
    }

    // ---- Helpers ----

    fn sys_ctx() -> CallContext {
        CallContext::system()
    }

    fn ns(path: &str) -> NamespaceString {
        NamespaceString::try_from(path).unwrap()
    }

    fn make_service() -> NamespaceService {
        let ns_store = Arc::new(InMemoryNamespaceStore::new());
        let manager = Arc::new(NamespaceManager::new(ns_store));
        let rbac_store = Arc::new(InMemoryRbacStore::new());
        let rbac_manager = Arc::new(RbacManager::new(
            rbac_store,
            Arc::new(crate::service::signing_key_slot::SigningKeySlot::new()),
        ));
        let rbac_service = Arc::new(RbacService::new(rbac_manager));
        NamespaceService::new(manager, Arc::new(MockKekEncryptor), rbac_service)
    }

    fn make_service_with_rbac_store() -> (NamespaceService, Arc<InMemoryRbacStore>) {
        let ns_store = Arc::new(InMemoryNamespaceStore::new());
        let manager = Arc::new(NamespaceManager::new(ns_store));
        let rbac_store = Arc::new(InMemoryRbacStore::new());
        let rbac_manager = Arc::new(RbacManager::new(
            rbac_store.clone(),
            Arc::new(crate::service::signing_key_slot::SigningKeySlot::new()),
        ));
        let rbac_service = Arc::new(RbacService::new(rbac_manager));
        let svc = NamespaceService::new(manager, Arc::new(MockKekEncryptor), rbac_service);
        (svc, rbac_store)
    }

    // ---- create / fetch ----

    #[tokio::test]
    async fn create_and_fetch_by_path() {
        let svc = make_service();
        svc.create(&sys_ctx(), &ns("/myns"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        let found = svc.fetch_by_namespace(&sys_ctx(), &ns("/myns")).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().namespace, ns("/myns"));
    }

    #[tokio::test]
    async fn fetch_by_namespace_not_found_returns_none() {
        let svc = make_service();
        let found = svc.fetch_by_namespace(&sys_ctx(), &ns("/ghost")).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn fetch_by_id_success() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/byid"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        let found = svc.fetch(&sys_ctx(), created.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, created.id);
    }

    #[tokio::test]
    async fn fetch_by_id_not_found_returns_none() {
        let svc = make_service();
        let found = svc.fetch(&sys_ctx(), NamespaceId::new()).await.unwrap();
        assert!(found.is_none());
    }

    // ---- update ----

    #[tokio::test]
    async fn update_success() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/upd"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        let mut new_meta = Metadata::new();
        new_meta.add_description("updated");
        let updated = svc.update(&sys_ctx(), created.id, new_meta).await.unwrap();
        assert_eq!(updated.id, created.id);
    }

    #[tokio::test]
    async fn update_not_found() {
        let svc = make_service();
        let result = svc.update(&sys_ctx(), NamespaceId::new(), Metadata::default()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- disable ----

    #[tokio::test]
    async fn disable_success() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/dis"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        let ok = svc.disable(&sys_ctx(), created.id).await.unwrap();
        assert!(ok);

        let found = svc.fetch(&sys_ctx(), created.id).await.unwrap().unwrap();
        assert_eq!(found.status, ResourceStatus::Disabled);
    }

    #[tokio::test]
    async fn disable_not_found() {
        let svc = make_service();
        let result = svc.disable(&sys_ctx(), NamespaceId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn disable_already_disabled_fails() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/dis2"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();
        svc.disable(&sys_ctx(), created.id).await.unwrap();

        let result = svc.disable(&sys_ctx(), created.id).await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    // ---- enable ----

    #[tokio::test]
    async fn enable_success() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/rst"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();
        svc.disable(&sys_ctx(), created.id).await.unwrap();

        let ok = svc.enable(&sys_ctx(), created.id).await.unwrap();
        assert!(ok);

        let found = svc.fetch(&sys_ctx(), created.id).await.unwrap().unwrap();
        assert_eq!(found.status, ResourceStatus::Active);
    }

    #[tokio::test]
    async fn enable_not_found() {
        let svc = make_service();
        let result = svc.enable(&sys_ctx(), NamespaceId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn enable_active_namespace_fails() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/rst2"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        // Active namespace cannot be enabled (it's not disabled)
        let result = svc.enable(&sys_ctx(), created.id).await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_success() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/del"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();
        svc.disable(&sys_ctx(), created.id).await.unwrap();

        let ok = svc.delete(&sys_ctx(), created.id).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn delete_not_found() {
        let svc = make_service();
        let result = svc.delete(&sys_ctx(), NamespaceId::new()).await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn delete_active_namespace_fails() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/del2"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        let result = svc.delete(&sys_ctx(), created.id).await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    // ---- has_status ----

    #[tokio::test]
    async fn has_status_active_returns_true() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/hs"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        assert!(
            svc.has_status(&sys_ctx(), created.id, ResourceStatus::Active)
                .await
                .unwrap()
        );
        assert!(
            !svc.has_status(&sys_ctx(), created.id, ResourceStatus::Disabled)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn has_status_not_found_returns_error() {
        let svc = make_service();
        let result = svc
            .has_status(&sys_ctx(), NamespaceId::new(), ResourceStatus::Active)
            .await;
        assert!(matches!(result, Err(CkError::ResourceNotFound { .. })));
    }

    // ---- search ----

    #[tokio::test]
    async fn search_returns_created_namespaces() {
        let svc = make_service();
        svc.create(&sys_ctx(), &ns("/search1"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();
        svc.create(&sys_ctx(), &ns("/search2"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(10),
            offset: None,
        };
        let (entries, _total) = svc.search(&sys_ctx(), &query).await.unwrap();
        assert!(entries.len() >= 2);
    }

    #[tokio::test]
    async fn search_rbac_filters_to_permitted_namespaces() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;

        let (svc, rbac_store) = make_service_with_rbac_store();

        // Create two namespaces via system context.
        svc.create(&sys_ctx(), &ns("/allowed"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();
        svc.create(&sys_ctx(), &ns("/denied"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        // Create a non-admin user and grant list only on /allowed.
        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);
        let spec = RuleSpec::try_from("allow namespace:list to namespace /allowed").unwrap();
        let rule = rbac_store
            .rule_create(user_id, spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store
            .bind_rule_to_user(user_id, rule.id, user_id, None)
            .await
            .unwrap();

        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(10),
            offset: None,
        };
        let (entries, total) = svc.search(&user_ctx, &query).await.unwrap();

        let paths: Vec<String> = entries.iter().map(|e| e.namespace.namespace.to_string()).collect();
        assert!(paths.contains(&"/allowed".to_string()), "should see /allowed; got {paths:?}");
        assert!(!paths.contains(&"/denied".to_string()), "should not see /denied; got {paths:?}");
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn search_rbac_system_actor_sees_all() {
        let svc = make_service();

        svc.create(&sys_ctx(), &ns("/ns-a"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();
        svc.create(&sys_ctx(), &ns("/ns-b"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(10),
            offset: None,
        };
        let (entries, total) = svc.search(&sys_ctx(), &query).await.unwrap();

        assert!(total >= 2);
        assert!(entries.len() >= 2);
    }

    #[tokio::test]
    async fn search_rbac_no_permission_returns_empty() {
        use crate::manager::account::AccountId;

        let (svc, _rbac_store) = make_service_with_rbac_store();

        svc.create(&sys_ctx(), &ns("/secret-ns"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        // User with no rules at all.
        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);

        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(10),
            offset: None,
        };
        let (entries, total) = svc.search(&user_ctx, &query).await.unwrap();

        assert_eq!(total, 0);
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn search_rbac_subtree_permission_shows_children() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;

        let (svc, rbac_store) = make_service_with_rbac_store();

        // /prod/db and /prod/app are children of /prod; /staging is unrelated.
        // Note: /prod/** covers the subtree but NOT /prod itself.
        for path in &["/prod/db", "/prod/app", "/staging"] {
            svc.create(&sys_ctx(), &ns(path), Metadata::default(), ResourceStatus::Active)
                .await
                .unwrap();
        }

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);

        // Subtree rule: covers everything strictly under /prod.
        let spec = RuleSpec::try_from("allow namespace:list to namespace /prod/**").unwrap();
        let rule = rbac_store
            .rule_create(user_id, spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store
            .bind_rule_to_user(user_id, rule.id, user_id, None)
            .await
            .unwrap();

        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(10),
            offset: None,
        };
        let (entries, total) = svc.search(&user_ctx, &query).await.unwrap();

        let paths: Vec<String> = entries.iter().map(|e| e.namespace.namespace.to_string()).collect();
        assert!(paths.contains(&"/prod/db".to_string()), "expected /prod/db; got {paths:?}");
        assert!(paths.contains(&"/prod/app".to_string()), "expected /prod/app; got {paths:?}");
        assert!(
            !paths.contains(&"/staging".to_string()),
            "should not see /staging; got {paths:?}"
        );
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn search_rbac_all_permission_shows_everything() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;

        let (svc, rbac_store) = make_service_with_rbac_store();

        for path in &["/ns1", "/ns2", "/ns3"] {
            svc.create(&sys_ctx(), &ns(path), Metadata::default(), ResourceStatus::Active)
                .await
                .unwrap();
        }

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);

        let spec = RuleSpec::try_from("allow namespace:list to all").unwrap();
        let rule = rbac_store
            .rule_create(user_id, spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store
            .bind_rule_to_user(user_id, rule.id, user_id, None)
            .await
            .unwrap();

        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(10),
            offset: None,
        };
        let (entries, total) = svc.search(&user_ctx, &query).await.unwrap();

        assert!(total >= 3);
        assert!(entries.len() >= 3);
    }

    #[tokio::test]
    async fn search_rbac_deny_overrides_allow() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;

        let (svc, rbac_store) = make_service_with_rbac_store();

        for path in &["/open", "/restricted"] {
            svc.create(&sys_ctx(), &ns(path), Metadata::default(), ResourceStatus::Active)
                .await
                .unwrap();
        }

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);

        // Allow all, then specifically deny /restricted.
        let allow_spec = RuleSpec::try_from("allow namespace:list to all").unwrap();
        let allow_rule = rbac_store
            .rule_create(user_id, allow_spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store
            .bind_rule_to_user(user_id, allow_rule.id, user_id, None)
            .await
            .unwrap();

        let deny_spec = RuleSpec::try_from("deny namespace:list to namespace /restricted").unwrap();
        let deny_rule = rbac_store
            .rule_create(user_id, deny_spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store
            .bind_rule_to_user(user_id, deny_rule.id, user_id, None)
            .await
            .unwrap();

        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(10),
            offset: None,
        };
        let (entries, _total) = svc.search(&user_ctx, &query).await.unwrap();

        let paths: Vec<String> = entries.iter().map(|e| e.namespace.namespace.to_string()).collect();
        assert!(paths.contains(&"/open".to_string()), "should see /open; got {paths:?}");
        assert!(
            !paths.contains(&"/restricted".to_string()),
            "deny should hide /restricted; got {paths:?}"
        );
    }

    #[tokio::test]
    async fn search_rbac_pagination_uses_filtered_count() {
        use crate::manager::account::AccountId;
        use crate::manager::rbac::RbacStore;
        use crate::rbac::spec::RuleSpec;

        let (svc, rbac_store) = make_service_with_rbac_store();

        // 4 namespaces, user can see only the /visible/* ones.
        for path in &["/visible/a", "/visible/b", "/visible/c", "/hidden"] {
            svc.create(&sys_ctx(), &ns(path), Metadata::default(), ResourceStatus::Active)
                .await
                .unwrap();
        }

        let user_id = AccountId::new();
        let user_ctx = CallContext::for_account(user_id);
        let spec = RuleSpec::try_from("allow namespace:list to namespace /visible/**").unwrap();
        let rule = rbac_store
            .rule_create(user_id, spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        rbac_store
            .bind_rule_to_user(user_id, rule.id, user_id, None)
            .await
            .unwrap();

        // Page 1: limit=2, offset=0 — should get first 2 visible namespaces, total=3.
        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(2),
            offset: Some(0),
        };
        let (entries, total) = svc.search(&user_ctx, &query).await.unwrap();
        assert_eq!(total, 3, "total should reflect filtered count");
        assert_eq!(entries.len(), 2, "first page should have 2 entries");

        // Page 2: limit=2, offset=2 — should get the remaining 1 visible namespace.
        let query = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(2),
            offset: Some(2),
        };
        let (entries, total) = svc.search(&user_ctx, &query).await.unwrap();
        assert_eq!(total, 3);
        assert_eq!(entries.len(), 1, "second page should have 1 remaining entry");
    }

    // ---- fetch_kek_assignments ----

    #[tokio::test]
    async fn fetch_kek_assignments_returns_initial_assignment() {
        let svc = make_service();
        let created = svc
            .create(&sys_ctx(), &ns("/kek"), Metadata::default(), ResourceStatus::Active)
            .await
            .unwrap();

        let assignments = svc.fetch_kek_assignments(&sys_ctx(), created.id).await.unwrap();
        assert_eq!(assignments.len(), 1);
        assert!(assignments[0].is_active);
    }

    fn parse_query(json: &str) -> NamespaceSearchQuery {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn namespace_search_query_status_defaults_to_empty() {
        let q = parse_query(r#"{}"#);
        assert!(q.status.is_empty());
    }

    #[test]
    fn namespace_search_query_status_single_value() {
        let q = parse_query(r#"{"status":["Active"]}"#);
        assert_eq!(q.status, vec![ResourceStatus::Active]);
    }

    #[test]
    fn namespace_search_query_status_multiple_values() {
        let q = parse_query(r#"{"status":["Active","Disabled","Deleted"]}"#);
        assert_eq!(
            q.status,
            vec![
                ResourceStatus::Active,
                ResourceStatus::Disabled,
                ResourceStatus::Deleted
            ]
        );
    }

    #[test]
    fn namespace_search_query_status_invalid_returns_error() {
        let result: Result<NamespaceSearchQuery, _> = serde_json::from_str(r#"{"status":["bogus"]}"#);
        assert!(result.is_err());
    }

    #[test]
    fn namespace_search_query_limit_and_offset() {
        let q = parse_query(r#"{"limit":25,"offset":50}"#);
        assert_eq!(q.limit, Some(25));
        assert_eq!(q.offset, Some(50));
    }
}
