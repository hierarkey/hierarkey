// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::manager::rbac::role::{AccountBindings, Role, RoleWithRules};
use crate::manager::rbac::rule::Rule;
use crate::rbac::Permission;
use crate::rbac::spec::RuleSpec;
use crate::rbac::{RbacAllowedRequest, RbacAllowedResponse, RbacExplainResponse, RbacResource, RoleId, RuleId};
use crate::service::account::AccountId;
use crate::{RbacManager, ResolveOne};
use hierarkey_core::Labels;
use hierarkey_core::error::validation::ValidationError;
use hierarkey_core::{CkError, CkResult, Metadata};
use std::sync::Arc;
use tracing::debug;

pub struct RuleListItem {
    pub rule: Rule,
    pub role_count: usize,
    pub account_count: usize,
}

fn rbac_platform_resource() -> RbacResource {
    RbacResource::Platform
}

pub struct RbacService {
    rbac_manager: Arc<RbacManager>,
}

impl RbacService {
    pub fn new(rbac_manager: Arc<RbacManager>) -> Self {
        Self { rbac_manager }
    }

    pub async fn resolve_short_rule_id(&self, _ctx: &CallContext, prefix_id: &str) -> CkResult<ResolveOne<RuleId>> {
        self.rbac_manager.resolve_short_rule_id(prefix_id).await
    }

    pub async fn is_allowed(&self, _ctx: &CallContext, request: RbacAllowedRequest) -> CkResult<RbacAllowedResponse> {
        self.rbac_manager.is_allowed(request).await
    }

    /// Check if the actor in `ctx` has `permission` on `resource`.
    /// Returns `Ok(true)` for system actors (bypass) or allowed accounts,
    /// `Ok(false)` if denied. Propagates DB/internal errors as `Err`.
    pub async fn check_permission(
        &self,
        ctx: &CallContext,
        permission: Permission,
        resource: RbacResource,
    ) -> CkResult<bool> {
        if ctx.actor.is_system() {
            return Ok(true);
        }
        let account_id = *ctx.actor.require_account_id()?;
        let response = self
            .rbac_manager
            .is_allowed(RbacAllowedRequest {
                subject: account_id,
                permission,
                resource,
                resource_labels: Labels::new(),
            })
            .await?;
        Ok(response.allowed)
    }

    /// Like [`check_permission`] but also passes the resource's labels for `where` condition evaluation.
    pub async fn check_permission_with_labels(
        &self,
        ctx: &CallContext,
        permission: Permission,
        resource: RbacResource,
        resource_labels: Labels,
    ) -> CkResult<bool> {
        if ctx.actor.is_system() {
            return Ok(true);
        }
        let account_id = *ctx.actor.require_account_id()?;
        let response = self
            .rbac_manager
            .is_allowed(RbacAllowedRequest {
                subject: account_id,
                permission,
                resource,
                resource_labels,
            })
            .await?;
        Ok(response.allowed)
    }

    /// Check if the actor in `ctx` has `permission` on `resource`.
    /// System actors bypass RBAC. Returns `Err(CkError::PermissionDenied)` if denied.
    pub async fn require_permission(
        &self,
        ctx: &CallContext,
        permission: Permission,
        resource: RbacResource,
    ) -> CkResult<()> {
        self.require_permission_with_labels(ctx, permission, resource, Labels::new())
            .await
    }

    /// Like [`require_permission`] but also passes the resource's labels for `where` condition evaluation.
    pub async fn require_permission_with_labels(
        &self,
        ctx: &CallContext,
        permission: Permission,
        resource: RbacResource,
        resource_labels: Labels,
    ) -> CkResult<()> {
        if ctx.actor.is_system() {
            debug!(
                request_id = %ctx.request_id,
                permission = %permission,
                resource = %resource,
                "rbac: system actor — bypassing check"
            );
            return Ok(());
        }

        let account_id = *ctx.actor.require_account_id()?;
        debug!(
            request_id = %ctx.request_id,
            account_id = %account_id,
            permission = %permission,
            resource = %resource,
            "rbac: checking permission"
        );

        let response = self
            .rbac_manager
            .is_allowed(RbacAllowedRequest {
                subject: account_id,
                permission,
                resource: resource.clone(),
                resource_labels,
            })
            .await?;

        if response.allowed {
            debug!(
                request_id = %ctx.request_id,
                account_id = %account_id,
                permission = %permission,
                resource = %resource,
                resource = %resource,
                matched_rule = ?response.matched_rule,
                "rbac: allowed"
            );
            Ok(())
        } else {
            debug!(
                request_id = %ctx.request_id,
                account_id = %account_id,
                permission = %permission,
                resource = %resource,
                resource = %resource,
                matched_rule = ?response.matched_rule,
                "rbac: denied"
            );
            Err(CkError::PermissionDenied)
        }
    }

    pub async fn explain(
        &self,
        ctx: &CallContext,
        request: RbacAllowedRequest,
        verbose: bool,
    ) -> CkResult<RbacExplainResponse> {
        // Anyone can explain their own permissions; explaining another account requires rbac:admin
        if !ctx.actor.is_system() {
            let caller_id = *ctx.actor.require_account_id()?;
            if caller_id != request.subject {
                self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
                    .await?;
            }
        }
        self.rbac_manager.explain(request, verbose).await
    }

    pub async fn get_bindings_for_account(
        &self,
        ctx: &CallContext,
        account_id: AccountId,
    ) -> CkResult<AccountBindings> {
        if !ctx.actor.is_system() {
            let caller_id = *ctx.actor.require_account_id()?;
            if caller_id != account_id {
                self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
                    .await?;
            }
        }
        self.rbac_manager.get_bindings_for_account(account_id).await
    }

    /// Returns bindings for all accounts. Requires `RbacAdmin` permission.
    /// Each entry is `(short_id, AccountBindings)`.
    pub async fn get_bindings_for_all_accounts(&self, ctx: &CallContext) -> CkResult<Vec<(String, AccountBindings)>> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;

        let account_ids = self.rbac_manager.list_all_account_ids().await?;
        let mut result = Vec::with_capacity(account_ids.len());
        for (account_id, short_id) in account_ids {
            let bindings = self.rbac_manager.get_bindings_for_account(account_id).await?;
            result.push((short_id, bindings));
        }
        Ok(result)
    }

    // ----------------------------------------------------------------------------------------

    pub async fn role_create(&self, ctx: &CallContext, name: String, metadata: Metadata) -> CkResult<Role> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;
        self.rbac_manager.role_create(ctx, name, metadata).await
    }

    pub async fn role_update(
        &self,
        ctx: &CallContext,
        role_id: RoleId,
        name: Option<String>,
        description: Option<String>,
    ) -> CkResult<Role> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;
        self.rbac_manager.role_update(ctx, role_id, name, description).await
    }

    pub async fn role_delete(&self, ctx: &CallContext, role_id: RoleId) -> CkResult<()> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;
        self.rbac_manager.role_delete(ctx, role_id).await
    }

    pub async fn role_get(&self, _ctx: &CallContext, role_id: RoleId) -> CkResult<RoleWithRules> {
        self.rbac_manager.role_get(role_id).await
    }

    pub async fn role_get_by_name(&self, _ctx: &CallContext, role_name: &str) -> CkResult<RoleWithRules> {
        self.rbac_manager.role_get_by_name(role_name).await
    }

    pub async fn role_search(&self, ctx: &CallContext) -> CkResult<Vec<RoleWithRules>> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;
        self.rbac_manager.role_search().await
    }

    // ----------------------------------------------------------------------------------------

    pub async fn rule_create(&self, ctx: &CallContext, spec: RuleSpec, metadata: Metadata) -> CkResult<Rule> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;
        self.rbac_manager.rule_create(ctx, spec, metadata).await
    }

    // pub async fn rule_update(&self, rule_id: RuleId, req: RuleUpdate) -> CkResult<Rule> {
    //     self.rbac_manager.rule_update(rule_id, req).await
    // }

    pub async fn rule_delete(&self, ctx: &CallContext, rule_id: RuleId) -> CkResult<()> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;
        self.rbac_manager.rule_delete(ctx, rule_id).await
    }

    pub async fn rule_get(&self, _ctx: &CallContext, rule_id: RuleId) -> CkResult<Rule> {
        self.rbac_manager.rule_get(rule_id).await
    }

    pub async fn rule_search(&self, _ctx: &CallContext) -> CkResult<Vec<RuleListItem>> {
        self.rbac_manager.rule_search().await
    }

    // ----------------------------------------------------------------------------------------

    pub async fn role_add_rule(&self, ctx: &CallContext, role_id: RoleId, rule_id: RuleId) -> CkResult<()> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;
        self.rbac_manager.role_add_rule(ctx, role_id, rule_id).await
    }

    pub async fn role_remove_rule(&self, ctx: &CallContext, role_id: RoleId, rule_id: RuleId) -> CkResult<()> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;
        self.rbac_manager.role_remove_rule(ctx, role_id, rule_id).await
    }

    // ----------------------------------------------------------------------------------------

    pub async fn bind(
        &self,
        ctx: &CallContext,
        account_id: Option<AccountId>,
        label_str: Option<(String, String)>,
        role_id: Option<RoleId>,
        rule_id: Option<RuleId>,
    ) -> CkResult<()> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;

        if account_id.is_none() && label_str.is_none() {
            return Err(ValidationError::Custom("Either account_id or label must be provided".into()).into());
        }
        if role_id.is_none() && rule_id.is_none() {
            return Err(ValidationError::Custom("Either role_id or rule_id must be provided".into()).into());
        }

        struct Label {
            key: String,
            value: String,
        }

        let label = label_str.map(|(k, v)| Label { key: k, value: v });

        match (rule_id, role_id, account_id, label) {
            (Some(rule_id), None, Some(account_id), None) => {
                self.rbac_manager.bind_rule_to_user(ctx, rule_id, account_id).await
            }
            (Some(rule_id), None, None, Some(label)) => {
                self.rbac_manager
                    .bind_rule_to_label(ctx, rule_id, &label.key, &label.value)
                    .await
            }
            (None, Some(role_id), Some(account_id), None) => {
                self.rbac_manager.bind_role_to_user(ctx, role_id, account_id).await
            }
            (None, Some(role_id), None, Some(label)) => {
                self.rbac_manager
                    .bind_role_to_label(ctx, role_id, &label.key, &label.value)
                    .await
            }
            _ => Err(ValidationError::Custom("Invalid combination of parameters".into()).into()),
        }
    }

    pub async fn unbind(
        &self,
        ctx: &CallContext,
        account_id: Option<AccountId>,
        label_str: Option<(String, String)>,
        role_id: Option<RoleId>,
        rule_id: Option<RuleId>,
    ) -> CkResult<()> {
        self.require_permission(ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await?;

        if account_id.is_none() && label_str.is_none() {
            return Err(ValidationError::Custom("Either account_id or label must be provided".into()).into());
        }
        if role_id.is_none() && rule_id.is_none() {
            return Err(ValidationError::Custom("Either role_id or rule_id must be provided".into()).into());
        }

        struct Label {
            key: String,
            value: String,
        }

        let label = label_str.map(|(k, v)| Label { key: k, value: v });

        match (rule_id, role_id, account_id, label) {
            (Some(rule_id), None, Some(account_id), None) => {
                self.rbac_manager.unbind_rule_from_user(ctx, rule_id, account_id).await
            }
            (Some(rule_id), None, None, Some(label)) => {
                self.rbac_manager
                    .unbind_rule_from_label(ctx, rule_id, &label.key, &label.value)
                    .await
            }
            (None, Some(role_id), Some(account_id), None) => {
                self.rbac_manager.unbind_role_from_user(ctx, role_id, account_id).await
            }
            (None, Some(role_id), None, Some(label)) => {
                self.rbac_manager
                    .unbind_role_from_label(ctx, role_id, &label.key, &label.value)
                    .await
            }
            _ => Err(ValidationError::Custom("Invalid combination of parameters".into()).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::manager::rbac::{InMemoryRbacStore, RbacStore};

    fn system_ctx() -> CallContext {
        CallContext::system()
    }

    fn make_service() -> RbacService {
        let store = Arc::new(InMemoryRbacStore::new());
        let manager = Arc::new(RbacManager::new(store));
        RbacService::new(manager)
    }

    /// Create a service together with a `CallContext` whose account already holds
    /// the `RbacAdmin` permission, so that service-layer permission checks pass.
    async fn make_service_with_admin_ctx() -> (RbacService, CallContext) {
        use crate::rbac::spec::RuleSpec;

        let store = Arc::new(InMemoryRbacStore::new());
        let manager = Arc::new(RbacManager::new(store.clone()));
        let svc = RbacService::new(manager);

        let admin_id = crate::manager::account::AccountId::new();
        let admin_ctx = CallContext::for_account(admin_id);

        // Bootstrap directly on the store to avoid the chicken-and-egg of needing
        // permission to create the permission-granting rule.
        let spec = RuleSpec::try_from("allow rbac:admin to all").unwrap();
        let rule = store
            .rule_create(admin_id, spec, hierarkey_core::Metadata::new())
            .await
            .expect("bootstrap rule_create");
        store
            .bind_rule_to_user(admin_id, rule.id, admin_id)
            .await
            .expect("bootstrap bind_rule_to_user");

        (svc, admin_ctx)
    }

    #[test]
    fn rbac_platform_resource_is_platform() {
        assert_eq!(rbac_platform_resource(), RbacResource::Platform);
    }

    // ---- require_permission: system actor bypasses all checks ----

    #[tokio::test]
    async fn require_permission_system_always_allowed() {
        let svc = make_service();
        let ctx = system_ctx();
        let result = svc
            .require_permission(&ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn require_permission_account_without_rule_is_denied() {
        let svc = make_service();
        let account_id = AccountId::new();
        let ctx = CallContext::for_account(account_id);
        let result = svc
            .require_permission(&ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await;
        assert!(matches!(result, Err(CkError::PermissionDenied)));
    }

    #[tokio::test]
    async fn platform_admin_permission_implies_rbac_admin() {
        use crate::manager::rbac::{InMemoryRbacStore, RbacStore};
        use crate::rbac::spec::RuleSpec;

        let store = Arc::new(InMemoryRbacStore::new());
        let manager = Arc::new(RbacManager::new(store.clone()));
        let svc = RbacService::new(manager);

        let account_id = crate::manager::account::AccountId::new();
        let ctx = CallContext::for_account(account_id);

        // Grant platform:admin (superuser) — should imply rbac:admin
        let spec = RuleSpec::try_from("allow platform:admin to platform").unwrap();
        let rule = store
            .rule_create(account_id, spec, hierarkey_core::Metadata::new())
            .await
            .unwrap();
        store.bind_rule_to_user(account_id, rule.id, account_id).await.unwrap();

        let result = svc
            .require_permission(&ctx, Permission::RbacAdmin, rbac_platform_resource())
            .await;
        assert!(result.is_ok(), "platform:admin should imply rbac:admin");
    }

    // ---- bind: validation errors before RBAC (system bypasses RBAC) ----

    #[tokio::test]
    async fn bind_requires_account_or_label() {
        let svc = make_service();
        let ctx = system_ctx();
        let rule_id = RuleId::new();
        let result = svc.bind(&ctx, None, None, None, Some(rule_id)).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("account_id") || msg.contains("label"));
    }

    #[tokio::test]
    async fn bind_requires_role_or_rule() {
        let svc = make_service();
        let ctx = system_ctx();
        let account_id = AccountId::new();
        let result = svc.bind(&ctx, Some(account_id), None, None, None).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("role_id") || msg.contains("rule_id"));
    }

    // ---- mutation methods: system actor can proceed ----

    #[tokio::test]
    async fn role_create_succeeds_for_admin_account() {
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let result = svc.role_create(&ctx, "test-role".to_string(), Metadata::new()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "test-role");
    }

    #[tokio::test]
    async fn rule_create_succeeds_for_admin_account() {
        use crate::rbac::spec::RuleSpec;
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let spec = RuleSpec::try_from("allow namespace:describe to namespace /test").unwrap();
        let result = svc.rule_create(&ctx, spec, Metadata::new()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn rule_create_denied_for_non_admin_account() {
        use crate::rbac::spec::RuleSpec;
        let svc = make_service();
        let account_id = AccountId::new();
        let ctx = CallContext::for_account(account_id);
        let spec = RuleSpec::try_from("allow namespace:describe to namespace /test").unwrap();
        let result = svc.rule_create(&ctx, spec, Metadata::new()).await;
        assert!(matches!(result, Err(CkError::PermissionDenied)));
    }

    #[tokio::test]
    async fn role_delete_denied_for_non_admin_account() {
        let svc = make_service();
        let account_id = AccountId::new();
        let ctx = CallContext::for_account(account_id);
        let result = svc.role_delete(&ctx, RoleId::new()).await;
        assert!(matches!(result, Err(CkError::PermissionDenied)));
    }

    // ---- role soft-delete ----------------------------------------------------------------

    #[tokio::test]
    async fn role_delete_succeeds_and_role_is_gone() {
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let role = svc
            .role_create(&ctx, "to-delete".to_string(), Metadata::new())
            .await
            .unwrap();
        svc.role_delete(&ctx, role.id).await.expect("delete should succeed");
        let err = svc.role_get(&ctx, role.id).await;
        assert!(err.is_err(), "deleted role should not be retrievable");
    }

    #[tokio::test]
    async fn role_delete_nonexistent_returns_error() {
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let result = svc.role_delete(&ctx, RoleId::new()).await;
        assert!(result.is_err(), "deleting a nonexistent role should fail");
    }

    #[tokio::test]
    async fn deleted_role_does_not_appear_in_search() {
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let role = svc
            .role_create(&ctx, "searchable".to_string(), Metadata::new())
            .await
            .unwrap();
        svc.role_delete(&ctx, role.id).await.unwrap();
        let roles = svc.role_search(&ctx).await.unwrap();
        assert!(
            !roles.iter().any(|r| r.role.id == role.id),
            "deleted role must not appear in search results"
        );
    }

    // ---- rule soft-delete ----------------------------------------------------------------

    #[tokio::test]
    async fn rule_delete_denied_for_non_admin_account() {
        let svc = make_service();
        let account_id = AccountId::new();
        let ctx = CallContext::for_account(account_id);
        let result = svc.rule_delete(&ctx, RuleId::new()).await;
        assert!(matches!(result, Err(CkError::PermissionDenied)));
    }

    #[tokio::test]
    async fn rule_delete_succeeds_and_rule_is_gone() {
        use crate::rbac::spec::RuleSpec;
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let spec = RuleSpec::try_from("allow namespace:describe to namespace /tmp").unwrap();
        let rule = svc.rule_create(&ctx, spec, Metadata::new()).await.unwrap();
        svc.rule_delete(&ctx, rule.id).await.expect("delete should succeed");
        let err = svc.rule_get(&ctx, rule.id).await;
        assert!(err.is_err(), "deleted rule should not be retrievable");
    }

    #[tokio::test]
    async fn rule_delete_nonexistent_returns_error() {
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let result = svc.rule_delete(&ctx, RuleId::new()).await;
        assert!(result.is_err(), "deleting a nonexistent rule should fail");
    }

    #[tokio::test]
    async fn deleted_rule_does_not_appear_in_rule_search() {
        use crate::rbac::spec::RuleSpec;
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let spec = RuleSpec::try_from("allow namespace:describe to namespace /tmp").unwrap();
        let rule = svc.rule_create(&ctx, spec, Metadata::new()).await.unwrap();
        svc.rule_delete(&ctx, rule.id).await.unwrap();
        let items = svc.rule_search(&ctx).await.unwrap();
        assert!(
            !items.iter().any(|i| i.rule.id == rule.id),
            "deleted rule must not appear in rule_search"
        );
    }

    // ---- role_add_rule / role_remove_rule ------------------------------------------------

    #[tokio::test]
    async fn role_remove_rule_removes_rule_from_role() {
        use crate::rbac::spec::RuleSpec;
        let (svc, ctx) = make_service_with_admin_ctx().await;

        let role = svc
            .role_create(&ctx, "myrole".to_string(), Metadata::new())
            .await
            .unwrap();
        let spec = RuleSpec::try_from("allow namespace:describe to namespace /x").unwrap();
        let rule = svc.rule_create(&ctx, spec, Metadata::new()).await.unwrap();

        svc.role_add_rule(&ctx, role.id, rule.id).await.unwrap();
        let with_rule = svc.role_get(&ctx, role.id).await.unwrap();
        assert!(
            with_rule.rules.iter().any(|r| r.id == rule.id),
            "rule should be in role after add"
        );

        svc.role_remove_rule(&ctx, role.id, rule.id).await.unwrap();
        let without_rule = svc.role_get(&ctx, role.id).await.unwrap();
        assert!(
            !without_rule.rules.iter().any(|r| r.id == rule.id),
            "rule should be gone after remove"
        );

        // The rule itself must still exist
        let still_there = svc.rule_get(&ctx, rule.id).await;
        assert!(still_there.is_ok(), "rule should still exist after being removed from role");
    }

    #[tokio::test]
    async fn role_readd_rule_after_removal() {
        use crate::rbac::spec::RuleSpec;
        let (svc, ctx) = make_service_with_admin_ctx().await;

        let role = svc
            .role_create(&ctx, "rerole".to_string(), Metadata::new())
            .await
            .unwrap();
        let spec = RuleSpec::try_from("allow namespace:describe to namespace /y").unwrap();
        let rule = svc.rule_create(&ctx, spec, Metadata::new()).await.unwrap();

        svc.role_add_rule(&ctx, role.id, rule.id).await.unwrap();
        svc.role_remove_rule(&ctx, role.id, rule.id).await.unwrap();
        svc.role_add_rule(&ctx, role.id, rule.id)
            .await
            .expect("re-adding a removed rule should succeed");

        let with_rule = svc.role_get(&ctx, role.id).await.unwrap();
        assert!(
            with_rule.rules.iter().any(|r| r.id == rule.id),
            "rule should be back after re-add"
        );
    }

    // ---- deleted rule no longer enforced for account ------------------------------------

    #[tokio::test]
    async fn deleted_rule_not_returned_for_account() {
        use crate::manager::rbac::{InMemoryRbacStore, RbacStore};
        use crate::rbac::spec::RuleSpec;

        let store = Arc::new(InMemoryRbacStore::new());
        let manager = Arc::new(RbacManager::new(store.clone()));
        let svc = RbacService::new(manager);

        let admin_id = AccountId::new();
        let admin_ctx = CallContext::for_account(admin_id);

        let spec = RuleSpec::try_from("allow rbac:admin to all").unwrap();
        let bootstrap = store.rule_create(admin_id, spec, Metadata::new()).await.unwrap();
        store.bind_rule_to_user(admin_id, bootstrap.id, admin_id).await.unwrap();

        // Create a second rule and bind it to admin
        let spec2 = RuleSpec::try_from("allow namespace:describe to namespace /z").unwrap();
        let rule = svc.rule_create(&admin_ctx, spec2, Metadata::new()).await.unwrap();
        svc.bind(&admin_ctx, Some(admin_id), None, None, Some(rule.id))
            .await
            .unwrap();

        // Delete the rule
        svc.rule_delete(&admin_ctx, rule.id).await.unwrap();

        // The deleted rule must not be returned via get_rules_for_account
        let rules = store.get_rules_for_account(admin_id).await.unwrap();
        assert!(
            !rules.iter().any(|r| r.id == rule.id),
            "deleted rule must not be returned for account"
        );
    }

    // ---- bind_rule_to_label / bind_role_to_label ----------------------------------------

    #[tokio::test]
    async fn bind_rule_to_label_succeeds() {
        use crate::rbac::spec::RuleSpec;
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let spec = RuleSpec::try_from("allow namespace:describe to namespace /lbl").unwrap();
        let rule = svc.rule_create(&ctx, spec, Metadata::new()).await.unwrap();
        let result = svc
            .bind(&ctx, None, Some(("env".to_string(), "prod".to_string())), None, Some(rule.id))
            .await;
        assert!(result.is_ok(), "bind_rule_to_label should succeed");
    }

    #[tokio::test]
    async fn bind_role_to_label_succeeds() {
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let role = svc
            .role_create(&ctx, "lblrole".to_string(), Metadata::new())
            .await
            .unwrap();
        let result = svc
            .bind(&ctx, None, Some(("team".to_string(), "ops".to_string())), Some(role.id), None)
            .await;
        assert!(result.is_ok(), "bind_role_to_label should succeed");
    }

    #[tokio::test]
    async fn bind_rule_to_label_idempotent() {
        use crate::rbac::spec::RuleSpec;
        let (svc, ctx) = make_service_with_admin_ctx().await;
        let spec = RuleSpec::try_from("allow namespace:describe to namespace /lbl2").unwrap();
        let rule = svc.rule_create(&ctx, spec, Metadata::new()).await.unwrap();
        svc.bind(
            &ctx,
            None,
            Some(("env".to_string(), "staging".to_string())),
            None,
            Some(rule.id),
        )
        .await
        .unwrap();
        // Second bind must not error (ON CONFLICT DO NOTHING)
        let result = svc
            .bind(
                &ctx,
                None,
                Some(("env".to_string(), "staging".to_string())),
                None,
                Some(rule.id),
            )
            .await;
        assert!(result.is_ok(), "duplicate label bind should be idempotent");
    }
}
