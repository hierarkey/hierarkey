// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub mod bind;
pub mod bindings;
pub mod explain;
pub mod role;
pub mod rule;
pub mod unbind;

use crate::api::v1::dto::global::AccountRefDto;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::manager::account::AccountId;
use hierarkey_core::resources::AccountName;

/// Resolve an AccountId to an AccountRefDto (short_id + name). Returns None if not found.
pub(super) async fn resolve_actor_ref(
    state: &AppState,
    call_ctx: &CallContext,
    id: AccountId,
) -> Option<AccountRefDto> {
    state
        .account_service
        .find_by_id(call_ctx, id)
        .await
        .ok()
        .flatten()
        .map(|a| AccountRefDto {
            account_id: a.short_id.to_string(),
            account_name: AccountName::try_from(a.name.as_str()).unwrap_or_else(|_| AccountName::unknown()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::test_utils::create_mock_app_state_with_rbac_store;
    use crate::http_server::AppState;
    use crate::http_server::handlers::auth_response::AuthScope;
    use crate::http_server::middleware::{audit_ctx_middleware, auth_middleware};
    use crate::manager::account::Password;
    use crate::manager::rbac::{InMemoryRbacStore, RbacStore};
    use crate::rbac::spec::RuleSpec;
    use crate::service::account::{AccountData, CustomAccountData, CustomUserAccountData};
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware as axum_middleware;
    use axum::routing::{get, post};
    use hierarkey_core::Metadata;
    use hierarkey_core::resources::AccountName;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn build_test_router(state: AppState) -> Router {
        Router::new()
            .route("/bind", post(bind::bind))
            .route("/unbind", post(unbind::unbind))
            .route("/bindings", post(bindings::bindings))
            .route("/bindings/all", post(bindings::bindings_all))
            .route("/role", post(role::create))
            .route("/role/search", post(role::search))
            .route("/role/{name}", get(role::describe).patch(role::update).delete(role::delete))
            .route("/role/{name}/rules", post(role::add))
            .route("/rule", post(rule::create))
            .route("/rule/search", post(rule::search))
            .route("/rule/{id}", get(rule::describe).delete(rule::delete))
            .route("/explain", post(explain::explain))
            .layer(axum_middleware::from_fn_with_state(state.clone(), auth_middleware))
            .layer(axum_middleware::from_fn(audit_ctx_middleware))
            .with_state(state)
    }

    /// Create a PAT for a freshly created regular user with no RBAC bindings.
    async fn create_non_admin_token(state: &AppState) -> String {
        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let data = AccountData {
            account_name: AccountName::try_from(format!("user-{}", uuid::Uuid::new_v4().simple())).unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                full_name: None,
                email: None,
                password: Password::new("user-password-for-test-12345"),
                must_change_password: false,
            }),
        };
        let user = state.account_service.create_account(&ctx, &data).await.unwrap();
        let (token, _) = state
            .auth_service
            .create_pat(&ctx, &user, "test-user-token", 60, AuthScope::Auth)
            .await
            .unwrap();
        token
    }

    /// Create a PAT for a user who has been granted PlatformAdmin via RBAC.
    /// Writes directly to the RBAC store to sidestep the chicken-and-egg problem
    /// (the store is empty, so there is no actor that can pass service-layer checks yet).
    async fn create_platform_admin_token(state: &AppState, rbac_store: &Arc<InMemoryRbacStore>) -> String {
        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let data = AccountData {
            account_name: AccountName::try_from(format!("admin-{}", uuid::Uuid::new_v4().simple())).unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                full_name: None,
                email: None,
                password: Password::new("admin-password-for-test-12345"),
                must_change_password: false,
            }),
        };
        let admin = state.account_service.create_account(&ctx, &data).await.unwrap();

        // Write directly to the store to bootstrap the first PlatformAdmin rule.
        let spec = RuleSpec::try_from("allow platform:admin to platform").unwrap();
        let rule = rbac_store.rule_create(admin.id, spec, Metadata::new()).await.unwrap();
        rbac_store.bind_rule_to_user(admin.id, rule.id, admin.id, None).await.unwrap();

        let (token, _) = state
            .auth_service
            .create_pat(&ctx, &admin, "test-admin-token", 60, AuthScope::Auth)
            .await
            .unwrap();
        token
    }

    async fn post_json(app: Router, path: &str, token: &str, body: &str) -> axum::http::StatusCode {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    async fn get_req(app: Router, path: &str, token: &str) -> axum::http::StatusCode {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    // ---------------------------------------------------------------------------
    // bind
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn bind_non_admin_is_forbidden() {
        let (state, _store) = create_mock_app_state_with_rbac_store();
        let token = create_non_admin_token(&state).await;
        let app = build_test_router(state);
        let status = post_json(app, "/bind", &token, r#"{"account_name": "some-account"}"#).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn bind_platform_admin_passes_permission_check() {
        let (state, store) = create_mock_app_state_with_rbac_store();
        let token = create_platform_admin_token(&state, &store).await;
        let app = build_test_router(state);
        // Empty body triggers validation error (400) rather than permission denied (403)
        let status = post_json(app, "/bind", &token, r#"{}"#).await;
        assert_ne!(status, axum::http::StatusCode::FORBIDDEN);
    }

    // ---------------------------------------------------------------------------
    // unbind
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unbind_non_admin_is_forbidden() {
        let (state, _store) = create_mock_app_state_with_rbac_store();
        let token = create_non_admin_token(&state).await;
        let app = build_test_router(state);
        let status = post_json(app, "/unbind", &token, r#"{"account_name": "some-account"}"#).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }

    // ---------------------------------------------------------------------------
    // role create / describe
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn role_create_non_admin_is_forbidden() {
        let (state, _store) = create_mock_app_state_with_rbac_store();
        let token = create_non_admin_token(&state).await;
        let app = build_test_router(state);
        let status = post_json(app, "/role", &token, r#"{"name": "evil-role"}"#).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn role_create_platform_admin_succeeds() {
        let (state, store) = create_mock_app_state_with_rbac_store();
        let token = create_platform_admin_token(&state, &store).await;
        let app = build_test_router(state);
        let status = post_json(app, "/role", &token, r#"{"name": "my-role"}"#).await;
        assert_eq!(status, axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn role_describe_non_admin_is_forbidden() {
        let (state, _store) = create_mock_app_state_with_rbac_store();
        let token = create_non_admin_token(&state).await;
        let app = build_test_router(state);
        let status = get_req(app, "/role/some-role", &token).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }

    // ---------------------------------------------------------------------------
    // rule create
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn rule_create_non_admin_is_forbidden() {
        let (state, _store) = create_mock_app_state_with_rbac_store();
        let token = create_non_admin_token(&state).await;
        let app = build_test_router(state);
        let status = post_json(
            app,
            "/rule",
            &token,
            r#"{"spec": "allow platform:admin to platform"}"#,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rule_create_platform_admin_succeeds() {
        let (state, store) = create_mock_app_state_with_rbac_store();
        let token = create_platform_admin_token(&state, &store).await;
        let app = build_test_router(state);
        let status = post_json(
            app,
            "/rule",
            &token,
            r#"{"spec": "allow platform:admin to platform"}"#,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
    }

    // ---------------------------------------------------------------------------
    // bindings
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn bindings_non_admin_is_forbidden() {
        let (state, _store) = create_mock_app_state_with_rbac_store();
        let token = create_non_admin_token(&state).await;
        let app = build_test_router(state);
        // Requesting another account's bindings without PlatformAdmin → 403
        let status = post_json(app, "/bindings", &token, r#"{"account": "other-account"}"#).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn bindings_all_non_admin_is_forbidden() {
        let (state, _store) = create_mock_app_state_with_rbac_store();
        let token = create_non_admin_token(&state).await;
        let app = build_test_router(state);
        let status = post_json(app, "/bindings/all", &token, r#"{}"#).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }
}
