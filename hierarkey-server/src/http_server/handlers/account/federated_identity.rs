// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! Handlers for managing the federated identity link on a service account.
//!
//! Routes (all require an authenticated `Auth`-scoped token AND admin privilege):
//!   POST   /v1/accounts/{account}/federated-identity   link
//!   GET    /v1/accounts/{account}/federated-identity   describe
//!   DELETE /v1/accounts/{account}/federated-identity   unlink

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::account::resolve_account;
use crate::manager::federated_identity::FederatedIdentityRow;
use crate::service::account::AccountType;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::license::Feature;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LinkRequest {
    /// Must match the `id` field of one of the `[[auth.federated]]` config entries.
    pub provider_id: String,
    /// The stable issuer string for this identity
    /// (e.g. OIDC issuer URL or Kubernetes API server URL).
    pub external_issuer: String,
    /// The stable subject identifier within the issuer
    /// (e.g. OIDC `sub` claim or Kubernetes user UID/username).
    pub external_subject: String,
}

#[derive(Debug, Serialize)]
pub struct FederatedIdentityResponse {
    pub provider_id: String,
    pub external_issuer: String,
    pub external_subject: String,
    pub created_at: DateTime<Utc>,
}

impl From<FederatedIdentityRow> for FederatedIdentityResponse {
    fn from(row: FederatedIdentityRow) -> Self {
        Self {
            provider_id: row.provider_id,
            external_issuer: row.external_issuer,
            external_subject: row.external_subject,
            created_at: row.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/accounts/{account}/federated-identity`
///
/// Link an external identity to a service account. The account must be of
/// type `service` and must not already have a federated identity linked.
#[axum::debug_handler]
pub(crate) async fn link(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    Extension(auth): Extension<AuthUser>,
    Path(account_name): Path<String>,
    ApiJson(req): ApiJson<LinkRequest>,
) -> ApiResult<Json<ApiResponse<FederatedIdentityResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountUpdateFailed,
    };

    if !state
        .license_service
        .get_effective_license()
        .has_feature(&Feature::FederatedAuth)
    {
        return Err(HttpError::forbidden(
            ctx,
            "Federated identity management is only available in the Commercial edition.",
        ));
    }

    if !state.account_service.is_admin(&call_ctx, auth.user.id).await.ctx(ctx)? {
        return Err(HttpError::forbidden(
            ctx,
            "Admin privilege required to manage federated identities",
        ));
    }

    let account = resolve_account(&state, &call_ctx, ctx, &account_name)
        .await?
        .ok_or_else(|| HttpError::not_found(ctx, format!("account '{account_name}' not found")))?;

    if account.account_type != AccountType::Service {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::ValidationFailed,
            message: "federated identities can only be linked to service accounts".into(),
            details: None,
        });
    }

    // Validate that the provider_id is known to this server.
    let provider = state
        .federated_providers
        .iter()
        .find(|p| p.provider_id() == req.provider_id)
        .ok_or_else(|| HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::ValidationFailed,
            message: format!("unknown provider_id '{}' — check server configuration", req.provider_id),
            details: None,
        })?;

    // Validate that external_issuer matches the provider's configured issuer so the
    // link can actually be resolved at auth time (exchange() always returns provider.issuer()).
    let configured_issuer = provider.issuer();
    if !configured_issuer.is_empty() && configured_issuer != req.external_issuer {
        return Err(HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::ValidationFailed,
            message: format!(
                "external_issuer '{}' does not match the configured issuer for provider '{}' (expected '{}')",
                req.external_issuer, req.provider_id, configured_issuer
            ),
            details: None,
        });
    }

    let actor_id = auth.user.id;

    let result = state
        .federated_identity_manager
        .link(
            account.id,
            &req.provider_id,
            &req.external_issuer,
            &req.external_subject,
            actor_id,
        )
        .await;

    let row = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, outcome)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({
                    "action": "link_federated_identity",
                    "provider_id": req.provider_id,
                    "external_issuer": req.external_issuer,
                }))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({
                    "action": "link_federated_identity",
                    "provider_id": req.provider_id,
                    "external_issuer": req.external_issuer,
                })),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountUpdated, "Federated identity linked".to_string());
    Ok(Json(ApiResponse::ok(status, FederatedIdentityResponse::from(row))))
}

/// `GET /v1/accounts/{account}/federated-identity`
///
/// Return the federated identity currently linked to a service account,
/// or 404 if none is linked.
#[axum::debug_handler]
pub(crate) async fn describe(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    Extension(auth): Extension<AuthUser>,
    Path(account_name): Path<String>,
) -> ApiResult<Json<ApiResponse<FederatedIdentityResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountRetrievalFailed,
    };

    if !state.account_service.is_admin(&call_ctx, auth.user.id).await.ctx(ctx)? {
        return Err(HttpError::forbidden(
            ctx,
            "Admin privilege required to view federated identities",
        ));
    }

    let account = resolve_account(&state, &call_ctx, ctx, &account_name)
        .await?
        .ok_or_else(|| HttpError::not_found(ctx, format!("account '{account_name}' not found")))?;

    let row = state
        .federated_identity_manager
        .find_by_account(account.id)
        .await
        .ctx(ctx)?
        .ok_or_else(|| {
            HttpError::not_found(ctx, format!("account '{account_name}' has no linked federated identity"))
        })?;

    let status = ApiStatus::new(ApiCode::AccountRetrieve, "Federated identity retrieved".to_string());
    Ok(Json(ApiResponse::ok(status, FederatedIdentityResponse::from(row))))
}

/// `DELETE /v1/accounts/{account}/federated-identity`
///
/// Remove the federated identity link from a service account.
#[axum::debug_handler]
pub(crate) async fn unlink(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    Extension(auth): Extension<AuthUser>,
    Path(account_name): Path<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountUpdateFailed,
    };

    if !state.account_service.is_admin(&call_ctx, auth.user.id).await.ctx(ctx)? {
        return Err(HttpError::forbidden(
            ctx,
            "Admin privilege required to manage federated identities",
        ));
    }

    let account = resolve_account(&state, &call_ctx, ctx, &account_name)
        .await?
        .ok_or_else(|| HttpError::not_found(ctx, format!("account '{account_name}' not found")))?;

    let deleted = state.federated_identity_manager.unlink(account.id).await.ctx(ctx)?;

    if !deleted {
        return Err(HttpError::not_found(
            ctx,
            format!("account '{account_name}' has no linked federated identity"),
        ));
    }

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account.name.as_str())
                .with_metadata(serde_json::json!({ "action": "unlink_federated_identity" })),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountUpdated, "Federated identity unlinked".to_string());
    Ok(Json(ApiResponse::ok(status, ())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::test_utils::create_mock_app_state;
    use crate::http_server::AppState;
    use crate::http_server::federated_auth_provider::{FederatedAuthProvider, FederatedIdentity};
    use crate::http_server::handlers::auth_response::AuthScope;
    use crate::http_server::middleware::{audit_ctx_middleware, auth_middleware};
    use crate::manager::account::Password;
    use crate::service::account::{AccountData, CustomAccountData, CustomServiceAccountData, CustomUserAccountData};
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware as axum_middleware;
    use axum::routing::post;
    use hierarkey_core::license::{EffectiveLicense, Feature, Tier};
    use hierarkey_core::resources::AccountName;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn create_licensed_app_state() -> AppState {
        let state = create_mock_app_state();
        state.license_service.set_effective(EffectiveLicense {
            tier: Tier::Commercial,
            licensee: Some("Test".to_string()),
            license_id: Some("test-license".to_string()),
            expires_at: None,
            is_community_fallback: false,
            features: vec![Feature::FederatedAuth],
            grace_features: vec![],
            grace_period_ends: None,
        });
        state
    }

    // ---------------------------------------------------------------------------
    // Stub provider
    // ---------------------------------------------------------------------------

    struct StubProvider {
        id: String,
    }

    #[async_trait::async_trait]
    impl FederatedAuthProvider for StubProvider {
        fn provider_id(&self) -> &str {
            &self.id
        }
        fn provider_type(&self) -> &str {
            "stub"
        }
        fn issuer(&self) -> &str {
            "https://stub.example.com"
        }
        fn audience(&self) -> Option<&str> {
            None
        }
        fn jwks_url(&self) -> Option<&str> {
            None
        }
        async fn exchange(
            &self,
            _credential: &str,
        ) -> Result<FederatedIdentity, crate::http_server::api_error::HttpError> {
            // exchange() is never called by the link/describe/unlink handlers —
            // those only check that the provider_id exists in the configured list.
            Err(crate::http_server::api_error::HttpError {
                http: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: hierarkey_core::api::status::ApiCode::InternalError,
                reason: hierarkey_core::api::status::ApiErrorCode::InternalError,
                message: "StubProvider::exchange should not be called in account handler tests".to_string(),
                details: None,
            })
        }
    }

    // ---------------------------------------------------------------------------
    // Router / account helpers
    // ---------------------------------------------------------------------------

    fn build_test_router(state: AppState) -> Router {
        Router::new()
            .route(
                "/v1/accounts/{account}/federated-identity",
                post(link).get(describe).delete(unlink),
            )
            .layer(axum_middleware::from_fn_with_state(state.clone(), auth_middleware))
            .layer(axum_middleware::from_fn(audit_ctx_middleware))
            .with_state(state)
    }

    async fn create_admin_token(state: &AppState) -> String {
        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let data = AccountData {
            account_name: AccountName::try_from(format!("admin-{}", uuid::Uuid::new_v4().simple())).unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                full_name: None,
                email: None,
                password: Password::new("password-for-test-12345"),
                must_change_password: false,
            }),
        };
        let admin = state.account_service.create_account(&ctx, &data).await.unwrap();
        let (token, _) = state
            .auth_service
            .create_pat(&ctx, &admin, "test-admin-token", 60, AuthScope::Auth)
            .await
            .unwrap();
        token
    }

    async fn create_service_account(state: &AppState, name: &str) -> crate::Account {
        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let data = AccountData {
            account_name: AccountName::try_from(name.to_string()).unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::Service(CustomServiceAccountData::Passphrase {
                passphrase: Password::new("svc-passphrase-for-test"),
            }),
        };
        state.account_service.create_account(&ctx, &data).await.unwrap()
    }

    async fn create_user_account(state: &AppState, name: &str) -> crate::Account {
        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let data = AccountData {
            account_name: AccountName::try_from(name.to_string()).unwrap(),
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
        state.account_service.create_account(&ctx, &data).await.unwrap()
    }

    fn link_body(provider_id: &str) -> String {
        serde_json::json!({
            "provider_id": provider_id,
            "external_issuer": "https://stub.example.com",
            "external_subject": "test-subject"
        })
        .to_string()
    }

    async fn do_request(
        app: Router,
        method: &str,
        path: &str,
        token: &str,
        body: Option<String>,
    ) -> axum::http::StatusCode {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"));

        if let Some(ref b) = body {
            builder = builder.header("content-type", "application/json");
            let req = builder.body(Body::from(b.clone())).unwrap();
            app.oneshot(req).await.unwrap().status()
        } else {
            let req = builder.body(Body::empty()).unwrap();
            app.oneshot(req).await.unwrap().status()
        }
    }

    // ---------------------------------------------------------------------------
    // link handler tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn link_account_not_found_returns_404() {
        let mut state = create_licensed_app_state();
        state.federated_providers = vec![Arc::new(StubProvider { id: "oidc".to_string() })];
        let token = create_admin_token(&state).await;
        let app = build_test_router(state);

        let status = do_request(
            app,
            "POST",
            "/v1/accounts/nonexistent-account/federated-identity",
            &token,
            Some(link_body("oidc")),
        )
        .await;

        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn link_user_account_returns_bad_request() {
        let mut state = create_licensed_app_state();
        state.federated_providers = vec![Arc::new(StubProvider { id: "oidc".to_string() })];
        let name = format!("user-{}", uuid::Uuid::new_v4().simple());
        create_user_account(&state, &name).await;
        let token = create_admin_token(&state).await;
        let app = build_test_router(state);

        let status = do_request(
            app,
            "POST",
            &format!("/v1/accounts/{name}/federated-identity"),
            &token,
            Some(link_body("oidc")),
        )
        .await;

        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn link_mismatched_issuer_returns_bad_request() {
        let mut state = create_licensed_app_state();
        state.federated_providers = vec![Arc::new(StubProvider { id: "oidc".to_string() })];
        let name = format!("svc-{}", uuid::Uuid::new_v4().simple());
        create_service_account(&state, &name).await;
        let token = create_admin_token(&state).await;
        let app = build_test_router(state);

        let body = serde_json::json!({
            "provider_id": "oidc",
            "external_issuer": "https://wrong-issuer.example.com",
            "external_subject": "test-subject"
        })
        .to_string();

        let status = do_request(
            app,
            "POST",
            &format!("/v1/accounts/{name}/federated-identity"),
            &token,
            Some(body),
        )
        .await;

        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn link_unknown_provider_id_returns_bad_request() {
        let mut state = create_licensed_app_state();
        state.federated_providers = vec![Arc::new(StubProvider { id: "oidc".to_string() })];
        let name = format!("svc-{}", uuid::Uuid::new_v4().simple());
        create_service_account(&state, &name).await;
        let token = create_admin_token(&state).await;
        let app = build_test_router(state);

        let status = do_request(
            app,
            "POST",
            &format!("/v1/accounts/{name}/federated-identity"),
            &token,
            Some(link_body("unknown-provider")),
        )
        .await;

        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    // ---------------------------------------------------------------------------
    // describe handler tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn describe_account_not_found_returns_404() {
        let state = create_mock_app_state();
        let token = create_admin_token(&state).await;
        let app = build_test_router(state);

        let status = do_request(app, "GET", "/v1/accounts/no-such-account/federated-identity", &token, None).await;

        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    // ---------------------------------------------------------------------------
    // unlink handler tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unlink_account_not_found_returns_404() {
        let state = create_mock_app_state();
        let token = create_admin_token(&state).await;
        let app = build_test_router(state);

        let status = do_request(app, "DELETE", "/v1/accounts/no-such-account/federated-identity", &token, None).await;

        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }
}
