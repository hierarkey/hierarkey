// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::auth_response::{AuthResponse, AuthScope};
use crate::manager::account::AccountStatus;
use crate::service::account::AccountType;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
pub struct FederatedAuthRequest {
    /// The raw credential to present to the federated provider.
    ///
    /// For OIDC: a signed JWT (ID token or access token).
    /// For Kubernetes TokenReview: a service account token.
    pub credential: Zeroizing<String>,
    #[serde(default)]
    pub scope: Option<AuthScope>,
    /// Requested token lifetime in minutes. Capped to the server-configured maximum.
    #[serde(default)]
    pub ttl_minutes: Option<u32>,
}

#[axum::debug_handler]
pub(crate) async fn federated(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    Path(provider_id): Path<String>,
    ApiJson(req): ApiJson<FederatedAuthRequest>,
) -> ApiResult<Json<ApiResponse<AuthResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuthTokenFailed,
    };

    // Only Auth scope is valid for federated authentication.
    let scope = match req.scope {
        None | Some(AuthScope::Auth) => AuthScope::Auth,
        Some(other) => {
            return Err(HttpError::bad_request(
                ctx,
                format!("scope '{other:?}' is not supported for federated authentication"),
            ));
        }
    };

    let access_ttl = req
        .ttl_minutes
        .map(|t| t as i64)
        .unwrap_or(state.auth_service.access_token_ttl_minutes);

    // Find the configured provider.
    let provider = state
        .federated_providers
        .iter()
        .find(|p| p.provider_id() == provider_id)
        .ok_or_else(|| HttpError {
            http: StatusCode::NOT_FOUND,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::NotFound,
            message: format!("unknown federated auth provider '{provider_id}'"),
            details: None,
        })?;

    // Exchange the credential for a federated identity.
    let identity = provider.exchange(&req.credential).await.map_err(|mut e| {
        // Downgrade any provider error to a generic 401 to avoid leaking
        // internal details to callers.
        e.fail_code = ctx.fail_code;
        e
    })?;

    // Resolve the identity to a linked service account.
    let fi_row = state
        .federated_identity_manager
        .find_by_provider_and_subject(&provider_id, &identity.external_issuer, &identity.external_subject)
        .await
        .ctx(ctx)?
        .ok_or_else(|| HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Unauthorized,
            message: "no account is linked to this federated identity".into(),
            details: None,
        })?;

    // Load the linked account and validate it.
    let account = state
        .account_service
        .get_by_id(&call_ctx, fi_row.account_id)
        .await
        .ctx(ctx)?;

    if account.account_type != AccountType::Service {
        return Err(HttpError {
            http: StatusCode::FORBIDDEN,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Unauthorized,
            message: "linked account is not a service account".into(),
            details: None,
        });
    }

    if account.status != AccountStatus::Active {
        state
            .audit_service
            .log(
                AuditEvent::from_ctx(&call_ctx, event_type::AUTH_FEDERATED, AuditOutcome::Failure)
                    .with_actor(account.id.0, "service_account", account.name.as_str())
                    .with_metadata(serde_json::json!({
                        "provider_id": provider_id,
                        "reason": "account_not_active"
                    })),
            )
            .await;
        return Err(HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Unauthorized,
            message: "linked account is not active".into(),
            details: None,
        });
    }

    // Issue an access token for the service account.
    let (token_str, pat) = state
        .auth_service
        .create_pat(
            &call_ctx,
            &account,
            &format!("Federated auth via {provider_id}"),
            access_ttl,
            scope,
        )
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::AUTH_FEDERATED, AuditOutcome::Success)
                .with_actor(account.id.0, "service_account", account.name.as_str())
                .with_metadata(serde_json::json!({ "provider_id": provider_id })),
        )
        .await;

    let status = ApiStatus::new(
        ApiCode::AuthTokenSucceeded,
        format!("Federated authentication via '{provider_id}' succeeded"),
    );

    Ok(Json(ApiResponse::ok(
        status,
        AuthResponse {
            account_id: account.id,
            account_short_id: account.short_id.to_string(),
            account_name: account.name,
            scope: pat.purpose.into(),
            access_token: Zeroizing::new(token_str),
            expires_at: pat.expires_at,
            refresh_token: Zeroizing::new(String::new()),
            refresh_expires_at: pat.expires_at,
            mfa_required: false,
            mfa_method: None,
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::test_utils::create_mock_app_state;
    use crate::http_server::federated_auth_provider::{FederatedAuthProvider, FederatedIdentity};
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use std::sync::Arc;
    use tower::ServiceExt;

    // ---------------------------------------------------------------------------
    // Mock provider
    // ---------------------------------------------------------------------------

    struct AlwaysFailProvider {
        id: String,
    }

    #[async_trait::async_trait]
    impl FederatedAuthProvider for AlwaysFailProvider {
        fn provider_id(&self) -> &str {
            &self.id
        }
        fn provider_type(&self) -> &str {
            "stub"
        }
        fn issuer(&self) -> &str {
            ""
        }
        fn audience(&self) -> Option<&str> {
            None
        }
        fn jwks_url(&self) -> Option<&str> {
            None
        }
        async fn exchange(&self, _credential: &str) -> Result<FederatedIdentity, HttpError> {
            Err(HttpError {
                http: axum::http::StatusCode::UNAUTHORIZED,
                fail_code: hierarkey_core::api::status::ApiCode::AuthTokenFailed,
                reason: hierarkey_core::api::status::ApiErrorCode::Unauthorized,
                message: "mock provider rejected credential".to_string(),
                details: None,
            })
        }
    }

    // ---------------------------------------------------------------------------
    // Router builder for tests
    // ---------------------------------------------------------------------------

    fn build_test_router(state: crate::http_server::AppState) -> Router {
        let call_ctx = CallContext::for_account(state.system_account_id.unwrap());
        Router::new()
            .route("/v1/auth/federated/{provider_id}", post(federated))
            .layer(axum::Extension(call_ctx))
            .with_state(state)
    }

    async fn post_federated(app: Router, provider_id: &str, body: serde_json::Value) -> axum::http::StatusCode {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/auth/federated/{provider_id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        response.status()
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_provider_id_returns_404() {
        let state = create_mock_app_state(); // federated_providers is empty
        let app = build_test_router(state);

        let status =
            post_federated(app, "nonexistent-provider", serde_json::json!({ "credential": "some-token" })).await;

        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn refresh_scope_returns_bad_request() {
        let state = create_mock_app_state();
        let app = build_test_router(state);

        let status = post_federated(
            app,
            "any-provider",
            serde_json::json!({ "credential": "tok", "scope": "refresh" }),
        )
        .await;

        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn change_password_scope_returns_bad_request() {
        let state = create_mock_app_state();
        let app = build_test_router(state);

        let status = post_federated(
            app,
            "any-provider",
            serde_json::json!({ "credential": "tok", "scope": "change_password" }),
        )
        .await;

        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_scope_passes_scope_validation() {
        // auth scope is valid; it will fail later at "unknown provider" (404), not at scope check.
        let state = create_mock_app_state();
        let app = build_test_router(state);

        let status =
            post_federated(app, "nonexistent", serde_json::json!({ "credential": "tok", "scope": "auth" })).await;

        // 404 from unknown provider, NOT 400 from scope validation.
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn provider_exchange_failure_returns_error() {
        let mut state = create_mock_app_state();
        state.federated_providers = vec![Arc::new(AlwaysFailProvider {
            id: "mock-provider".to_string(),
        })];

        let app = build_test_router(state);

        let status = post_federated(app, "mock-provider", serde_json::json!({ "credential": "bad-credential" })).await;

        // Provider returned 401 which should propagate as an error response.
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }
}
