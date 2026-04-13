// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct SetCertRequest {
    /// PEM-encoded client certificate to register, or `null` to remove.
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetCertResponse {
    pub fingerprint: Option<String>,
    pub subject: Option<String>,
}

#[axum::debug_handler]
pub(crate) async fn set_cert(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    Extension(auth): Extension<AuthUser>,
    Path(account_name): Path<AccountName>,
    ApiJson(req): ApiJson<SetCertRequest>,
) -> ApiResult<Json<ApiResponse<SetCertResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountUpdateFailed,
    };

    let account = state
        .account_service
        .find_by_name(&call_ctx, &account_name)
        .await
        .ctx(ctx)?
        .ok_or_else(|| HttpError::not_found(ctx, format!("account '{account_name}' not found")))?;

    // Authorization: caller must own the account or be an admin.
    if auth.user.id != account.id && !state.account_service.is_admin(&call_ctx, auth.user.id).await.ctx(ctx)? {
        return Err(HttpError::forbidden(
            ctx,
            "Admin privilege required to set certificate on another account",
        ));
    }

    let (fingerprint, subject) = match req.certificate_pem {
        None => (None, None),
        Some(pem_str) => {
            let pem_bytes = pem_str.as_bytes();
            let (_, pem) = parse_x509_pem(pem_bytes).map_err(|_| HttpError {
                http: StatusCode::BAD_REQUEST,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::ValidationFailed,
                message: "failed to parse PEM certificate".into(),
                details: None,
            })?;

            let der = pem.contents;
            let (_, cert) = parse_x509_certificate(&der).map_err(|_| HttpError {
                http: StatusCode::BAD_REQUEST,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::ValidationFailed,
                message: "failed to parse X.509 certificate".into(),
                details: None,
            })?;

            let fingerprint = {
                let hash = Sha256::digest(&der);
                hash.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
            };
            let subject = cert.subject().to_string();
            (Some(fingerprint), Some(subject))
        }
    };

    let result = state
        .account_service
        .set_client_cert(&call_ctx, account.id, fingerprint.clone(), subject.clone())
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, outcome)
                .with_resource("account", account.id.0, account_name.as_str())
                .with_metadata(serde_json::json!({"action": "set_cert", "fingerprint": &fingerprint}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account_name.as_str())
                .with_metadata(serde_json::json!({"action": "set_cert", "fingerprint": fingerprint})),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountUpdated, "Client certificate updated".to_string());
    Ok(Json(ApiResponse::ok(status, SetCertResponse { fingerprint, subject })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::test_utils::create_mock_app_state;
    use crate::http_server::handlers::auth_response::AuthScope;
    use crate::http_server::middleware::{audit_ctx_middleware, auth_middleware};
    use crate::manager::account::Password;
    use crate::service::account::{AccountData, CustomAccountData, CustomUserAccountData};
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware as axum_middleware;
    use axum::routing::post;
    use tower::ServiceExt;

    fn build_test_router(state: crate::http_server::AppState) -> Router {
        Router::new()
            .route("/v1/accounts/{account}/cert", post(set_cert))
            .layer(axum_middleware::from_fn_with_state(state.clone(), auth_middleware))
            .layer(axum_middleware::from_fn(audit_ctx_middleware))
            .with_state(state)
    }

    /// Create a regular (non-admin) user account and return a valid Auth-scoped token for it.
    async fn create_user_with_token(state: &crate::http_server::AppState, name: &str) -> (crate::Account, String) {
        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let data = AccountData {
            account_name: AccountName::try_from(name.to_string()).unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                full_name: None,
                email: None,
                password: Password::new("test-password-12345"),
                must_change_password: false,
            }),
        };
        let account = state.account_service.create_account(&ctx, &data).await.unwrap();
        let (token, _) = state
            .auth_service
            .create_pat(&ctx, &account, "test-token", 60, AuthScope::Auth)
            .await
            .unwrap();
        (account, token)
    }

    /// Create a user account, promote it to admin, and return a valid token for it.
    async fn create_admin_with_token(state: &crate::http_server::AppState, name: &str) -> (crate::Account, String) {
        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let (account, token) = create_user_with_token(state, name).await;
        state.account_service.grant_admin(&ctx, account.id).await.unwrap();
        (account, token)
    }

    async fn post_set_cert(app: Router, account_name: &str, token: &str) -> axum::http::StatusCode {
        let body = serde_json::json!({ "certificate_pem": null }).to_string();
        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/accounts/{account_name}/cert"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn owner_can_update_own_cert() {
        let state = create_mock_app_state();
        let (account, token) = create_user_with_token(&state, "certowner").await;
        let app = build_test_router(state);

        let status = post_set_cert(app, account.name.as_str(), &token).await;

        assert_eq!(status, axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_can_update_cert_on_other_account() {
        let state = create_mock_app_state();
        let (target, _) = create_user_with_token(&state, "certtarget").await;
        let (_, admin_token) = create_admin_with_token(&state, "certadmin").await;
        let app = build_test_router(state);

        let status = post_set_cert(app, target.name.as_str(), &admin_token).await;

        assert_eq!(status, axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn non_admin_cannot_update_cert_on_other_account() {
        let state = create_mock_app_state();
        let (target, _) = create_user_with_token(&state, "certvictim").await;
        let (_, attacker_token) = create_user_with_token(&state, "certattacker").await;
        let app = build_test_router(state);

        let status = post_set_cert(app, target.name.as_str(), &attacker_token).await;

        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    }
}
