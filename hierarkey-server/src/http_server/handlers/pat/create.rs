// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::auth_response::AuthScope;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Deserialize)]
pub(crate) struct CreateTokenRequest {
    description: String,
    #[serde(default = "default_ttl_minutes")]
    ttl_minutes: i64,
}

fn default_ttl_minutes() -> i64 {
    24 * 60 * 30 // Default to 30 days
}

#[derive(Serialize)]
pub(crate) struct CreateTokenResponse {
    id: crate::PatId,
    short_id: String,
    token: Zeroizing<String>,
    description: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[axum::debug_handler]
pub(crate) async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(req): ApiJson<CreateTokenRequest>,
) -> ApiResult<Json<ApiResponse<CreateTokenResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AuthTokenIssueFailed,
    };

    // Cap the caller-supplied TTL to the server-configured maximum.
    let ttl_minutes = req.ttl_minutes.min(state.auth_service.access_token_ttl_minutes);

    let result = state
        .auth_service
        .create_pat(&call_ctx, &auth.user, &req.description, ttl_minutes, AuthScope::Auth)
        .await;
    let (raw_token, pat) = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::PAT_ISSUED, outcome)
        })
        .await
        .ctx(ctx)?;

    let data = CreateTokenResponse {
        id: pat.id,
        short_id: pat.short_id.to_string(),
        token: Zeroizing::new(raw_token),
        description: pat.description,
        expires_at: pat.expires_at,
    };

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::PAT_ISSUED, AuditOutcome::Success).with_resource(
                "pat",
                pat.id.0,
                pat.short_id.to_string(),
            ),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AuthTokenIssued, "Personal access token created successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
