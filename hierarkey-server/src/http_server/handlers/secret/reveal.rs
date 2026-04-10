// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use base64::Engine;
use hierarkey_core::CkError;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use hierarkey_core::resources::SecretRef;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Deserialize)]
pub struct RevealSecretRequest {
    sec_ref: String,
}

#[derive(Serialize)]
pub struct RevealSecretResponse {
    sec_ref: SecretRef,
    value_b64: String,
}

#[axum::debug_handler]
pub(crate) async fn reveal(
    State(state): State<AppState>,
    _auth: AuthUser, // extracted to enforce authentication; actor identity flows through call_ctx
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(payload): ApiJson<RevealSecretRequest>,
) -> ApiResult<Json<ApiResponse<RevealSecretResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretRevealFailed,
    };

    debug!("Received request to reveal secret");

    let sec_ref = SecretRef::from_string(&payload.sec_ref).ctx(ctx)?;

    let reveal_result = state.secret_service.reveal_by_ref(&call_ctx, &sec_ref).await;

    let value = match reveal_result {
        Ok(v) => {
            metrics::counter!("hierarkey_secret_reveals_total").increment(1);
            state
                .audit_service
                .log(
                    AuditEvent::from_ctx(&call_ctx, event_type::SECRET_READ, AuditOutcome::Success)
                        .with_resource_ref("secret", sec_ref.to_string()),
                )
                .await;
            v
        }
        Err(e) => {
            let outcome = match &e {
                CkError::Rbac(_) | CkError::PermissionDenied => AuditOutcome::Denied,
                _ => AuditOutcome::Failure,
            };
            state
                .audit_service
                .log(
                    AuditEvent::from_ctx(&call_ctx, event_type::SECRET_READ, outcome)
                        .with_resource_ref("secret", sec_ref.to_string()),
                )
                .await;
            return Err(e).ctx(ctx);
        }
    };

    let value_b64 = base64::engine::general_purpose::STANDARD.encode(value.expose_secret());

    let data = RevealSecretResponse {
        sec_ref: sec_ref.clone(),
        value_b64,
    };

    let status = ApiStatus::new(ApiCode::SecretRevealed, "Secret revealed successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
