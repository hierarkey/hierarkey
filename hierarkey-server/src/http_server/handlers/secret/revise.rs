// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use super::validation::validate_secret_data;
use crate::ResolveOne;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::secret_response::SecretResponse;
use crate::manager::secret::secret_data::SecretData;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::ApiCode::SecretRevisionCreateFailed;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::SecretRef;
use serde::Deserialize;
use tracing::{debug, trace};

#[derive(Deserialize)]
pub(crate) struct ReviseSecretRequest {
    sec_ref: String,
    value_b64: String,
    note: Option<String>,
    activate: bool,
}

#[axum::debug_handler]
pub(crate) async fn revise(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(payload): ApiJson<ReviseSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: SecretRevisionCreateFailed,
    };

    debug!("Received request to revise secret");

    // If sec_ref looks like a short-id, resolve it to the actual secret first
    let secret = if payload.sec_ref.starts_with("sec_") {
        let result = state
            .secret_service
            .resolve_short_secret_id(&payload.sec_ref)
            .await
            .ctx(ctx)?;
        let id = match result {
            ResolveOne::None => {
                return Err(HttpError::not_found(ctx, format!("Secret '{}' not found", payload.sec_ref)));
            }
            ResolveOne::One(id) => id,
            ResolveOne::Many(n) => {
                let msg = match n {
                    Some(n) => format!("Ambiguous id: {n} secrets match '{}'", payload.sec_ref),
                    None => format!("Ambiguous id: multiple secrets match '{}'", payload.sec_ref),
                };
                return Err(HttpError::bad_request(ctx, msg));
            }
        };
        state
            .secret_service
            .find_secret(&call_ctx, id)
            .await
            .ctx(ctx)?
            .ok_or_else(|| HttpError::not_found(ctx, format!("Secret '{}' not found", payload.sec_ref)))?
    } else {
        let sec_ref = SecretRef::from_string(&payload.sec_ref).ctx(ctx)?;

        // Find the secret by ref (service enforces RBAC)
        state
            .secret_service
            .find_by_ref(&call_ctx, &sec_ref)
            .await
            .ctx(ctx)?
            .ok_or_else(|| HttpError::not_found(ctx, format!("Secret '{}' does not exist", payload.sec_ref)))?
    };

    let secret_data = SecretData::from_base64(&payload.value_b64).ctx(ctx)?;

    validate_secret_data(&secret_data, secret.metadata.secret_type()).map_err(|e| HttpError {
        http: StatusCode::UNPROCESSABLE_ENTITY,
        fail_code: SecretRevisionCreateFailed,
        reason: ApiErrorCode::ValidationFailed,
        message: e.to_string(),
        details: None,
    })?;

    // Create the new revision (service enforces namespace-active check)
    trace!("Revising secret '{}' with note: {:?}", &payload.sec_ref, &payload.note);
    let result = state
        .secret_service
        .create_secret_revision(&call_ctx, secret.id, payload.note, secret_data)
        .await;
    let secret_revision = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_REVISE, outcome).with_resource(
                "secret",
                secret.id.0,
                &secret.ref_key,
            )
        })
        .await
        .ctx(ctx)?;

    if payload.activate {
        trace!("Setting active revision to {}", secret_revision.revision);
        let result = state
            .secret_service
            .set_active_revision(&call_ctx, secret_revision.id)
            .await;
        state.audit_service.log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_STATUS_CHANGE, outcome)
                .with_resource("secret", secret.id.0, &secret.ref_key)
                .with_metadata(serde_json::json!({"action": "activate_revision", "revision": secret_revision.revision.to_string()}))
        }).await.ctx(ctx)?;
    }

    // Load the revision and create response
    let revisions = state
        .secret_service
        .get_secret_revisions(&call_ctx, secret.id)
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_REVISE, AuditOutcome::Success).with_resource(
                "secret",
                secret.id.0,
                &secret.ref_key,
            ),
        )
        .await;

    let data = SecretResponse::new(secret, revisions);

    let status = ApiStatus::new(ApiCode::SecretCreated, "Secret created successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
