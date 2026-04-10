// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::secret_response::SecretResponse;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::Revision;
use serde::Deserialize;
use tracing::debug;

#[derive(Deserialize)]
pub(crate) struct ActivateSecretRequest {
    reason: Option<String>,
}

#[axum::debug_handler]
pub(crate) async fn activate(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(sec_ref): ApiPath<String>,
    ApiJson(payload): ApiJson<ActivateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretRevisionActivateFailed,
    };

    debug!("Received request to activate secret: {:?}", payload.reason);

    let secret = super::resolve_secret(&state, &call_ctx, ctx, &sec_ref).await?;

    // Determine revision: for short-id lookups use active, for path lookups parse from ref
    let revision = if sec_ref.starts_with("sec_") {
        secret.active_revision
    } else {
        use hierarkey_core::resources::SecretRef;
        let parsed = SecretRef::from_string(&format!("/{sec_ref}")).ctx(ctx)?;
        match parsed.revision {
            Some(Revision::Active) => secret.active_revision,
            Some(Revision::Latest) => secret.latest_revision,
            Some(rev) => rev,
            None => secret.active_revision,
        }
    };

    let Some(secret_revision) = state
        .secret_service
        .find_secret_revision(&call_ctx, secret.id, revision)
        .await
        .ctx(ctx)?
    else {
        return Err(HttpError {
            http: StatusCode::NOT_FOUND,
            fail_code: ApiCode::SecretRevisionActivateFailed,
            reason: ApiErrorCode::NotFound,
            message: format!("Revision '{revision}' of secret not found"),
            details: None,
        });
    };

    // Activate the secret revision (service enforces namespace-active check)
    let result = state
        .secret_service
        .set_active_revision(&call_ctx, secret_revision.id)
        .await;
    state.audit_service.log_err(result, |outcome| {
        AuditEvent::from_ctx(&call_ctx, event_type::SECRET_STATUS_CHANGE, outcome)
            .with_resource("secret", secret.id.0, &secret.ref_key)
            .with_metadata(serde_json::json!({"action": "activate_revision", "revision": secret_revision.revision.to_string()}))
    }).await.ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_STATUS_CHANGE, AuditOutcome::Success)
                .with_resource("secret", secret.id.0, &secret.ref_key)
                .with_metadata(serde_json::json!({"action": "activate_revision", "revision": secret_revision.revision.to_string()})),
        )
        .await;

    let revisions = state
        .secret_service
        .get_secret_revisions(&call_ctx, secret.id)
        .await
        .ctx(ctx)?;
    let data = SecretResponse::new(secret, revisions);

    let status = ApiStatus::new(ApiCode::SecretUpdated, "Secret revision activated successfully");
    Ok(Json(ApiResponse::ok(status, data)))
}
