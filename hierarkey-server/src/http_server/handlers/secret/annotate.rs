// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::resource::ResourceStatus;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::secret_response::SecretResponse;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::NamespaceString;
use hierarkey_core::{Metadata, resources::Revision};
use serde::Deserialize;
use std::str::FromStr;
use tracing::debug;

#[derive(Deserialize)]
pub(crate) struct AnnotateSecretRequest {
    note: Option<String>,
    clear_note: bool,
}

#[axum::debug_handler]
pub(crate) async fn annotate(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(sec_ref): ApiPath<String>,
    ApiJson(payload): ApiJson<AnnotateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretAnnotateFailed,
    };

    debug!("Received request to annotate secret");

    let secret = super::resolve_secret(&state, &call_ctx, ctx, &sec_ref).await?;

    let ns_path = NamespaceString::from_str(&secret.ref_ns).ctx(ctx)?;
    let Some(namespace) = state
        .namespace_service
        .fetch_by_namespace(&call_ctx, &ns_path)
        .await
        .ctx(ctx)?
    else {
        return Err(HttpError {
            http: StatusCode::NOT_FOUND,
            fail_code: ApiCode::SecretAnnotateFailed,
            reason: ApiErrorCode::NotFound,
            message: format!("Namespace '{}' not found", secret.ref_ns),
            details: None,
        });
    };

    if namespace.status != ResourceStatus::Active {
        return Err(HttpError {
            http: StatusCode::CONFLICT,
            fail_code: ApiCode::SecretAnnotateFailed,
            reason: ApiErrorCode::PreconditionFailed,
            message: format!("Namespace '{}' is not active", secret.ref_ns),
            details: None,
        });
    }

    let result = state
        .rbac_service
        .require_permission(
            &call_ctx,
            Permission::SecretUpdateMeta,
            RbacResource::Secret {
                namespace: secret.ref_ns.clone(),
                path: secret.ref_key.clone(),
            },
        )
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_UPDATE, outcome)
                .with_resource("secret", secret.id.0, &secret.ref_key)
                .with_metadata(serde_json::json!({"action": "annotate"}))
        })
        .await
        .ctx(ctx)?;

    // We need the sec_ref revision info; for short-id lookups, use active/latest
    // Since we resolved by short-id or path, determine revision from the path param
    let revision = if sec_ref.starts_with("sec_") {
        // No revision info for short-id lookups — use active revision
        secret.active_revision
    } else {
        // Parse revision from the ref path
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
            fail_code: ApiCode::SecretAnnotateFailed,
            reason: ApiErrorCode::NotFound,
            message: format!("Revision '{revision}' of secret not found"),
            details: None,
        });
    };

    // Set metadata
    let mut metadata = Metadata::new();
    if payload.clear_note {
        metadata.remove("description");
    } else if let Some(ref note) = payload.note {
        metadata.add_description(note);
    }

    // Update the secret
    let result = state
        .secret_service
        .annotate_secret_revision(&call_ctx, secret_revision.id, metadata)
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_UPDATE, outcome)
                .with_resource("secret", secret.id.0, &secret.ref_key)
                .with_metadata(serde_json::json!({"action": "annotate"}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_UPDATE, AuditOutcome::Success)
                .with_resource("secret", secret.id.0, &secret.ref_key)
                .with_metadata(serde_json::json!({"action": "annotate"})),
        )
        .await;

    let revisions = state
        .secret_service
        .get_secret_revisions(&call_ctx, secret.id)
        .await
        .ctx(ctx)?;
    let data = SecretResponse::new(secret, revisions);

    let status = ApiStatus::new(ApiCode::SecretUpdated, "Secret updated successfully");
    Ok(Json(ApiResponse::ok(status, data)))
}
