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
use hierarkey_core::{Labels, Metadata};
use serde::Deserialize;
use std::str::FromStr;
use tracing::debug;

#[derive(Deserialize)]
pub(crate) struct UpdateSecretRequest {
    description: Option<String>,
    updated_labels: Labels,
    remove_labels: Vec<String>,
    clear_description: bool,
    clear_labels: bool,
}

#[axum::debug_handler]
pub(crate) async fn update(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(sec_ref): ApiPath<String>,
    ApiJson(payload): ApiJson<UpdateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SecretUpdateFailed,
    };

    debug!("Received request to update secret");

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
            fail_code: ApiCode::SecretUpdateFailed,
            reason: ApiErrorCode::NotFound,
            message: format!("Namespace '{}' not found", secret.ref_ns),
            details: None,
        });
    };

    if namespace.status != ResourceStatus::Active {
        return Err(HttpError {
            http: StatusCode::CONFLICT,
            fail_code: ApiCode::SecretUpdateFailed,
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
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_UPDATE, outcome).with_resource(
                "secret",
                secret.id.0,
                &secret.ref_key,
            )
        })
        .await
        .ctx(ctx)?;

    // Set metadata
    let mut metadata = Metadata::new();
    if payload.clear_description {
        metadata.remove("description");
    } else if let Some(ref description) = payload.description {
        metadata.add_description(description);
    }

    if payload.clear_labels {
        metadata.remove("labels");
    }

    for label in &payload.updated_labels {
        metadata.add_label(label.0, label.1);
    }

    for label in &payload.remove_labels {
        metadata.remove_label(label);
    }

    // Update the secret
    let result = state.secret_service.update_secret(&call_ctx, secret.id, metadata).await;
    let secret = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_UPDATE, outcome).with_resource(
                "secret",
                secret.id.0,
                &secret.ref_key,
            )
        })
        .await
        .ctx(ctx)?;

    let revisions = state
        .secret_service
        .get_secret_revisions(&call_ctx, secret.id)
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_UPDATE, AuditOutcome::Success).with_resource(
                "secret",
                secret.id.0,
                &secret.ref_key,
            ),
        )
        .await;

    let data = SecretResponse::new(secret, revisions);

    let status = ApiStatus::new(ApiCode::SecretUpdated, "Secret updated successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
