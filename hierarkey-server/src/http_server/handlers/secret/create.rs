// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use super::validation::validate_secret_data;
use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::secret_response::SecretResponse;
use crate::manager::account::AccountId;
use crate::manager::secret::secret_data::SecretData;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::search::query::SecretType;
use hierarkey_core::api::status::ApiCode::SecretCreateFailed;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::SecretRef;
use hierarkey_core::{Labels, Metadata};
use serde::Deserialize;
use tracing::{debug, trace};

#[derive(Deserialize)]
pub(crate) struct CreateSecretRequest {
    sec_ref: String,
    value_b64: String,
    secret_type: SecretType,
    description: Option<String>,
    labels: Labels,
}

#[axum::debug_handler]
pub(crate) async fn create(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(payload): ApiJson<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: SecretCreateFailed,
    };

    debug!("Received request to create secret");

    let sec_ref = SecretRef::from_string(&payload.sec_ref).ctx(ctx)?;

    let result = state
        .rbac_service
        .require_permission(
            &call_ctx,
            Permission::SecretCreate,
            RbacResource::Secret {
                namespace: sec_ref.namespace.to_string(),
                path: sec_ref.key.to_string(),
            },
        )
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_CREATE, outcome)
                .with_metadata(serde_json::json!({"sec_ref": sec_ref.to_string()}))
        })
        .await
        .ctx(ctx)?;

    // Use a system context here: we've already verified secret:create permission above.
    // namespace_service.fetch_by_namespace would require namespace:describe which is a separate
    // permission the caller may not hold.
    let namespace = state
        .namespace_service
        .fetch_by_namespace(&CallContext::system(), &sec_ref.namespace)
        .await
        .ctx(ctx)?;

    let Some(namespace) = namespace else {
        return Err(HttpError::not_found(
            ctx,
            format!("Namespace '{}' is not found", sec_ref.namespace),
        ));
    };

    let secret_data = SecretData::from_base64(&payload.value_b64).ctx(ctx)?;

    validate_secret_data(&secret_data, payload.secret_type).map_err(|e| HttpError {
        http: StatusCode::UNPROCESSABLE_ENTITY,
        fail_code: SecretCreateFailed,
        reason: ApiErrorCode::ValidationFailed,
        message: e.to_string(),
        details: None,
    })?;

    // Set metadata
    let mut metadata = Metadata::new();
    if let Some(ref description) = payload.description {
        metadata.add_description(description);
    }
    metadata.add_labels(payload.labels.clone());
    metadata.set_secret_type(payload.secret_type);

    // Create the secret and first revision
    trace!("Creating secret '{}' with metadata: {:?}", &payload.sec_ref, &metadata);
    let result = state
        .secret_service
        .create_new_secret(
            &call_ctx,
            namespace.id,
            &sec_ref,
            crate::global::resource::ResourceStatus::Active,
            metadata,
            secret_data,
            None,
        )
        .await;
    let secret = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_CREATE, outcome)
                .with_metadata(serde_json::json!({"sec_ref": sec_ref.to_string()}))
        })
        .await
        .ctx(ctx)?;

    // Load the revision and create response.
    // Use a system context here: we've already verified secret:create permission above.
    // get_secret_revisions would require secret:history:read which the caller may not hold.
    let revisions = state
        .secret_service
        .get_secret_revisions(&CallContext::system(), secret.id)
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::SECRET_CREATE, AuditOutcome::Success).with_resource(
                "secret",
                secret.id.0,
                sec_ref.to_string(),
            ),
        )
        .await;

    let created_by_name = super::resolve_actor_name(&state, &call_ctx, secret.created_by.map(AccountId)).await;
    let data = SecretResponse::new(secret, revisions).with_actors(created_by_name, None);

    let status = ApiStatus::new(ApiCode::SecretCreated, "Secret created successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
