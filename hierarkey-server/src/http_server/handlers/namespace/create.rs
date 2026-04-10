// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::resource::ResourceStatus;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::namespace_response::NamespaceResponse;
use crate::manager::account::AccountId;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::ApiCode::NamespaceCreateFailed;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::NamespaceString;
use hierarkey_core::{Labels, Metadata};
use serde::Deserialize;
use tracing::{debug, trace};

#[derive(Deserialize, Debug)]
pub struct CreateNamespaceRequest {
    namespace: NamespaceString,
    description: Option<String>,
    labels: Labels,
}

#[axum::debug_handler]
pub(crate) async fn create(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiJson(payload): ApiJson<CreateNamespaceRequest>,
) -> ApiResult<Json<ApiResponse<NamespaceResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: NamespaceCreateFailed,
    };

    let result = state
        .rbac_service
        .require_permission(
            &call_ctx,
            Permission::NamespaceCreate,
            RbacResource::Namespace {
                path: payload.namespace.to_string(),
            },
        )
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_CREATE, outcome)
                .with_metadata(serde_json::json!({"namespace": payload.namespace.to_string()}))
        })
        .await
        .ctx(ctx)?;

    debug!("Received request to create namespace");

    // Check if the namespace already exists.
    // Use a system context: we've already verified namespace:create above.
    // fetch_by_namespace would require namespace:describe which the caller may not hold.
    let exists = state
        .namespace_service
        .fetch_by_namespace(&CallContext::system(), &payload.namespace)
        .await
        .ctx(ctx)?;

    if exists.is_some() {
        return Err(HttpError {
            http: StatusCode::CONFLICT,
            fail_code: NamespaceCreateFailed,
            reason: ApiErrorCode::AlreadyExists,
            message: format!("Namespace '{}' already exists", payload.namespace),
            details: None,
        });
    }

    let mut metadata = Metadata::default();
    if let Some(ref description) = payload.description {
        metadata.add_description(description);
    }
    metadata.add_labels(payload.labels.clone());

    trace!("Creating namespace '{}' with metadata: {:?}", &payload.namespace, &metadata);
    let result = state
        .namespace_service
        .create(&call_ctx, &payload.namespace, metadata, ResourceStatus::Active)
        .await;
    let namespace = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_CREATE, outcome)
                .with_metadata(serde_json::json!({"namespace": payload.namespace.to_string()}))
        })
        .await
        .ctx(ctx)?;

    // Load the revision and create response
    let keks = state
        .namespace_service
        .fetch_kek_assignments(&call_ctx, namespace.id)
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_CREATE, AuditOutcome::Success).with_resource(
                "namespace",
                namespace.id.0,
                payload.namespace.to_string(),
            ),
        )
        .await;

    let created_by_name = super::resolve_actor_name(&state, &call_ctx, namespace.created_by.map(AccountId)).await;
    let data = NamespaceResponse::new(&namespace, keks).with_actors(created_by_name, None);

    let status = ApiStatus::new(ApiCode::NamespaceCreated, "Namespace created successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
