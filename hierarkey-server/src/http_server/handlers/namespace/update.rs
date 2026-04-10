// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiJson, ApiPath};
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::namespace_response::NamespaceResponse;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::Labels;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::Deserialize;
use tracing::debug;

#[derive(Deserialize)]
pub struct UpdateNamespaceRequest {
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
    ApiPath(param): ApiPath<String>,
    ApiJson(payload): ApiJson<UpdateNamespaceRequest>,
) -> ApiResult<Json<ApiResponse<NamespaceResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::NamespaceUpdateFailed,
    };

    debug!("Received request to update namespace");

    // Find and fetch the namespace (handles both short-id and path).
    // Use a system context: namespace:update:meta does not imply namespace:describe.
    let namespace = super::resolve_namespace(&state, &CallContext::system(), ctx, &param).await?;

    let result = state
        .rbac_service
        .require_permission(
            &call_ctx,
            Permission::NamespaceUpdateMeta,
            RbacResource::Namespace {
                path: namespace.namespace.to_string(),
            },
        )
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_UPDATE, outcome).with_resource(
                "namespace",
                namespace.id.0,
                namespace.namespace.as_str(),
            )
        })
        .await
        .ctx(ctx)?;

    let mut metadata = namespace.metadata.clone();
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

    let result = state.namespace_service.update(&call_ctx, namespace.id, metadata).await;
    let namespace = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_UPDATE, outcome).with_resource(
                "namespace",
                namespace.id.0,
                namespace.namespace.as_str(),
            )
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
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_UPDATE, AuditOutcome::Success).with_resource(
                "namespace",
                namespace.id.0,
                namespace.namespace.as_str(),
            ),
        )
        .await;

    let data = NamespaceResponse::new(&namespace, keks);

    let status = ApiStatus::new(ApiCode::NamespaceUpdated, "Namespace updated successfully");

    Ok(Json(ApiResponse::ok(status, data)))
}
