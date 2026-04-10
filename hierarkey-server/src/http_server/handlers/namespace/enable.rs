// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use tracing::{debug, warn};

#[axum::debug_handler]
pub(crate) async fn enable(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(param): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::NamespaceEnableFailed,
    };

    debug!("Enabling namespace '{}'", &param);

    // Find and fetch the namespace (handles both short-id and path)
    let namespace = super::resolve_namespace(&state, &call_ctx, ctx, &param).await?;

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
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_STATUS_CHANGE, outcome)
                .with_resource("namespace", namespace.id.0, namespace.namespace.as_str())
                .with_metadata(serde_json::json!({"action": "enable"}))
        })
        .await
        .ctx(ctx)?;

    let result = state.namespace_service.enable(&call_ctx, namespace.id).await;
    let enabled = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_STATUS_CHANGE, outcome)
                .with_resource("namespace", namespace.id.0, namespace.namespace.as_str())
                .with_metadata(serde_json::json!({"action": "enable"}))
        })
        .await
        .ctx(ctx)?;

    if !enabled {
        warn!("Namespace '{}' could not be enabled", &param);

        return Err(HttpError {
            http: StatusCode::CONFLICT,
            fail_code: ApiCode::NamespaceEnableFailed,
            reason: ApiErrorCode::PreconditionFailed,
            message: format!("Namespace '{}' could not be enabled", &param),
            details: None,
        });
    }

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_STATUS_CHANGE, AuditOutcome::Success)
                .with_resource("namespace", namespace.id.0, namespace.namespace.as_str())
                .with_metadata(serde_json::json!({"action": "enable"})),
        )
        .await;

    let status = ApiStatus::new(ApiCode::NamespaceEnabled, "Namespace enabled successfully");

    Ok(Json(ApiResponse::ok_no_data(status)))
}
