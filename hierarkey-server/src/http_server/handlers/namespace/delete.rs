// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::{ApiPath, ApiQuery};
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Deserialize, Default)]
pub struct DeleteQuery {
    #[serde(default)]
    pub delete_secrets: bool,
}

#[axum::debug_handler]
pub(crate) async fn delete(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(param): ApiPath<String>,
    ApiQuery(query): ApiQuery<DeleteQuery>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::NamespaceDeleteFailed,
    };

    debug!("Deleting namespace '{}'", &param);

    // Find and fetch the namespace (handles both short-id and path).
    // Use a system context: namespace:delete does not imply namespace:describe.
    let namespace = super::resolve_namespace(&state, &CallContext::system(), ctx, &param).await?;

    // Protect the /$hierarkey system namespace from deletion
    if namespace.namespace.as_str() == "/$hierarkey" {
        return Err(HttpError {
            http: StatusCode::FORBIDDEN,
            fail_code: ApiCode::NamespaceDeleteFailed,
            reason: ApiErrorCode::Forbidden,
            message: "The /$hierarkey system namespace cannot be deleted".into(),
            details: None,
        });
    }

    let result = state
        .rbac_service
        .require_permission(
            &call_ctx,
            Permission::NamespaceDelete,
            RbacResource::Namespace {
                path: namespace.namespace.to_string(),
            },
        )
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_DELETE, outcome).with_resource(
                "namespace",
                namespace.id.0,
                namespace.namespace.as_str(),
            )
        })
        .await
        .ctx(ctx)?;

    let result = state
        .secret_service
        .delete_namespace(&call_ctx, namespace.id, query.delete_secrets)
        .await;
    let deleted = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_DELETE, outcome).with_resource(
                "namespace",
                namespace.id.0,
                namespace.namespace.as_str(),
            )
        })
        .await
        .ctx(ctx)?;

    if !deleted {
        warn!("Namespace '{}' could not be deleted completely. ", &param);
        return Err(HttpError {
            http: StatusCode::CONFLICT,
            fail_code: ApiCode::NamespaceDeleteFailed,
            reason: ApiErrorCode::PreconditionFailed,
            message: format!("Namespace '{}' could not be deleted completely", &param),
            details: None,
        });
    }

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_DELETE, AuditOutcome::Success).with_resource(
                "namespace",
                namespace.id.0,
                namespace.namespace.as_str(),
            ),
        )
        .await;

    let status = ApiStatus::new(ApiCode::NamespaceDeleted, "Namespace successfully deleted");

    Ok(Json(ApiResponse::ok_no_data(status)))
}
