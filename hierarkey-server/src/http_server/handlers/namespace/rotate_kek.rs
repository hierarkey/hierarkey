// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiPath;
use crate::http_server::handlers::ApiResult;
use crate::http_server::handlers::namespace_response::KekAssignmentResponse;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::Metadata;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};

#[axum::debug_handler]
pub(crate) async fn rotate_kek(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
    ApiPath(param): ApiPath<String>,
) -> ApiResult<Json<ApiResponse<KekAssignmentResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::KekRotateFailed,
    };

    let namespace = super::resolve_namespace(&state, &call_ctx, ctx, &param).await?;

    let result = state
        .namespace_service
        .rotate_kek(&call_ctx, namespace.id, Metadata::default())
        .await;
    let kek_assignment = state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_KEK_ROTATE, outcome).with_resource(
                "namespace",
                namespace.id.0,
                namespace.namespace.as_str(),
            )
        })
        .await
        .ctx(ctx)?;
    metrics::counter!("hierarkey_kek_rotations_total").increment(1);

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::NAMESPACE_KEK_ROTATE, AuditOutcome::Success).with_resource(
                "namespace",
                namespace.id.0,
                namespace.namespace.as_str(),
            ),
        )
        .await;

    let status = ApiStatus::new(ApiCode::KekRotated, "KEK rotated successfully");

    Ok(Json(ApiResponse::ok(status, KekAssignmentResponse::from(kek_assignment))))
}
