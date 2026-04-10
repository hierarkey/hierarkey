// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::extractors::ApiJson;
use crate::http_server::handlers::ApiResult;
use crate::service::audit::{AuditEvent, AuditOutcome, event_type};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct SetCertRequest {
    /// PEM-encoded client certificate to register, or `null` to remove.
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetCertResponse {
    pub fingerprint: Option<String>,
    pub subject: Option<String>,
}

#[axum::debug_handler]
pub(crate) async fn set_cert(
    State(state): State<AppState>,
    Extension(call_ctx): Extension<CallContext>,
    Extension(_auth): Extension<AuthUser>,
    Path(account_name): Path<AccountName>,
    ApiJson(req): ApiJson<SetCertRequest>,
) -> ApiResult<Json<ApiResponse<SetCertResponse>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::AccountUpdateFailed,
    };

    let account = state
        .account_service
        .find_by_name(&call_ctx, &account_name)
        .await
        .ctx(ctx)?
        .ok_or_else(|| HttpError::not_found(ctx, format!("account '{account_name}' not found")))?;

    let (fingerprint, subject) = match req.certificate_pem {
        None => (None, None),
        Some(pem_str) => {
            let pem_bytes = pem_str.as_bytes();
            let (_, pem) = parse_x509_pem(pem_bytes).map_err(|_| HttpError {
                http: StatusCode::BAD_REQUEST,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::ValidationFailed,
                message: "failed to parse PEM certificate".into(),
                details: None,
            })?;

            let der = pem.contents;
            let (_, cert) = parse_x509_certificate(&der).map_err(|_| HttpError {
                http: StatusCode::BAD_REQUEST,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::ValidationFailed,
                message: "failed to parse X.509 certificate".into(),
                details: None,
            })?;

            let fingerprint = {
                let hash = Sha256::digest(&der);
                hash.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
            };
            let subject = cert.subject().to_string();
            (Some(fingerprint), Some(subject))
        }
    };

    let result = state
        .account_service
        .set_client_cert(&call_ctx, account.id, fingerprint.clone(), subject.clone())
        .await;
    state
        .audit_service
        .log_err(result, |outcome| {
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, outcome)
                .with_resource("account", account.id.0, account_name.as_str())
                .with_metadata(serde_json::json!({"action": "set_cert", "fingerprint": &fingerprint}))
        })
        .await
        .ctx(ctx)?;

    state
        .audit_service
        .log(
            AuditEvent::from_ctx(&call_ctx, event_type::ACCOUNT_UPDATE, AuditOutcome::Success)
                .with_resource("account", account.id.0, account_name.as_str())
                .with_metadata(serde_json::json!({"action": "set_cert", "fingerprint": fingerprint})),
        )
        .await;

    let status = ApiStatus::new(ApiCode::AccountUpdated, "Client certificate updated".to_string());
    Ok(Json(ApiResponse::ok(status, SetCertResponse { fingerprint, subject })))
}
