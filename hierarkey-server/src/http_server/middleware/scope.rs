// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::http_server::auth_user::AuthUser;
use crate::manager::token::TokenPurpose;
use axum::{body::Body, http::Request, middleware::Next, response::Response};
use hierarkey_core::api::status::ApiCode;

pub async fn require_auth_purpose(req: Request<Body>, next: Next) -> Result<Response, HttpError> {
    require_scope_inner(req, next, &[TokenPurpose::Auth]).await
}

pub async fn require_change_password_purpose(req: Request<Body>, next: Next) -> Result<Response, HttpError> {
    require_scope_inner(req, next, &[TokenPurpose::ChangePwd, TokenPurpose::Auth]).await
}

async fn require_scope_inner(req: Request<Body>, next: Next, required: &[TokenPurpose]) -> Result<Response, HttpError> {
    let auth = req.extensions().get::<AuthUser>().ok_or_else(|| {
        HttpError::unauthorized(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            "Missing auth context",
        )
    })?;

    let pat_scope = auth.pat.purpose;
    let allowed = pat_scope == TokenPurpose::Auth || required.contains(&pat_scope);

    if !allowed {
        return Err(HttpError::forbidden(
            ApiErrorCtx {
                fail_code: ApiCode::Forbidden,
            },
            "Insufficient token scope",
        ));
    }

    Ok(next.run(req).await)
}
