// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::{Actor, CallContext};
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::http_server::auth_user::AuthUser;
use crate::manager::token::TokenPurpose;
use axum::body::Body;
use axum::extract::{MatchedPath, State};
use axum::http::Method;
use axum::{
    http::{Request, header::AUTHORIZATION},
    middleware::Next,
    response::Response,
};
use hierarkey_core::api::status::ApiCode;

fn is_allowed_for_change_pwd(method: &Method, path: &str) -> bool {
    matches!(
        (method.as_str(), path),
        ("POST", "/v1/accounts/{account}/password") | ("GET", "/v1/auth/whoami")
    )
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, HttpError> {
    let header = req.headers().get(AUTHORIZATION).ok_or_else(|| {
        HttpError::unauthorized(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            "Missing Authorization header",
        )
    })?;

    let header_str = header.to_str().map_err(|_| {
        HttpError::unauthorized(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            "Invalid Authorization header",
        )
    })?;

    const PREFIX: &str = "Bearer ";
    let token = header_str.strip_prefix(PREFIX).ok_or_else(|| {
        HttpError::unauthorized(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            "Bearer token required",
        )
    })?;

    let ctx = CallContext::system();
    let (user, pat) = state.auth_service.authenticate(&ctx, token).await.map_err(|e| {
        HttpError::unauthorized(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            e.to_string(),
        )
    })?;

    // Check if the token is allowed for change password operations. Only continue to
    // whitelisted paths if the token scope is ChangePwd.
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str())
        .unwrap_or(req.uri().path());

    // Refresh tokens may only be used at the /auth/refresh endpoint
    if pat.purpose == TokenPurpose::Refresh {
        return Err(HttpError::forbidden(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            "Refresh tokens cannot be used for API access — use /v1/auth/refresh to obtain a new access token",
        ));
    }

    let has_changepwd_token = pat.purpose == TokenPurpose::ChangePwd;
    let change_route = is_allowed_for_change_pwd(&method, route);

    if has_changepwd_token && !change_route {
        return Err(HttpError::forbidden(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            "This token is restricted to password change",
        ));
    }

    let auth_user = AuthUser {
        user: user.clone(),
        pat,
    };
    req.extensions_mut().insert(auth_user);

    if let Some(ctx) = req.extensions_mut().get_mut::<CallContext>() {
        ctx.actor = Actor::Account(user.id);
        ctx.actor_name = Some(user.name.to_string());
    }

    Ok(next.run(req).await)
}
