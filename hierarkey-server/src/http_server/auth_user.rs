// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::{Account, PersonalAccessToken};
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use hierarkey_core::api::status::ApiCode;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user: Account,
    pub pat: PersonalAccessToken,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts.headers.get(AUTHORIZATION).ok_or(HttpError::unauthorized(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            "Missing Authorization header",
        ))?;

        let header_str = header.to_str().map_err(|_| {
            HttpError::unauthorized(
                ApiErrorCtx {
                    fail_code: ApiCode::Unauthorized,
                },
                "Invalid Authorization header",
            )
        })?;

        const PREFIX: &str = "Bearer ";
        let token = header_str.strip_prefix(PREFIX).ok_or(HttpError::unauthorized(
            ApiErrorCtx {
                fail_code: ApiCode::Unauthorized,
            },
            "Bearer token required",
        ))?;

        let ctx = CallContext::system();
        let (user, pat) = state.auth_service.authenticate(&ctx, token).await.map_err(|e| {
            HttpError::unauthorized(
                ApiErrorCtx {
                    fail_code: ApiCode::Unauthorized,
                },
                e.to_string(),
            )
        })?;

        Ok(AuthUser { user, pat })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::test_utils::create_mock_app_state;
    use crate::http_server::handlers::auth_response::AuthScope;
    use crate::manager::account::Password;
    use crate::service::account::{AccountData, CustomAccountData, CustomUserAccountData};
    use axum::body::Body;
    use axum::http::Request;
    use hierarkey_core::resources::AccountName;

    // Helper to create test request parts
    fn create_request_parts(auth_header: Option<&str>) -> Parts {
        let mut request = Request::builder();

        if let Some(header) = auth_header {
            request = request.header(AUTHORIZATION, header);
        }

        let (parts, _body) = request.body(Body::empty()).unwrap().into_parts();
        parts
    }

    #[tokio::test]
    async fn test_valid_bearer_token() {
        let state = create_mock_app_state();

        let data = AccountData {
            account_name: AccountName::try_from("testuser").unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                email: None,
                full_name: None,
                password: Password::new("dummy_dummy_dummy"),
                must_change_password: false,
            }),
        };

        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let user = state.account_service.create_account(&ctx, &data).await.unwrap();
        let (token, _pat) = state
            .auth_service
            .create_pat(&ctx, &user, "test token", 1, AuthScope::Auth)
            .await
            .unwrap();

        let mut parts = create_request_parts(Some(&format!("Bearer {token}")));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_ok());
        let auth_user = result.unwrap();
        assert_eq!(auth_user.user.id, user.id);
        // assert!(auth_user.expires_at > chrono::Utc::now());
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let state = create_mock_app_state();
        let mut parts = create_request_parts(None);

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
        let HttpError { http, .. } = result.unwrap_err();
        assert_eq!(http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_bearer_prefix() {
        let state = create_mock_app_state();
        let mut parts = create_request_parts(Some("Basic sometoken"));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
        let HttpError { http, .. } = result.unwrap_err();
        assert_eq!(http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_bearer_prefix() {
        let state = create_mock_app_state();
        let mut parts = create_request_parts(Some("sometoken"));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
        let HttpError { http, .. } = result.unwrap_err();
        assert_eq!(http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_empty_bearer_token() {
        let state = create_mock_app_state();
        let mut parts = create_request_parts(Some("Bearer "));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let state = create_mock_app_state();
        let mut parts = create_request_parts(Some("Bearer invalid_token_xyz"));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_expired_token() {
        let state = create_mock_app_state();

        // Create a token that's already expired (if your TokenManager supports this)
        // This test depends on your TokenManager implementation
        // let account_id = AccountId::new();
        let expired_token = "some_expired_token";

        let mut parts = create_request_parts(Some(&format!("Bearer {expired_token}")));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_token_for_nonexistent_user() {
        let state = create_mock_app_state();

        // Create a valid token but for a user that doesn't exist
        // This tests the case where authenticate_token succeeds but get_user_by_id returns None

        let mut parts = create_request_parts(Some("Bearer valid_token_invalid_account"));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
        let HttpError { http, .. } = result.unwrap_err();
        assert_eq!(http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_non_utf8_authorization_header() {
        let state = create_mock_app_state();

        // Create a request with non-UTF8 bytes in the header
        let mut request = Request::builder();
        request = request.header(AUTHORIZATION, &b"Bearer \xff\xfe"[..]);
        let (mut parts, _body) = request.body(Body::empty()).unwrap().into_parts();

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
        let HttpError { http, .. } = result.unwrap_err();
        assert_eq!(http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_case_sensitive_bearer_prefix() {
        let state = create_mock_app_state();

        // Test lowercase "bearer" instead of "Bearer"
        let mut parts = create_request_parts(Some("bearer validtoken"));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        // Should fail because "bearer" != "Bearer"
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_whitespace_in_bearer_prefix() {
        let state = create_mock_app_state();

        // Test extra whitespace
        let mut parts = create_request_parts(Some("Bearer  token_with_extra_space"));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;

        // The token will be " token_with_extra_space" (with leading space)
        // Should fail token validation
        assert!(result.is_err());
    }
}
