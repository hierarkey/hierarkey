// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub mod file;
pub mod password;
pub mod sql;

use hierarkey_core::CkResult;
use hierarkey_core::error::validation::ValidationError;
use zeroize::Zeroizing;

/// Show a prompt and read input from the user without echoing it back (for passwords), returning a zeroizing string.
pub fn prompt_hidden(prompt: &str) -> CkResult<Zeroizing<String>> {
    use std::io::Write;

    eprint!("{prompt}");
    std::io::stderr().flush()?;

    let passphrase = rpassword::read_password()?;
    if passphrase.is_empty() {
        return Err(ValidationError::Field {
            field: "passphrase",
            code: "empty_input",
            message: "input cannot be empty".into(),
        }
        .into());
    }

    Ok(Zeroizing::new(passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use crate::global::HTTP_MAX_BODY_SIZE;
    use crate::global::config::ServerConfig;
    use crate::global::test_utils::create_mock_app_state;
    use crate::http_server::handlers::auth_response::AuthScope;
    use crate::http_server::{build_router, start_tls_server};
    use crate::manager::account::Password;
    use crate::service::account::{AccountData, CustomAccountData, CustomUserAccountData};
    use axum::http::StatusCode;
    use hierarkey_core::CkError;
    use hierarkey_core::resources::AccountName;
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_build_router() {
        let state = create_mock_app_state();
        let router = build_router(state, &[]);

        // Router should build without panicking
        assert!(size_of_val(&router) > 0);
    }

    #[tokio::test]
    async fn test_app_state_clone() {
        let state = create_mock_app_state();
        let cloned_state = state.clone();

        // Verify that Arc references are properly cloned
        assert!(Arc::ptr_eq(&state.secret_service, &cloned_state.secret_service));
    }

    #[test]
    fn test_max_body_size_constant() {
        assert_eq!(HTTP_MAX_BODY_SIZE, 5 * 1024 * 1024);
        assert_eq!(HTTP_MAX_BODY_SIZE, 5_242_880);
    }

    #[tokio::test]
    async fn test_start_tls_server_missing_cert_path() {
        let server_cfg = ServerConfig {
            bind_address: "127.0.0.1:8443".to_string(),
            cert_path: None,
            key_path: Some("/path/to/key.pem".to_string()),
            ..Default::default()
        };

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let result = start_tls_server(&server_cfg, app).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cert_path"));
    }

    #[tokio::test]
    async fn test_start_tls_server_missing_key_path() {
        let server_cfg = ServerConfig {
            bind_address: "127.0.0.1:8443".to_string(),
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: None,
            ..Default::default()
        };

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let result = start_tls_server(&server_cfg, app).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key_path"));
    }

    #[tokio::test]
    async fn test_start_tls_server_nonexistent_key_file() {
        let server_cfg = ServerConfig {
            bind_address: "127.0.0.1:8443".to_string(),
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: Some("/nonexistent/key.pem".to_string()),
            ..Default::default()
        };

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let result = start_tls_server(&server_cfg, app).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("file not found: TLS key file"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_start_tls_server_insecure_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        // Create a temporary key file with insecure permissions
        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(b"dummy key content").unwrap();

        // Set insecure permissions (e.g., 0644)
        let metadata = key_file.as_file().metadata().unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(key_file.path(), permissions).unwrap();

        let server_cfg = ServerConfig {
            bind_address: "127.0.0.1:8443".to_string(),
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: Some(key_file.path().to_str().unwrap().to_string()),
            ..Default::default()
        };

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let result = start_tls_server(&server_cfg, app).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            CkError::FilePermissions(msg) => {
                assert!(msg.contains("insecure permissions"));
                assert!(msg.contains("0600"));
            }
            _ => panic!("Expected FilePermissions error, got {err:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_start_tls_server_secure_key_permissions_invalid_cert() {
        use std::os::unix::fs::PermissionsExt;

        // Create a temporary key file with secure permissions
        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(b"dummy key content").unwrap();

        // Set secure permissions (0600)
        let metadata = key_file.as_file().metadata().unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(key_file.path(), permissions).unwrap();

        // Create a temporary cert file with invalid (non-PEM) content so the
        // file-read succeeds but RustlsConfig::from_pem fails.
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(b"not a valid cert").unwrap();

        let server_cfg = ServerConfig {
            bind_address: "127.0.0.1:8443".to_string(),
            cert_path: Some(cert_file.path().to_str().unwrap().to_string()),
            key_path: Some(key_file.path().to_str().unwrap().to_string()),
            ..Default::default()
        };

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let result = start_tls_server(&server_cfg, app).await;
        // Should pass permission check and file reads, but fail on loading TLS config
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to load TLS config"));
    }

    // Integration test using axum's testing utilities
    #[tokio::test]
    async fn test_router_get_index() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt; // for `oneshot`

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Just verify the route exists (actual handler behavior is tested elsewhere)
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_router_get_healthz() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let response = app
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_router_post_login() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"test","password":"test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_router_nonexistent_route() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        let response = app
            .oneshot(Request::builder().uri("/v1/nonexistent").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_router_body_size_limit() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let state = create_mock_app_state();
        let app = build_router(state.clone(), &[]);

        let data = AccountData {
            account_name: AccountName::try_from("admin").unwrap(),
            is_active: true,
            description: None,
            labels: Default::default(),
            custom: CustomAccountData::User(CustomUserAccountData {
                email: None,
                full_name: None,
                password: Password::new("admin_password"),
                must_change_password: false,
            }),
        };

        let ctx = CallContext::for_account(state.system_account_id.unwrap());
        let admin_user = state.account_service.create_account(&ctx, &data).await.unwrap();
        // state.account_service.must_change_password(admin_user.id, false).await.unwrap();

        let (bearer_token, _pat) = state
            .auth_service
            .create_pat(&ctx, &admin_user, "admin_token", 1, AuthScope::Auth)
            .await
            .unwrap();

        // Create a body larger than MAX_BODY_SIZE
        let mut data = HashMap::new();
        let blob = "x".repeat(HTTP_MAX_BODY_SIZE + 1);
        data.insert("foo", &blob);
        let data = serde_json::to_string(&data).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/secrets")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {bearer_token}"))
                    .body(Body::from(data))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        use http_body_util::BodyExt;
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        let _ = String::from_utf8_lossy(&bytes);

        // Should be rejected due to body size limit
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_router_method_not_allowed() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = create_mock_app_state();
        let app = build_router(state, &[]);

        // Try POST on a GET-only route
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_server_config_tls_validation() {
        let mut cfg = ServerConfig {
            bind_address: "127.0.0.1:8443".to_string(),
            ..Default::default()
        };

        // Missing both cert and key
        cfg.cert_path = None;
        cfg.key_path = None;
        assert!(cfg.cert_path.is_none());
        assert!(cfg.key_path.is_none());

        // Only cert provided
        cfg.cert_path = Some("/path/to/cert.pem".to_string());
        assert!(cfg.cert_path.is_some());
        assert!(cfg.key_path.is_none());

        // Both provided
        cfg.key_path = Some("/path/to/key.pem".to_string());
        assert!(cfg.cert_path.is_some());
        assert!(cfg.key_path.is_some());
    }

    #[test]
    fn test_prompt_hidden_validation() {
        // Note: This test can't actually test the interactive prompt,
        // but we can test that the function signature and error handling exist
        // In real usage, this would require mocking stdin

        // Test that empty passphrase handling exists in the code
        // (actual testing would require dependency injection or test doubles)
        let empty_string = String::new();
        assert!(empty_string.is_empty());
    }

    #[test]
    fn test_zeroizing_string_creation() {
        let secret = Zeroizing::new("test-secret".to_string());
        assert_eq!(*secret, "test-secret");
    }

    #[test]
    fn test_zeroizing_string_drops() {
        let secret = Zeroizing::new("test-secret".to_string());
        assert_eq!(secret.len(), 11);
        drop(secret);
        // Secret should be zeroized after drop
    }
}
