// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! Kubernetes TokenReview federated auth provider.
//!
//! Validates a Kubernetes service account token by calling the
//! `authentication.k8s.io/v1/tokenreviews` API. The caller presents their
//! SA token; the server performs a `TokenReview` request (optionally using
//! a reviewer bearer token) and maps the authenticated user to a linked
//! service account in Hierarkey.

use crate::http_server::api_error::HttpError;
use crate::http_server::federated_auth_provider::{FederatedAuthProvider, FederatedIdentity};
use axum::http::StatusCode;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode};
use serde::{Deserialize, Serialize};
use tracing::debug;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Kubernetes API types (minimal subset needed for TokenReview)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct TokenReviewRequest {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    spec: TokenReviewSpec,
}

#[derive(Debug, Serialize)]
struct TokenReviewSpec {
    token: String,
}

#[derive(Debug, Deserialize)]
struct TokenReviewResponse {
    status: Option<TokenReviewStatus>,
}

#[derive(Debug, Deserialize)]
struct TokenReviewStatus {
    #[serde(default)]
    authenticated: bool,
    user: Option<TokenReviewUser>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenReviewUser {
    #[serde(default)]
    uid: String,
    #[serde(default)]
    username: String,
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct K8sTokenReviewProvider {
    id: String,
    /// Kubernetes API server URL — also used as `external_issuer`.
    api_server: String,
    /// Pre-built reqwest client configured with the cluster CA.
    client: reqwest::Client,
    /// Optional reviewer token path; read fresh on every request so projected
    /// tokens that rotate automatically are always current.
    reviewer_token_path: Option<String>,
    /// Full TokenReview endpoint URL.
    endpoint: String,
}

impl K8sTokenReviewProvider {
    pub fn new(
        id: String,
        api_server: String,
        ca_cert_path: Option<String>,
        reviewer_token_path: Option<String>,
    ) -> hierarkey_core::CkResult<Self> {
        let mut builder = reqwest::Client::builder().use_rustls_tls();

        if let Some(ref ca_path) = ca_cert_path {
            let ca_pem = std::fs::read(ca_path).map_err(|e| {
                hierarkey_core::CkError::Custom(format!(
                    "k8s-tokenreview provider '{id}': failed to read CA cert '{ca_path}': {e}"
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&ca_pem).map_err(|e| {
                hierarkey_core::CkError::Custom(format!(
                    "k8s-tokenreview provider '{id}': invalid CA cert '{ca_path}': {e}"
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        let client = builder.build().map_err(|e| {
            hierarkey_core::CkError::Custom(format!(
                "k8s-tokenreview provider '{id}': failed to build HTTP client: {e}"
            ))
        })?;

        let endpoint = format!(
            "{}/apis/authentication.k8s.io/v1/tokenreviews",
            api_server.trim_end_matches('/')
        );

        Ok(Self {
            id,
            api_server,
            client,
            reviewer_token_path,
            endpoint,
        })
    }

    /// Read the reviewer token from disk if a path is configured.
    /// Returns `None` if no reviewer token is needed (e.g. anonymous review is permitted).
    fn reviewer_token(&self) -> hierarkey_core::CkResult<Option<Zeroizing<String>>> {
        let Some(ref path) = self.reviewer_token_path else {
            return Ok(None);
        };
        let token = std::fs::read_to_string(path).map_err(|e| {
            hierarkey_core::CkError::Custom(format!(
                "k8s-tokenreview provider '{}': failed to read reviewer token from '{path}': {e}",
                self.id
            ))
        })?;
        Ok(Some(Zeroizing::new(token.trim().to_owned())))
    }
}

#[async_trait::async_trait]
impl FederatedAuthProvider for K8sTokenReviewProvider {
    fn provider_id(&self) -> &str {
        &self.id
    }

    fn provider_type(&self) -> &str {
        "k8s-tokenreview"
    }

    fn issuer(&self) -> &str {
        &self.api_server
    }

    fn audience(&self) -> Option<&str> {
        None
    }

    fn jwks_url(&self) -> Option<&str> {
        None
    }

    async fn exchange(&self, credential: &str) -> Result<FederatedIdentity, HttpError> {
        let ctx = ApiCode::AuthTokenFailed;

        // Read reviewer token fresh from disk so rotated projected tokens work.
        let reviewer_token = self.reviewer_token().map_err(|e| HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ctx,
            reason: ApiErrorCode::InternalError,
            message: format!("could not load reviewer token: {e}"),
            details: None,
        })?;

        let body = TokenReviewRequest {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: TokenReviewSpec {
                token: credential.to_owned(),
            },
        };

        let mut req = self.client.post(&self.endpoint).json(&body);
        if let Some(ref token) = reviewer_token {
            req = req.bearer_auth(token.as_str());
        }

        debug!(
            provider_id = %self.id,
            endpoint = %self.endpoint,
            "Sending TokenReview request to Kubernetes API",
        );

        let response = req.send().await.map_err(|e| HttpError {
            http: StatusCode::SERVICE_UNAVAILABLE,
            fail_code: ctx,
            reason: ApiErrorCode::InternalError,
            message: format!("TokenReview request to Kubernetes API failed: {e}"),
            details: None,
        })?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(HttpError {
                http: StatusCode::SERVICE_UNAVAILABLE,
                fail_code: ctx,
                reason: ApiErrorCode::InternalError,
                message: format!("Kubernetes API returned HTTP {status} for TokenReview"),
                details: None,
            });
        }

        let review: TokenReviewResponse = response.json().await.map_err(|e| HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ctx,
            reason: ApiErrorCode::InternalError,
            message: format!("failed to parse TokenReview response: {e}"),
            details: None,
        })?;

        let status = review.status.ok_or_else(|| HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ctx,
            reason: ApiErrorCode::InternalError,
            message: "TokenReview response missing 'status' field".into(),
            details: None,
        })?;

        if !status.authenticated {
            let reason = status
                .error
                .unwrap_or_else(|| "Kubernetes did not authenticate the token".into());
            return Err(HttpError {
                http: StatusCode::UNAUTHORIZED,
                fail_code: ctx,
                reason: ApiErrorCode::Unauthorized,
                message: reason,
                details: None,
            });
        }

        let user = status.user.ok_or_else(|| HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ctx,
            reason: ApiErrorCode::InternalError,
            message: "TokenReview authenticated but 'user' field is absent".into(),
            details: None,
        })?;

        // Prefer UID (stable across renames) but fall back to username.
        let subject = if !user.uid.is_empty() {
            user.uid
        } else if !user.username.is_empty() {
            user.username
        } else {
            return Err(HttpError {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx,
                reason: ApiErrorCode::InternalError,
                message: "TokenReview user has neither uid nor username".into(),
                details: None,
            });
        };

        Ok(FederatedIdentity {
            external_subject: subject,
            external_issuer: self.api_server.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    fn make_provider(api_server: &str) -> K8sTokenReviewProvider {
        K8sTokenReviewProvider::new(api_server.to_string(), api_server.to_string(), None, None).unwrap()
    }

    fn authenticated_response(uid: &str, username: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "status": {
                "authenticated": true,
                "user": {
                    "uid": uid,
                    "username": username
                }
            }
        })
    }

    fn unauthenticated_response(error: Option<&str>) -> serde_json::Value {
        let mut status = serde_json::json!({ "authenticated": false });
        if let Some(msg) = error {
            status["error"] = serde_json::json!(msg);
        }
        serde_json::json!({ "status": status })
    }

    // ---------------------------------------------------------------------------
    // Constructor tests
    // ---------------------------------------------------------------------------

    #[test]
    fn new_without_ca_cert_succeeds() {
        let result =
            K8sTokenReviewProvider::new("test-k8s".to_string(), "https://k8s.example.com".to_string(), None, None);
        assert!(result.is_ok());
        let provider = result.unwrap();
        assert_eq!(provider.provider_id(), "test-k8s");
        assert_eq!(
            provider.endpoint,
            "https://k8s.example.com/apis/authentication.k8s.io/v1/tokenreviews"
        );
    }

    #[test]
    fn new_with_nonexistent_ca_cert_returns_error() {
        let result = K8sTokenReviewProvider::new(
            "test-k8s".to_string(),
            "https://k8s.example.com".to_string(),
            Some("/nonexistent/ca.pem".to_string()),
            None,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("ca.pem"), "expected path in error, got: {msg}");
    }

    #[test]
    fn endpoint_strips_trailing_slash_from_api_server() {
        let provider =
            K8sTokenReviewProvider::new("p".to_string(), "https://k8s.example.com/".to_string(), None, None).unwrap();
        // The trailing slash on the api_server should be stripped so the path separator
        // between host and path is exactly one `/`.
        assert_eq!(
            provider.endpoint,
            "https://k8s.example.com/apis/authentication.k8s.io/v1/tokenreviews"
        );
    }

    // ---------------------------------------------------------------------------
    // reviewer_token tests
    // ---------------------------------------------------------------------------

    #[test]
    fn reviewer_token_returns_none_when_no_path() {
        let provider = make_provider("https://k8s.example.com");
        assert!(provider.reviewer_token().unwrap().is_none());
    }

    #[test]
    fn reviewer_token_reads_from_file_and_trims_whitespace() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"my-reviewer-token\n").unwrap();

        let provider = K8sTokenReviewProvider::new(
            "test".to_string(),
            "https://k8s.example.com".to_string(),
            None,
            Some(tmp.path().to_string_lossy().into_owned()),
        )
        .unwrap();

        let token = provider.reviewer_token().unwrap();
        assert_eq!(token.as_deref().map(|s| s.as_str()), Some("my-reviewer-token"));
    }

    #[test]
    fn reviewer_token_returns_error_for_missing_file() {
        let provider = K8sTokenReviewProvider::new(
            "test".to_string(),
            "https://k8s.example.com".to_string(),
            None,
            Some("/nonexistent/reviewer-token.txt".to_string()),
        )
        .unwrap();
        assert!(provider.reviewer_token().is_err());
    }

    // ---------------------------------------------------------------------------
    // Serialisation test
    // ---------------------------------------------------------------------------

    #[test]
    fn token_review_request_serialises_correctly() {
        let req = TokenReviewRequest {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: TokenReviewSpec {
                token: "my-sa-token".to_string(),
            },
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["apiVersion"], "authentication.k8s.io/v1");
        assert_eq!(json["kind"], "TokenReview");
        assert_eq!(json["spec"]["token"], "my-sa-token");
    }

    // ---------------------------------------------------------------------------
    // exchange() — HTTP-mocked tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn exchange_authenticated_with_uid_prefers_uid() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/apis/authentication.k8s.io/v1/tokenreviews")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(authenticated_response("uid-abc", "svc:default:my-sa").to_string())
            .create_async()
            .await;

        let provider = make_provider(&server.url());
        let identity = provider.exchange("fake-token").await.unwrap();

        assert_eq!(identity.external_subject, "uid-abc");
        assert_eq!(identity.external_issuer, server.url());
    }

    #[tokio::test]
    async fn exchange_authenticated_falls_back_to_username_when_uid_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/apis/authentication.k8s.io/v1/tokenreviews")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(authenticated_response("", "svc:default:my-sa").to_string())
            .create_async()
            .await;

        let provider = make_provider(&server.url());
        let identity = provider.exchange("fake-token").await.unwrap();

        assert_eq!(identity.external_subject, "svc:default:my-sa");
    }

    #[tokio::test]
    async fn exchange_unauthenticated_returns_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/apis/authentication.k8s.io/v1/tokenreviews")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(unauthenticated_response(None).to_string())
            .create_async()
            .await;

        let provider = make_provider(&server.url());
        let err = provider.exchange("bad-token").await.unwrap_err();

        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exchange_unauthenticated_with_error_field_uses_it_as_message() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/apis/authentication.k8s.io/v1/tokenreviews")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(unauthenticated_response(Some("token has expired")).to_string())
            .create_async()
            .await;

        let provider = make_provider(&server.url());
        let err = provider.exchange("bad-token").await.unwrap_err();

        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
        assert!(err.message.contains("token has expired"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn exchange_k8s_api_non_200_returns_service_unavailable() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/apis/authentication.k8s.io/v1/tokenreviews")
            .with_status(403)
            .with_body("Forbidden")
            .create_async()
            .await;

        let provider = make_provider(&server.url());
        let err = provider.exchange("any-token").await.unwrap_err();

        assert_eq!(err.http, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn exchange_missing_status_field_returns_internal_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/apis/authentication.k8s.io/v1/tokenreviews")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview"}"#)
            .create_async()
            .await;

        let provider = make_provider(&server.url());
        let err = provider.exchange("any-token").await.unwrap_err();

        assert_eq!(err.http, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.message.contains("status"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn exchange_user_with_no_uid_or_username_returns_internal_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/apis/authentication.k8s.io/v1/tokenreviews")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(authenticated_response("", "").to_string())
            .create_async()
            .await;

        let provider = make_provider(&server.url());
        let err = provider.exchange("token").await.unwrap_err();

        assert_eq!(err.http, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn exchange_network_failure_returns_service_unavailable() {
        // Port 1 is reserved and will always refuse connections.
        let provider =
            K8sTokenReviewProvider::new("test".to_string(), "http://127.0.0.1:1".to_string(), None, None).unwrap();

        let err = provider.exchange("any-token").await.unwrap_err();
        assert_eq!(err.http, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
}
