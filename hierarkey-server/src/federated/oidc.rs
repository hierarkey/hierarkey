// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! OIDC federated auth provider.
//!
//! Validates a JWT (ID token or access token) issued by an OpenID Connect
//! provider. The provider's JWKS is fetched at startup and cached; unknown
//! key IDs trigger a single cache refresh before returning an error.

use crate::http_server::api_error::HttpError;
use crate::http_server::federated_auth_provider::{FederatedAuthProvider, FederatedIdentity};
use axum::http::StatusCode;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Algorithms accepted from OIDC providers. HS* are intentionally excluded
/// (symmetric secret would have to be shared with the provider).
///
/// # Security note — Marvin Attack (RUSTSEC-2023-0071)
///
/// The `rsa` crate (pulled in by `jsonwebtoken`) has a known timing side-channel
/// vulnerability in RSA **private-key** operations (decryption and signing).
/// No upstream fix is available as of the time of writing.
///
/// This code is not affected: the RS*/PS* algorithms here are used exclusively
/// for JWT **verification** (public-key operations). The vulnerable private-key
/// path is never exercised. Removing RS*/PS* would break compatibility with
/// enterprise OIDC providers (Azure AD, Okta, …) that only issue RSA-signed
/// tokens, so they are kept with this explicit acknowledgement.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: String,
    iss: String,
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

pub struct OidcProvider {
    id: String,
    issuer: String,
    audience: String,
    jwks_url: String,
    jwks: Arc<RwLock<JwkSet>>,
    client: reqwest::Client,
    /// Path to a file containing a bearer token for authenticating JWKS requests.
    bearer_token_path: Option<String>,
}

impl OidcProvider {
    /// Build an `OidcProvider` and immediately fetch the initial JWKS.
    pub async fn new(
        id: String,
        issuer: String,
        audience: String,
        jwks_url: Option<String>,
        ca_cert_path: Option<String>,
        bearer_token_path: Option<String>,
    ) -> hierarkey_core::CkResult<Self> {
        let mut builder = reqwest::Client::builder().use_rustls_tls();

        if let Some(path) = ca_cert_path {
            let pem = std::fs::read(&path)
                .map_err(|e| hierarkey_core::CkError::Custom(format!("failed to read CA cert '{path}': {e}")))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| hierarkey_core::CkError::Custom(format!("invalid CA cert '{path}': {e}")))?;
            builder = builder.add_root_certificate(cert);
        }

        let client = builder.build().map_err(|e| {
            hierarkey_core::CkError::Custom(format!("failed to build HTTP client for OIDC provider '{id}': {e}"))
        })?;

        // Resolve JWKS URL: use explicit override, or discover via OIDC metadata.
        let resolved_jwks_url = match jwks_url {
            Some(url) => url,
            None => discover_jwks_url(&client, &issuer, bearer_token_path.as_deref())
                .await
                .map_err(|e| {
                    hierarkey_core::CkError::Custom(format!("OIDC discovery failed for provider '{id}': {e}"))
                })?,
        };

        let initial_jwks = fetch_jwks(&client, &resolved_jwks_url, bearer_token_path.as_deref())
            .await
            .map_err(|e| hierarkey_core::CkError::Custom(format!("failed to fetch JWKS for provider '{id}': {e}")))?;

        Ok(Self {
            id,
            issuer,
            audience,
            jwks_url: resolved_jwks_url,
            jwks: Arc::new(RwLock::new(initial_jwks)),
            client,
            bearer_token_path,
        })
    }

    async fn refresh_jwks(&self) -> Result<(), HttpError> {
        debug!("Refreshing JWKS for OIDC provider '{}'", self.id);
        match fetch_jwks(&self.client, &self.jwks_url, self.bearer_token_path.as_deref()).await {
            Ok(fresh) => {
                *self.jwks.write().await = fresh;
                Ok(())
            }
            Err(e) => {
                warn!("Failed to refresh JWKS for provider '{}': {e}", self.id);
                Err(HttpError {
                    http: StatusCode::SERVICE_UNAVAILABLE,
                    fail_code: ApiCode::AuthTokenFailed,
                    reason: ApiErrorCode::InternalError,
                    message: "federated auth unavailable: could not refresh signing keys".into(),
                    details: None,
                })
            }
        }
    }
}

#[async_trait::async_trait]
impl FederatedAuthProvider for OidcProvider {
    fn provider_id(&self) -> &str {
        &self.id
    }

    fn provider_type(&self) -> &str {
        "oidc"
    }

    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn audience(&self) -> Option<&str> {
        Some(&self.audience)
    }

    fn jwks_url(&self) -> Option<&str> {
        Some(&self.jwks_url)
    }

    async fn exchange(&self, credential: &str) -> Result<FederatedIdentity, HttpError> {
        let ctx = ApiCode::AuthTokenFailed;

        // Decode header without verifying signature to obtain `kid` and `alg`.
        let header = decode_header(credential).map_err(|e| HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx,
            reason: ApiErrorCode::Unauthorized,
            message: format!("invalid JWT header: {e}"),
            details: None,
        })?;

        // Reject disallowed algorithms upfront.
        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(HttpError {
                http: StatusCode::UNAUTHORIZED,
                fail_code: ctx,
                reason: ApiErrorCode::Unauthorized,
                message: format!("JWT algorithm '{:?}' is not accepted", header.alg),
                details: None,
            });
        }

        let kid = header.kid.ok_or_else(|| HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx,
            reason: ApiErrorCode::Unauthorized,
            message: "JWT is missing 'kid' header".into(),
            details: None,
        })?;

        // Try to find the key. If absent, refresh JWKS once and retry.
        let jwk = {
            let keys = self.jwks.read().await;
            keys.find(&kid).cloned()
        };

        let jwk = match jwk {
            Some(k) => k,
            None => {
                self.refresh_jwks().await?;
                let keys = self.jwks.read().await;
                keys.find(&kid).cloned().ok_or_else(|| HttpError {
                    http: StatusCode::UNAUTHORIZED,
                    fail_code: ctx,
                    reason: ApiErrorCode::Unauthorized,
                    message: format!("unknown signing key '{kid}'"),
                    details: None,
                })?
            }
        };

        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ctx,
            reason: ApiErrorCode::InternalError,
            message: format!("could not build decoding key from JWK: {e}"),
            details: None,
        })?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        let token_data = decode::<OidcClaims>(credential, &decoding_key, &validation).map_err(|e| HttpError {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx,
            reason: ApiErrorCode::Unauthorized,
            message: format!("JWT validation failed: {e}"),
            details: None,
        })?;

        Ok(FederatedIdentity {
            external_subject: token_data.claims.sub,
            external_issuer: token_data.claims.iss,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a bearer token from a file path, trimming whitespace.
fn read_bearer_token(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .map_err(|e| format!("failed to read bearer token from '{path}': {e}"))
}

/// Fetch the OIDC discovery document and extract `jwks_uri`.
async fn discover_jwks_url(
    client: &reqwest::Client,
    issuer: &str,
    bearer_token_path: Option<&str>,
) -> Result<String, String> {
    let discovery_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let mut req = client.get(&discovery_url);
    if let Some(path) = bearer_token_path {
        req = req.bearer_auth(read_bearer_token(path)?);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("GET {discovery_url} failed: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("reading discovery response failed: {e}"))?;
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("parsing discovery document (HTTP {status}) failed: {e} — body: {body}"))?;

    parsed["jwks_uri"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("discovery document at {discovery_url} has no 'jwks_uri' field"))
}

// ---------------------------------------------------------------------------
// Test-only helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
impl OidcProvider {
    /// Construct a provider with a pre-loaded JWK set — no network call is made.
    /// Use this in unit tests to avoid needing a live OIDC server.
    pub(crate) fn new_for_test(id: &str, issuer: &str, audience: &str, jwks: JwkSet) -> Self {
        let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
        Self {
            id: id.to_string(),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            jwks_url: "http://127.0.0.1:1/jwks.json".to_string(), // unreachable; refresh fails
            jwks: Arc::new(RwLock::new(jwks)),
            client,
            bearer_token_path: None,
        }
    }
}

/// Fetch and parse a JWK Set from `url`.
async fn fetch_jwks(client: &reqwest::Client, url: &str, bearer_token_path: Option<&str>) -> Result<JwkSet, String> {
    let mut req = client.get(url);
    if let Some(path) = bearer_token_path {
        req = req.bearer_auth(read_bearer_token(path)?);
    }
    let resp = req.send().await.map_err(|e| format!("GET {url} failed: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("reading JWKS response failed: {e}"))?;
    serde_json::from_str::<JwkSet>(&body)
        .map_err(|e| format!("parsing JWKS from {url} (HTTP {status}) failed: {e} — body: {body:.200}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType, Jwk,
        JwkSet,
    };

    const TEST_ISSUER: &str = "https://issuer.example.com";
    const TEST_AUDIENCE: &str = "test-audience";
    const TEST_KID: &str = "test-key-1";

    // ---------------------------------------------------------------------------
    // Test key helpers — generate a fresh EC P-256 key pair via rcgen
    // ---------------------------------------------------------------------------

    struct TestKey {
        encoding_key: jsonwebtoken::EncodingKey,
        jwk: Jwk,
    }

    fn make_test_ec_key() -> TestKey {
        // Generate an EC P-256 key pair.
        let key_pair = rcgen::KeyPair::generate().unwrap();

        // Export the private key as PKCS#8 PEM for jsonwebtoken.
        let private_pem = key_pair.serialize_pem();
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(private_pem.as_bytes())
            .expect("rcgen private key must be valid EC PEM");

        // Export the public key as DER (SPKI format).
        // For P-256 SPKI the last 65 bytes are: 0x04 | x (32 bytes) | y (32 bytes).
        let pub_der = key_pair.public_key_der();
        let point_start = pub_der.len() - 65;
        assert_eq!(pub_der[point_start], 0x04, "EC point must start with 0x04 (uncompressed)");
        let x = URL_SAFE_NO_PAD.encode(&pub_der[point_start + 1..point_start + 33]);
        let y = URL_SAFE_NO_PAD.encode(&pub_der[point_start + 33..point_start + 65]);

        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: None,
                key_operations: None,
                key_algorithm: None,
                key_id: Some(TEST_KID.to_string()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x,
                y,
            }),
        };

        TestKey { encoding_key, jwk }
    }

    fn make_provider_with_key(key: &TestKey) -> OidcProvider {
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        OidcProvider::new_for_test("test-oidc", TEST_ISSUER, TEST_AUDIENCE, jwks)
    }

    fn sign_claims(key: &TestKey, claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(&header, claims, &key.encoding_key).expect("JWT signing must succeed")
    }

    /// Build a fake JWT (invalid signature) with the given JSON header.
    /// Useful for testing header-parsing and early-rejection logic without real keys.
    fn fake_jwt(header_json: &str) -> String {
        let h = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let c = URL_SAFE_NO_PAD
            .encode(br#"{"sub":"x","iss":"https://issuer.example.com","aud":"test-audience","exp":9999999999}"#);
        format!("{h}.{c}.fakesig")
    }

    // ---------------------------------------------------------------------------
    // Error-path tests — no real crypto needed
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn exchange_completely_malformed_jwt_returns_error() {
        let provider = OidcProvider::new_for_test("p", TEST_ISSUER, TEST_AUDIENCE, JwkSet { keys: vec![] });
        let err = provider.exchange("not.a.jwt").await.unwrap_err();
        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exchange_hs256_algorithm_rejected() {
        let provider = OidcProvider::new_for_test("p", TEST_ISSUER, TEST_AUDIENCE, JwkSet { keys: vec![] });
        let token = fake_jwt(r#"{"alg":"HS256","typ":"JWT"}"#);
        let err = provider.exchange(&token).await.unwrap_err();
        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.message.contains("HS256") || err.message.contains("not accepted"),
            "got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn exchange_hs512_algorithm_rejected() {
        let provider = OidcProvider::new_for_test("p", TEST_ISSUER, TEST_AUDIENCE, JwkSet { keys: vec![] });
        let token = fake_jwt(r#"{"alg":"HS512","typ":"JWT"}"#);
        let err = provider.exchange(&token).await.unwrap_err();
        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exchange_rs256_missing_kid_returns_error() {
        let provider = OidcProvider::new_for_test("p", TEST_ISSUER, TEST_AUDIENCE, JwkSet { keys: vec![] });
        // RS256 is allowed but kid is absent.
        let token = fake_jwt(r#"{"alg":"RS256","typ":"JWT"}"#);
        let err = provider.exchange(&token).await.unwrap_err();
        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
        assert!(err.message.contains("kid"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn exchange_unknown_kid_returns_error() {
        // The JWK set is empty, so any kid will be unknown; the refresh will fail
        // (unreachable URL in new_for_test) and the provider returns an error.
        let provider = OidcProvider::new_for_test("p", TEST_ISSUER, TEST_AUDIENCE, JwkSet { keys: vec![] });
        let token = fake_jwt(r#"{"alg":"ES256","kid":"unknown-key","typ":"JWT"}"#);
        let err = provider.exchange(&token).await.unwrap_err();
        // Either SERVICE_UNAVAILABLE (refresh network error) or UNAUTHORIZED (key not found)
        assert!(
            err.http == axum::http::StatusCode::SERVICE_UNAVAILABLE || err.http == axum::http::StatusCode::UNAUTHORIZED,
            "unexpected status: {}",
            err.http
        );
    }

    // ---------------------------------------------------------------------------
    // Happy-path tests — real EC key + real JWT
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn exchange_valid_token_returns_correct_identity() {
        let key = make_test_ec_key();
        let provider = make_provider_with_key(&key);

        let claims = serde_json::json!({
            "sub": "user-subject-123",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": chrono::Utc::now().timestamp() + 3600,
            "iat": chrono::Utc::now().timestamp(),
        });
        let token = sign_claims(&key, &claims);

        let identity = provider.exchange(&token).await.unwrap();
        assert_eq!(identity.external_subject, "user-subject-123");
        assert_eq!(identity.external_issuer, TEST_ISSUER);
    }

    #[tokio::test]
    async fn exchange_expired_token_returns_error() {
        let key = make_test_ec_key();
        let provider = make_provider_with_key(&key);

        let claims = serde_json::json!({
            "sub": "user-subject-123",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": chrono::Utc::now().timestamp() - 3600, // expired 1 hour ago
            "iat": chrono::Utc::now().timestamp() - 7200,
        });
        let token = sign_claims(&key, &claims);

        let err = provider.exchange(&token).await.unwrap_err();
        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            err.message.contains("expired") || err.message.contains("JWT validation failed"),
            "got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn exchange_wrong_issuer_returns_error() {
        let key = make_test_ec_key();
        let provider = make_provider_with_key(&key);

        let claims = serde_json::json!({
            "sub": "user-subject-123",
            "iss": "https://wrong-issuer.example.com",
            "aud": TEST_AUDIENCE,
            "exp": chrono::Utc::now().timestamp() + 3600,
            "iat": chrono::Utc::now().timestamp(),
        });
        let token = sign_claims(&key, &claims);

        let err = provider.exchange(&token).await.unwrap_err();
        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exchange_wrong_audience_returns_error() {
        let key = make_test_ec_key();
        let provider = make_provider_with_key(&key);

        let claims = serde_json::json!({
            "sub": "user-subject-123",
            "iss": TEST_ISSUER,
            "aud": "wrong-audience",
            "exp": chrono::Utc::now().timestamp() + 3600,
            "iat": chrono::Utc::now().timestamp(),
        });
        let token = sign_claims(&key, &claims);

        let err = provider.exchange(&token).await.unwrap_err();
        assert_eq!(err.http, axum::http::StatusCode::UNAUTHORIZED);
    }

    // ---------------------------------------------------------------------------
    // JWKS refresh — serve a live mockito JWKS endpoint
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn exchange_unknown_kid_triggers_refresh_and_succeeds() {
        let key = make_test_ec_key();

        // Start with an empty JWKS — the provider won't know the key yet.
        let mut server = mockito::Server::new_async().await;
        let jwks_body = serde_json::to_string(&JwkSet {
            keys: vec![key.jwk.clone()],
        })
        .unwrap();
        let _m = server
            .mock("GET", "/jwks.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_body)
            .create_async()
            .await;

        // Provider starts with empty JWKS (kid unknown → triggers refresh to mockito).
        let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
        let provider = OidcProvider {
            id: "test-oidc".to_string(),
            issuer: TEST_ISSUER.to_string(),
            audience: TEST_AUDIENCE.to_string(),
            jwks_url: format!("{}/jwks.json", server.url()),
            jwks: Arc::new(RwLock::new(JwkSet { keys: vec![] })),
            client,
            bearer_token_path: None,
        };

        let claims = serde_json::json!({
            "sub": "refresh-user",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": chrono::Utc::now().timestamp() + 3600,
            "iat": chrono::Utc::now().timestamp(),
        });
        let token = sign_claims(&key, &claims);

        let identity = provider.exchange(&token).await.unwrap();
        assert_eq!(identity.external_subject, "refresh-user");
    }
}
