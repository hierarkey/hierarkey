// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! Federated authentication providers.
//!
//! Each `[[auth.federated]]` config entry is turned into a boxed
//! `FederatedAuthProvider` by `build_providers()` and stored in
//! `AppState::federated_providers`.

pub mod k8s_tokenreview;
pub mod oidc;

use crate::global::config::FederatedProviderConfig;
use crate::http_server::federated_auth_provider::FederatedAuthProvider;
use hierarkey_core::CkResult;
use std::sync::Arc;

/// Instantiate all federated providers declared in the configuration.
///
/// Providers are built concurrently but the returned `Vec` preserves the
/// order of the config entries.  Any failure (bad config, unreachable
/// OIDC discovery endpoint, missing CA cert) is returned immediately.
pub async fn build_providers(configs: &[FederatedProviderConfig]) -> CkResult<Vec<Arc<dyn FederatedAuthProvider>>> {
    let mut providers: Vec<Arc<dyn FederatedAuthProvider>> = Vec::new();

    for cfg in configs {
        let provider: Arc<dyn FederatedAuthProvider> = match cfg.provider.as_str() {
            "oidc" => {
                let issuer = cfg.issuer.clone().ok_or_else(|| {
                    hierarkey_core::CkError::Custom(format!(
                        "federated provider '{}': 'issuer' is required for provider type 'oidc'",
                        cfg.id
                    ))
                })?;
                let audience = cfg.audience.clone().ok_or_else(|| {
                    hierarkey_core::CkError::Custom(format!(
                        "federated provider '{}': 'audience' is required for provider type 'oidc'",
                        cfg.id
                    ))
                })?;
                Arc::new(
                    oidc::OidcProvider::new(
                        cfg.id.clone(),
                        issuer,
                        audience,
                        cfg.jwks_url.clone(),
                        cfg.ca_cert_path.clone(),
                        cfg.bearer_token_path.clone(),
                    )
                    .await?,
                )
            }
            "k8s-tokenreview" => {
                let api_server = cfg.api_server.clone().ok_or_else(|| {
                    hierarkey_core::CkError::Custom(format!(
                        "federated provider '{}': 'api_server' is required for provider type 'k8s-tokenreview'",
                        cfg.id
                    ))
                })?;
                Arc::new(k8s_tokenreview::K8sTokenReviewProvider::new(
                    cfg.id.clone(),
                    api_server,
                    cfg.ca_cert_path.clone(),
                    cfg.reviewer_token_path.clone(),
                )?)
            }
            other => {
                return Err(hierarkey_core::CkError::Custom(format!(
                    "federated provider '{}': unknown provider type '{other}' (supported: 'oidc', 'k8s-tokenreview')",
                    cfg.id
                )));
            }
        };
        providers.push(provider);
    }

    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::config::FederatedProviderConfig;

    fn oidc_cfg(id: &str) -> FederatedProviderConfig {
        FederatedProviderConfig {
            provider: "oidc".into(),
            id: id.into(),
            issuer: Some("https://issuer.example.com".into()),
            audience: Some("test-audience".into()),
            jwks_url: Some("https://issuer.example.com/.well-known/jwks.json".into()),
            bearer_token_path: None,
            api_server: None,
            ca_cert_path: None,
            reviewer_token_path: None,
        }
    }

    fn k8s_cfg(id: &str) -> FederatedProviderConfig {
        FederatedProviderConfig {
            provider: "k8s-tokenreview".into(),
            id: id.into(),
            issuer: None,
            audience: None,
            jwks_url: None,
            bearer_token_path: None,
            api_server: Some("https://k8s.example.com".into()),
            ca_cert_path: None,
            reviewer_token_path: None,
        }
    }

    #[tokio::test]
    async fn empty_config_yields_empty_vec() {
        let result = build_providers(&[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn oidc_missing_issuer_returns_error() {
        let mut cfg = oidc_cfg("oidc1");
        cfg.issuer = None;
        let err = build_providers(&[cfg]).await.err().unwrap();
        assert!(err.to_string().contains("issuer"), "expected 'issuer' in error, got: {err}");
    }

    #[tokio::test]
    async fn oidc_missing_audience_returns_error() {
        let mut cfg = oidc_cfg("oidc1");
        cfg.audience = None;
        let err = build_providers(&[cfg]).await.err().unwrap();
        assert!(err.to_string().contains("audience"), "expected 'audience' in error, got: {err}");
    }

    #[tokio::test]
    async fn k8s_missing_api_server_returns_error() {
        let mut cfg = k8s_cfg("k8s1");
        cfg.api_server = None;
        let err = build_providers(&[cfg]).await.err().unwrap();
        assert!(
            err.to_string().contains("api_server"),
            "expected 'api_server' in error, got: {err}"
        );
    }

    #[tokio::test]
    async fn unknown_provider_type_returns_error() {
        let cfg = FederatedProviderConfig {
            provider: "saml".into(),
            id: "saml1".into(),
            issuer: None,
            audience: None,
            jwks_url: None,
            bearer_token_path: None,
            api_server: None,
            ca_cert_path: None,
            reviewer_token_path: None,
        };
        let err = build_providers(&[cfg]).await.err().unwrap();
        assert!(err.to_string().contains("saml"), "expected provider type in error, got: {err}");
    }

    #[tokio::test]
    async fn k8s_builds_successfully_without_ca_cert() {
        let cfg = k8s_cfg("k8s-no-ca");
        let result = build_providers(&[cfg]).await;
        assert!(result.is_ok());
        let providers = result.unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].provider_id(), "k8s-no-ca");
    }
}
