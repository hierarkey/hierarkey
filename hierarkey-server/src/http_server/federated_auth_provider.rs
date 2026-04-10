// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::http_server::api_error::HttpError;

/// The identity asserted by a federated auth provider after validating a credential.
#[derive(Debug, Clone)]
pub struct FederatedIdentity {
    /// Stable, unique identifier for this principal within the issuer.
    ///
    /// For OIDC this is the `sub` claim; for Kubernetes TokenReview this is the
    /// user UID (falling back to the username if UID is absent).
    pub external_subject: String,

    /// The issuer that attests to this identity.
    ///
    /// For OIDC this is the issuer URL (`iss` claim); for Kubernetes TokenReview
    /// this is the configured `api_server` URL.
    pub external_issuer: String,
}

/// Extension point for federated (external) authentication providers.
///
/// Each `[[auth.federated]]` config block is materialised into one implementation
/// of this trait and stored in `AppState::federated_providers`.
///
/// The auth handler looks up the correct provider by its `provider_id()`, calls
/// `exchange()` to validate the credential, and then resolves the returned
/// `FederatedIdentity` against the `federated_identities` table to find the
/// linked service account.
#[async_trait::async_trait]
pub trait FederatedAuthProvider: Send + Sync {
    /// The unique ID of this provider — must match the `id` field of the config
    /// entry and is used as the URL path segment in `POST /v1/auth/federated/{id}`.
    fn provider_id(&self) -> &str;

    /// The provider type string, e.g. `"oidc"` or `"k8s-tokenreview"`.
    fn provider_type(&self) -> &str;

    /// The issuer / external system URL.
    /// For OIDC this is the issuer URL (may be empty when jwks_url is set directly);
    /// for k8s-tokenreview this is the API server URL.
    fn issuer(&self) -> &str;

    /// The expected audience claim (OIDC only; `None` for k8s-tokenreview).
    fn audience(&self) -> Option<&str>;

    /// The resolved JWKS URL used to fetch signing keys.
    /// `None` for providers that don't use JWKS (e.g. k8s-tokenreview).
    fn jwks_url(&self) -> Option<&str>;

    /// Validate `credential` and return the asserted `FederatedIdentity` on success.
    ///
    /// Implementations are responsible for all cryptographic verification (JWT
    /// signature, expiry, issuer/audience) or external API calls (TokenReview).
    /// Return an appropriate `HttpError` on any validation failure.
    async fn exchange(&self, credential: &str) -> Result<FederatedIdentity, HttpError>;
}
