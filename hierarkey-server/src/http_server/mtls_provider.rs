// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, HttpError};
use crate::http_server::handlers::auth_response::{AuthResponse, AuthScope};

/// Extension point for mTLS service-account authentication.
///
/// Implement this trait in the Commercial Edition and register the provider via
/// `StateBuilder::register_mtls_provider()` in a `ServerExtension::configure()` hook.
///
/// The community edition leaves `AppState::mtls_auth_provider` as `None`, causing
/// the token handler to return HTTP 501 when `method: "mtls"` is requested.
#[async_trait::async_trait]
pub trait MtlsAuthProvider: Send + Sync {
    /// Authenticate a service account using the supplied client-certificate DER bytes.
    ///
    /// `peer_cert_der` is `None` when no certificate was presented (e.g. header absent).
    /// The implementation is responsible for:
    ///   1. Rejecting `None` with an appropriate error.
    ///   2. Validating the cert chain against the configured CA.
    ///   3. Computing the SHA-256 fingerprint and looking up the service account.
    ///   4. Issuing a token via `state.auth_service.create_pat()`.
    async fn authenticate(
        &self,
        state: &AppState,
        call_ctx: &CallContext,
        ctx: ApiErrorCtx,
        peer_cert_der: Option<Vec<u8>>,
        scope: AuthScope,
        ttl_minutes: i64,
    ) -> Result<AuthResponse, HttpError>;
}
