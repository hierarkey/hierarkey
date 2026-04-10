// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::HttpError;
use crate::manager::account::Account;
use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

/// The MFA method that was used (for display / client guidance).
#[derive(Debug, Clone)]
pub enum MfaMethod {
    Totp,
}

impl MfaMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            MfaMethod::Totp => "totp",
        }
    }
}

/// Returned by `MfaProvider::begin_challenge` so the login handler can build
/// the intermediate `AuthResponse`.
pub struct MfaChallengeInfo {
    /// The short-lived MFA-challenge PAT token string (e.g. `hkmf_…`).
    pub challenge_token: Zeroizing<String>,
    pub expires_at: DateTime<Utc>,
    pub method: MfaMethod,
}

/// Extension point for MFA verification.
///
/// Registered on `AppState` by the commercial `MfaExtension`.  The community
/// edition ships no implementation; the commercial edition provides TOTP-based
/// verification.
#[async_trait::async_trait]
pub trait MfaProvider: Send + Sync {
    /// Called when password auth succeeds and `account.mfa_enabled = true`.
    ///
    /// Should issue a short-lived `MfaChallenge` PAT and return a
    /// `MfaChallengeInfo` describing it.
    async fn begin_challenge(
        &self,
        state: &AppState,
        call_ctx: &CallContext,
        account: &Account,
    ) -> Result<MfaChallengeInfo, HttpError>;

    /// Called by `POST /auth/mfa/verify`.
    ///
    /// Validates `code` (TOTP or backup code) against the account's stored
    /// secret.  Returns `Ok(())` on success; the caller issues full Auth
    /// tokens.
    async fn verify_code(
        &self,
        state: &AppState,
        call_ctx: &CallContext,
        account: &Account,
        code: &str,
    ) -> Result<(), HttpError>;
}
