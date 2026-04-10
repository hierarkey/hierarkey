// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::http_server::handlers::pat_response::PatResponse;
use crate::manager::account::{AccountDto, AccountId};
use crate::manager::token::TokenPurpose;
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
// -----------------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
pub struct WhoamiResponse {
    pub account: AccountDto,
    pub token: PatResponse,
}

// -----------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthScope {
    /// One time token for changing password
    ChangePassword,
    /// Token with full access
    Auth,
    /// Long-lived token used only to obtain a new access token via /auth/refresh
    Refresh,
    /// Short-lived token used only to complete an MFA challenge
    MfaChallenge,
}

impl From<TokenPurpose> for AuthScope {
    fn from(scope: TokenPurpose) -> Self {
        match scope {
            TokenPurpose::ChangePwd => AuthScope::ChangePassword,
            TokenPurpose::Auth => AuthScope::Auth,
            TokenPurpose::Refresh => AuthScope::Refresh,
            TokenPurpose::MfaChallenge => AuthScope::MfaChallenge,
        }
    }
}

impl std::fmt::Display for AuthScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthScope::ChangePassword => write!(f, "change_password"),
            AuthScope::Auth => write!(f, "auth"),
            AuthScope::Refresh => write!(f, "refresh"),
            AuthScope::MfaChallenge => write!(f, "mfa_challenge"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub account_name: AccountName,
    pub password: Zeroizing<String>,
    pub description: String,
    pub ttl_minutes: u32,
    pub scope: AuthScope,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub account_id: AccountId,
    pub account_short_id: String,
    pub account_name: AccountName,
    pub scope: AuthScope,
    pub access_token: Zeroizing<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub refresh_token: Zeroizing<String>,
    pub refresh_expires_at: chrono::DateTime<chrono::Utc>,

    /// When `true`, the client must complete an MFA challenge before receiving
    /// a full Auth token. `access_token` holds the short-lived MFA-challenge
    /// token in this case; `refresh_token` is empty.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mfa_required: bool,
    /// The TOTP/backup-code method required ("totp" when set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_method: Option<String>,
}
