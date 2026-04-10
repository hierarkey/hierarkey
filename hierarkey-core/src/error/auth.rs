// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::CkError;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Authentication failed due to invalid credentials, token issues, or account problems.
    #[error("unauthenticated")]
    Unauthenticated { reason: AuthFailReason },
    /// Authentication succeeded but the authenticated user does not have permission to perform the requested action.
    #[error("forbidden: {reason}")]
    Forbidden { reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthFailReason {
    /// Username or password is incorrect
    InvalidCredentials,
    /// Token is not conforming to expected format
    InvalidToken,
    /// Token has expired
    ExpiredToken,
    /// No token provided
    MissingToken,
    /// Token has been revoked
    RevokedToken,
    /// Associated user is missing
    AccountNotFound,
    /// Associated user is disabled
    AccountDisabled,
    /// Account is temporarily locked due to too many failed login attempts
    AccountLocked,
}

impl From<AuthError> for CkError {
    fn from(e: AuthError) -> Self {
        CkError::Auth(e)
    }
}

impl std::fmt::Display for AuthFailReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason_str = match self {
            AuthFailReason::InvalidCredentials => "User not found or invalid credentials",
            AuthFailReason::InvalidToken => "Invalid token",
            AuthFailReason::ExpiredToken => "Expired token",
            AuthFailReason::MissingToken => "Missing token",
            AuthFailReason::RevokedToken => "Revoked token",
            AuthFailReason::AccountNotFound => "User not found or invalid credentials",
            AuthFailReason::AccountDisabled => "User disabled",
            AuthFailReason::AccountLocked => "Account is temporarily locked due to too many failed login attempts",
        };
        write!(f, "{reason_str}")
    }
}
