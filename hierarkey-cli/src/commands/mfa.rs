// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{Parser, Subcommand};

pub mod backup_codes;
pub mod confirm;
pub mod disable;
pub mod enroll;
pub mod verify;

#[derive(Subcommand)]
pub enum MfaCommand {
    /// Start MFA enrollment — generates a TOTP secret and QR code URI
    Enroll,

    /// Confirm MFA enrollment with a TOTP code from your authenticator app
    Confirm(MfaConfirmArgs),

    /// Complete an MFA login challenge (use when you already have a challenge token)
    Verify(MfaVerifyArgs),

    /// Disable MFA for your account
    Disable,

    /// Regenerate backup codes (invalidates previous codes)
    BackupCodes,
}

#[derive(Parser, Debug)]
pub struct MfaConfirmArgs {
    /// TOTP code from your authenticator app
    #[arg(long)]
    pub code: String,
}

#[derive(Parser, Debug)]
pub struct MfaVerifyArgs {
    /// The MFA challenge token returned by `hkey auth login` (when mfa_required is true)
    #[arg(long)]
    pub challenge_token: String,

    /// TOTP code or backup code from your authenticator app
    #[arg(long)]
    pub code: String,

    /// Token lifetime (e.g. 60s, 30m, 2h, 7d); defaults to server-configured value
    #[arg(long)]
    pub ttl: Option<String>,
}
