// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure wrapper for API tokens that ensures sensitive data is zeroed out when dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecureToken(String);

impl SecureToken {
    pub fn new(token: String) -> Self {
        Self(token)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecureToken {
    fn from(s: String) -> Self {
        SecureToken::new(s)
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CliConfig {
    pub server_url: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl CliConfig {
    pub fn get_token(&self) -> Option<SecureToken> {
        self.token.as_ref().map(|t| SecureToken::new(t.clone()))
    }

    pub fn set_token(&mut self, token: SecureToken) {
        self.token = Some(token.0.clone());
    }

    pub fn clear_token(&mut self) {
        if let Some(mut token) = self.token.take() {
            token.zeroize();
        }
    }
}
