// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::manager::account::AccountDto;
use hierarkey_core::Labels;
use hierarkey_core::resources::AccountName;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "account_type", rename_all = "lowercase")]
pub enum CreateAccountRequest {
    User {
        name: AccountName,
        email: Option<String>,
        full_name: Option<String>,
        is_active: bool,
        must_change_password: bool,
        description: Option<String>,
        labels: Labels,

        // user-only
        password: Zeroizing<String>,
    },

    Service {
        name: AccountName,
        is_active: bool,
        description: Option<String>,
        labels: Labels,

        // service-only
        bootstrap: ServiceBootstrap,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum ServiceBootstrap {
    Passphrase {
        // Either client-generated or user-provided; server stores hash.
        passphrase: Zeroizing<String>,
    },

    Ed25519 {
        // client-generated keypair; server stores public key
        public_key: String,
    },
}

// fn is_false(v: &bool) -> bool { !*v }

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountSearchResponse {
    pub entries: Vec<AccountDto>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}
