// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::PersonalAccessToken;
use crate::manager::account::AccountId;
use crate::manager::token::PatId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PatResponse {
    pub id: PatId,
    pub short_id: String,
    pub account_id: AccountId,
    pub description: String,
    pub token_suffix: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<&PersonalAccessToken> for PatResponse {
    fn from(pat: &PersonalAccessToken) -> Self {
        PatResponse::new(pat)
    }
}

impl PatResponse {
    pub fn new(pat: &PersonalAccessToken) -> Self {
        PatResponse {
            id: pat.id,
            short_id: pat.short_id.to_string(),
            account_id: pat.account_id,
            description: pat.description.clone(),
            token_suffix: pat.token_suffix.clone(),
            created_at: pat.created_at,
            expires_at: pat.expires_at,
            last_used_at: pat.last_used_at,
            revoked_at: pat.revoked_at,
        }
    }
}
