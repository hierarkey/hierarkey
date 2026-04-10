// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::TokenManager;
use crate::audit_context::CallContext;
use crate::manager::token::PatId;
use hierarkey_core::CkResult;
use std::sync::Arc;

pub struct TokenService {
    token_manager: Arc<TokenManager>,
}

impl TokenService {
    pub fn new(token_manager: Arc<TokenManager>) -> Self {
        Self { token_manager }
    }

    pub async fn revoke_token(&self, ctx: &CallContext, token_id: PatId) -> CkResult<bool> {
        self.token_manager.revoke_token(ctx, token_id).await
    }
}
