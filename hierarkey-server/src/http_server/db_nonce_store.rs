// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::{CkError, CkResult};
use sqlx::PgPool;

/// TTL applied to every stored nonce, in seconds.
///
/// Must be at least `2 × TS_WINDOW` (the timestamp acceptance window used by
/// the Ed25519 handler) so that a nonce remains in the store for the full
/// period during which a matching signed request would be accepted.
pub const NONCE_TTL_SECS: i64 = 120;

pub struct DbNonceStore {
    pool: PgPool,
}

impl DbNonceStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Try to consume a nonce.
    ///
    /// Returns `Ok(true)` if the nonce was freshly accepted and recorded.
    /// Returns `Ok(false)` if the nonce was already present — the caller
    /// should reject the request as a replay.
    pub async fn try_consume(&self, nonce: &str) -> CkResult<bool> {
        // Prune expired entries first to keep the table small.
        sqlx::query("DELETE FROM auth_nonces WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| CkError::Custom(format!("nonce store prune failed: {e}")))?;

        // Atomic check-and-insert via PRIMARY KEY conflict.
        // Affected rows = 1 → fresh nonce; 0 → already consumed.
        let result = sqlx::query(
            "INSERT INTO auth_nonces (nonce, expires_at) \
             VALUES ($1, NOW() + ($2 || ' seconds')::INTERVAL) \
             ON CONFLICT (nonce) DO NOTHING",
        )
        .bind(nonce)
        .bind(NONCE_TTL_SECS)
        .execute(&self.pool)
        .await
        .map_err(|e| CkError::Custom(format!("nonce store insert failed: {e}")))?;

        Ok(result.rows_affected() == 1)
    }
}
