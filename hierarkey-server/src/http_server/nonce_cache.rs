// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// In-process nonce cache for Ed25519 service-account token authentication.
///
/// Prevents replay attacks by ensuring each nonce can only be used once
/// within the timestamp acceptance window.  Entries are kept for `ttl`
/// and are pruned lazily on every insert.
pub struct NonceCache {
    inner: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl NonceCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Try to consume a nonce.
    ///
    /// Returns `true` if the nonce was freshly accepted (not seen before
    /// within the TTL window) and has now been recorded.
    /// Returns `false` if the nonce was already seen — the request should
    /// be rejected as a replay.
    pub fn try_consume(&self, nonce: &str) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Prune expired entries to keep memory bounded.
        map.retain(|_, expires_at| now < *expires_at);

        if map.contains_key(nonce) {
            return false;
        }

        map.insert(nonce.to_string(), now + self.ttl);
        true
    }
}
