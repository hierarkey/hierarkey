// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::manager::account::AccountId;
use crate::manager::rbac::rule::Rule;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Default time-to-live for a cached rule set.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Default maximum number of accounts to keep in the cache.
pub const DEFAULT_MAX_SIZE: usize = 1000;

/// Per-account RBAC rule cache.
///
/// Caches the full set of rules that apply to an account (the result of
/// `get_rules_for_account`) so that `is_allowed` / `explain` don't need a
/// database round-trip on every request.
///
/// Invalidation strategy:
///  - Account-specific operations (bind/unbind rule or role to a user) ->
///    `invalidate(account_id)` — only that account's entry is dropped.
///  - Role-wide or rule-wide mutations (add/remove rule from role, delete role
///    or rule) -> `invalidate_all()` — the entire cache is cleared, because we
///    don't track which accounts are bound to which role.
///  - A TTL acts as a safety net regardless.
pub struct RbacCache {
    entries: Mutex<HashMap<AccountId, RbacCacheEntry>>,
    ttl: Duration,
    max_size: usize,
}

struct RbacCacheEntry {
    rules: Vec<Rule>,
    inserted_at: Instant,
}

impl RbacCacheEntry {
    fn is_expired(&self, ttl: Duration) -> bool {
        Instant::now().duration_since(self.inserted_at) > ttl
    }
}

impl RbacCache {
    pub fn new(ttl: Duration, max_size: usize) -> Arc<Self> {
        debug!("Creating RBAC cache with TTL {:?} and max size {}", ttl, max_size);
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_size,
        })
    }

    /// Return the cached rules for `account_id`, or `None` on miss/expiry.
    pub fn get(&self, account_id: AccountId) -> Option<Vec<Rule>> {
        let mut entries = self.entries.lock();

        if let Some(entry) = entries.get(&account_id) {
            if entry.is_expired(self.ttl) {
                trace!("RBAC cache entry expired for account '{}'", account_id);
                entries.remove(&account_id);
                return None;
            }
            trace!("RBAC cache hit for account '{}'", account_id);
            return Some(entry.rules.clone());
        }

        trace!("RBAC cache miss for account '{}'", account_id);
        None
    }

    /// Store `rules` for `account_id`. Evicts the oldest entry if at capacity.
    pub fn insert(&self, account_id: AccountId, rules: Vec<Rule>) {
        let mut entries = self.entries.lock();

        // If at capacity and this is a new key, evict the oldest entry.
        if entries.len() >= self.max_size
            && !entries.contains_key(&account_id)
            && let Some((&oldest_id, _)) = entries.iter().min_by_key(|(_, e)| e.inserted_at)
        {
            entries.remove(&oldest_id);
            trace!("RBAC cache evicted oldest entry to make room");
        }

        trace!("RBAC cache insert for account '{}' ({} rules)", account_id, rules.len());
        entries.insert(
            account_id,
            RbacCacheEntry {
                rules,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Invalidate a single account's cached rules (e.g. after a direct bind/unbind).
    pub fn invalidate(&self, account_id: AccountId) {
        if self.entries.lock().remove(&account_id).is_some() {
            debug!("RBAC cache invalidated for account '{}'", account_id);
        }
    }

    /// Invalidate the entire cache (e.g. after a role or rule mutation).
    pub fn invalidate_all(&self) {
        let mut entries = self.entries.lock();
        let count = entries.len();
        entries.clear();
        if count > 0 {
            debug!("RBAC cache cleared ({} entries evicted)", count);
        }
    }

    // ------ test helpers -------------------------------------------------------

    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.entries.lock().len()
    }

    #[cfg(test)]
    pub fn contains(&self, account_id: AccountId) -> bool {
        let entries = self.entries.lock();
        entries.get(&account_id).is_some_and(|e| !e.is_expired(self.ttl))
    }

    // #[cfg(test)]
    // pub fn ttl(&self) -> Duration {
    //     self.ttl
    // }
    //
    // #[cfg(test)]
    // pub fn max_size(&self) -> usize {
    //     self.max_size
    // }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::account::AccountId;

    fn make_cache(ttl: Duration, max_size: usize) -> Arc<RbacCache> {
        RbacCache::new(ttl, max_size)
    }

    #[test]
    fn miss_on_empty_cache() {
        let cache = make_cache(DEFAULT_TTL, DEFAULT_MAX_SIZE);
        assert!(cache.get(AccountId::new()).is_none());
    }

    #[test]
    fn insert_and_hit() {
        let cache = make_cache(DEFAULT_TTL, DEFAULT_MAX_SIZE);
        let id = AccountId::new();
        cache.insert(id, vec![]);
        assert!(cache.get(id).is_some());
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = make_cache(DEFAULT_TTL, DEFAULT_MAX_SIZE);
        let id = AccountId::new();
        cache.insert(id, vec![]);
        assert!(cache.contains(id));
        cache.invalidate(id);
        assert!(!cache.contains(id));
        assert!(cache.get(id).is_none());
    }

    #[test]
    fn invalidate_all_clears_cache() {
        let cache = make_cache(DEFAULT_TTL, DEFAULT_MAX_SIZE);
        let id1 = AccountId::new();
        let id2 = AccountId::new();
        cache.insert(id1, vec![]);
        cache.insert(id2, vec![]);
        assert_eq!(cache.size(), 2);
        cache.invalidate_all();
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn ttl_expiry_returns_none() {
        let cache = make_cache(Duration::from_millis(50), DEFAULT_MAX_SIZE);
        let id = AccountId::new();
        cache.insert(id, vec![]);
        // Use size() instead of contains() here: the entry is definitely in the
        // map right after insert, but contains() also checks TTL expiry and the
        // 50 ms window is too tight under instrumented test runners (e.g. tarpaulin).
        assert_eq!(cache.size(), 1);
        std::thread::sleep(Duration::from_millis(100));
        assert!(cache.get(id).is_none());
        assert!(!cache.contains(id));
    }

    #[test]
    fn evicts_oldest_when_full() {
        let cache = make_cache(DEFAULT_TTL, 2);
        let id1 = AccountId::new();
        let id2 = AccountId::new();
        let id3 = AccountId::new();

        cache.insert(id1, vec![]);
        std::thread::sleep(Duration::from_millis(5));
        cache.insert(id2, vec![]);
        // id1 is oldest — should be evicted when id3 is inserted
        cache.insert(id3, vec![]);

        assert_eq!(cache.size(), 2);
        assert!(!cache.contains(id1));
        assert!(cache.contains(id2));
        assert!(cache.contains(id3));
    }

    #[test]
    fn reinserting_same_id_does_not_evict() {
        let cache = make_cache(DEFAULT_TTL, 2);
        let id1 = AccountId::new();
        let id2 = AccountId::new();
        cache.insert(id1, vec![]);
        cache.insert(id2, vec![]);
        // Re-inserting id1 (already in cache) should not trigger eviction
        cache.insert(id1, vec![]);
        assert_eq!(cache.size(), 2);
        assert!(cache.contains(id1));
        assert!(cache.contains(id2));
    }
}
