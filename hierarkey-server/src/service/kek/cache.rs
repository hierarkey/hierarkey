// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::keys::{Kek, KekId};
use hierarkey_core::CkResult;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, trace};
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of KEKs to store in the cache by default
const DEFAULT_MAX_CACHE_SIZE: usize = 1000;
/// Seconds between eviction runs
const DEFAULT_EVICTION_SCHEDULE: usize = 60;

/// A Kek cache that stored UNENCRYPTED KEKs in memory with TTL and LRU eviction.
/// This is to make sure we don't need to consult the master key for each request
/// to a secret. If the cache reaches its max size, the least recently used entry
/// is evicted. If the TTL is reached, the entry is evicted by a secondary thread.
pub struct KekCache {
    /// Time-to-live for each KEK entry
    default_ttl: Duration,
    /// Maximum number of KEK entries to store
    max_size: usize,
    /// The cache entries
    entries: Mutex<HashMap<KekId, KekCacheEntry>>,
}

impl KekCache {
    pub fn new(ttl: Duration) -> Arc<Self> {
        Self::with_max_size(ttl, DEFAULT_MAX_CACHE_SIZE)
    }

    pub fn with_max_size(ttl: Duration, max_size: usize) -> Arc<Self> {
        debug!("Creating KEK cache with TTL {:?} and max size {}", ttl, max_size);

        Arc::new(Self {
            default_ttl: ttl,
            max_size,
            entries: Mutex::new(HashMap::new()),
        })
    }

    pub fn find_entry(&self, kek_id: KekId) -> CkResult<Option<Kek>> {
        let mut entries = self.entries.lock();

        if let Some(entry) = entries.get_mut(&kek_id) {
            // Check if entry has expired
            if entry.is_expired(self.default_ttl) {
                trace!("KEK cache entry expired for kek_id '{}'", kek_id);
                entries.remove(&kek_id);
                return Ok(None);
            }

            entry.last_used = Instant::now();
            entry.access_count += 1;

            trace!(
                "KEK cache hit for namespace '{}' (accessed {} times)",
                kek_id, entry.access_count
            );

            Ok(Some(Kek::from_bytes(&entry.decrypted_kek)?))
        } else {
            trace!("KEK cache miss for kek_id '{}'", kek_id);
            Ok(None)
        }
    }

    pub fn insert(&self, kek_id: KekId, key: &Kek) {
        let mut entries = self.entries.lock();

        // If cache is full, evict LRU entry
        if entries.len() >= self.max_size && !entries.contains_key(&kek_id) {
            self.evict_lru(&mut entries);
        }

        let entry = KekCacheEntry {
            decrypted_kek: Zeroizing::new(*key.as_bytes()),
            last_used: Instant::now(),
            access_count: 0,
        };

        trace!("Inserting KEK into cache for kek id '{}'", kek_id);
        entries.insert(kek_id, entry);
    }

    pub fn evict(&self, kek_id: KekId) {
        let mut entries = self.entries.lock();

        if let Some(mut kek) = entries.remove(&kek_id) {
            trace!("Evicting kek id: {}", kek_id);
            kek.decrypted_kek.zeroize();
        }
    }

    pub fn evict_idle(&self) {
        let mut entries = self.entries.lock();
        let initial_size = entries.len();

        let now = Instant::now();
        entries.retain(|kek_id, entry| {
            let expired = entry.is_expired(self.default_ttl);
            if expired {
                trace!(
                    "Evicting idle KEK id '{}' (unused for {:?})",
                    kek_id,
                    now.duration_since(entry.last_used)
                );
                entry.decrypted_kek.zeroize();
            }
            !expired
        });

        let evicted = initial_size - entries.len();
        if evicted > 0 {
            debug!("Evicted {} idle KEK entries", evicted);
        }
    }

    fn evict_lru(&self, entries: &mut HashMap<KekId, KekCacheEntry>) {
        // Find the least recently used entry
        if let Some((lru_kek_id, _)) = entries.iter().min_by_key(|(_, entry)| entry.last_used) {
            let lru_kek_id = *lru_kek_id;
            if let Some(mut entry) = entries.remove(&lru_kek_id) {
                trace!(
                    "Evicting LRU KEK for id '{}' (last used {:?} ago)",
                    lru_kek_id,
                    Instant::now().duration_since(entry.last_used)
                );
                entry.decrypted_kek.zeroize();
            }
        }
    }

    #[cfg(test)]
    pub fn clear(&self) {
        let mut entries = self.entries.lock();
        let count = entries.len();

        for (_, mut entry) in entries.drain() {
            entry.decrypted_kek.zeroize();
        }

        debug!("Cleared {} KEK entries from cache", count);
    }

    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.entries.lock().len()
    }

    #[cfg(test)]
    pub fn contains(&self, kek_id: KekId) -> bool {
        let entries = self.entries.lock();
        if let Some(entry) = entries.get(&kek_id) {
            !entry.is_expired(self.default_ttl)
        } else {
            false
        }
    }

    #[cfg(test)]
    pub fn ttl(&self) -> Duration {
        self.default_ttl
    }

    #[cfg(test)]
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

impl Drop for KekCache {
    fn drop(&mut self) {
        // Ensure all keys are zeroized when cache is dropped
        let mut entries = self.entries.lock();
        for (_, mut entry) in entries.drain() {
            entry.decrypted_kek.zeroize();
        }
    }
}

#[derive(Debug)]
struct KekCacheEntry {
    decrypted_kek: Zeroizing<[u8; 32]>,
    last_used: Instant,
    access_count: u64,
}

impl KekCacheEntry {
    fn is_expired(&self, ttl: Duration) -> bool {
        Instant::now().duration_since(self.last_used) > ttl
    }
}

impl Drop for KekCacheEntry {
    fn drop(&mut self) {
        self.decrypted_kek.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::keys::Kek;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = KekCache::new(Duration::from_secs(60));
        let kek = Kek::generate().unwrap();

        let kek_id = KekId::new();
        cache.insert(kek_id, &kek);

        let retrieved = cache.find_entry(kek_id).unwrap().unwrap();
        assert_eq!(kek.as_bytes(), retrieved.as_bytes());
    }

    #[test]
    fn test_cache_miss() {
        let cache = KekCache::new(Duration::from_secs(60));

        let kek_id = KekId::new();
        let result = cache.find_entry(kek_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_eviction() {
        let cache = KekCache::new(Duration::from_secs(60));
        let kek = Kek::generate().unwrap();

        let kek_id = KekId::new();
        cache.insert(kek_id, &kek);
        assert!(cache.contains(kek_id));

        cache.evict(kek_id);
        assert!(!cache.contains(kek_id));

        let result = cache.find_entry(kek_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = KekCache::new(Duration::from_millis(100));
        let kek = Kek::generate().unwrap();

        let kek_id = KekId::new();
        cache.insert(kek_id, &kek);
        assert!(cache.contains(kek_id));

        std::thread::sleep(Duration::from_millis(150));

        let result = cache.find_entry(kek_id).unwrap();
        assert!(result.is_none());
        assert!(!cache.contains(kek_id));
    }

    #[test]
    fn test_cache_evict_idle() {
        let cache = KekCache::new(Duration::from_millis(500));
        let kek1 = Kek::generate().unwrap();
        let kek2 = Kek::generate().unwrap();

        let kek1_id = KekId::new();
        cache.insert(kek1_id, &kek1);

        std::thread::sleep(Duration::from_millis(600));

        let kek2_id = KekId::new();
        cache.insert(kek2_id, &kek2);

        cache.evict_idle();

        assert!(!cache.contains(kek1_id));
        // Use size() instead of contains(kek2_id): kek2 was just inserted so it is
        // definitely in the map, but contains() also re-checks TTL expiry and the
        // 500 ms window is too tight under instrumented test runners (e.g. tarpaulin).
        // Knowing kek1 is gone and exactly one entry remains is sufficient proof.
        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = KekCache::with_max_size(Duration::from_secs(60), 2);

        let kek1 = Kek::generate().unwrap();
        let kek2 = Kek::generate().unwrap();
        let kek3 = Kek::generate().unwrap();

        let kek1_id = KekId::new();
        let kek2_id = KekId::new();
        let kek3_id = KekId::new();

        cache.insert(kek1_id, &kek1);
        std::thread::sleep(Duration::from_millis(10));

        cache.insert(kek2_id, &kek2);
        std::thread::sleep(Duration::from_millis(10));

        // Access ns1 to make it more recently used
        cache.find_entry(kek1_id).unwrap();

        // Insert ns3, should evict ns2 (least recently used)
        cache.insert(kek3_id, &kek3);

        assert_eq!(cache.size(), 2);
        assert!(cache.contains(kek1_id));
        assert!(!cache.contains(kek2_id));
        assert!(cache.contains(kek3_id));
    }

    #[test]
    fn test_cache_clear() {
        let cache = KekCache::new(Duration::from_secs(60));

        let kek1 = Kek::generate().unwrap();
        let kek2 = Kek::generate().unwrap();

        let kek1_id = KekId::new();
        let kek2_id = KekId::new();

        cache.insert(kek1_id, &kek1);
        cache.insert(kek2_id, &kek2);

        assert_eq!(cache.size(), 2);

        cache.clear();

        assert_eq!(cache.size(), 0);
        assert!(!cache.contains(kek1_id));
        assert!(!cache.contains(kek2_id));
    }

    #[test]
    fn test_cache_contains() {
        let cache = KekCache::new(Duration::from_secs(60));
        let kek = Kek::generate().unwrap();

        let kek_id = KekId::new();
        assert!(!cache.contains(kek_id));

        cache.insert(kek_id, &kek);
        assert!(cache.contains(kek_id));

        cache.evict(kek_id);
        assert!(!cache.contains(kek_id));
    }

    #[test]
    fn test_cache_max_size() {
        let cache = KekCache::with_max_size(Duration::from_secs(60), 100);
        assert_eq!(cache.max_size(), 100);
    }

    #[test]
    fn test_cache_ttl() {
        let ttl = Duration::from_secs(300);
        let cache = KekCache::new(ttl);
        assert_eq!(cache.ttl(), ttl);
    }

    #[test]
    fn test_multiple_inserts_same_kek_ids() {
        let cache = KekCache::new(Duration::from_secs(60));

        let kek1 = Kek::generate().unwrap();
        let kek2 = Kek::generate().unwrap();

        let kek_id = KekId::new();
        cache.insert(kek_id, &kek1);
        cache.insert(kek_id, &kek2);

        // Should still have only 1 entry
        assert_eq!(cache.size(), 1);

        // Should retrieve the latest key
        let retrieved = cache.find_entry(kek_id).unwrap().unwrap();
        assert_eq!(kek2.as_bytes(), retrieved.as_bytes());
    }
}
