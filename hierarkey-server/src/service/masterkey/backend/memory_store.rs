// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#![allow(unused)]

use std::collections::HashMap;

use hierarkey_core::{CkError, CkResult};
use parking_lot::RwLock;
use zeroize::Zeroizing;

/// An in-memory "file store" for tests/dev.
/// Stores UTF-8 JSON strings keyed by filename.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: RwLock<HashMap<String, String>>,
    max_bytes: Option<usize>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_bytes: None,
        }
    }

    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_bytes: Some(max_bytes),
        }
    }

    pub fn contains(&self, filename: &str) -> bool {
        self.entries.read().contains_key(filename)
    }

    pub fn read_to_string(&self, filename: &str) -> CkResult<Zeroizing<String>> {
        let guard = self.entries.read();
        let s = guard
            .get(filename)
            .ok_or_else(|| CkError::MasterKey("file not found in memory store".into()))?;
        Ok(Zeroizing::new(s.clone()))
    }

    /// Serializes JSON and stores it under `filename`.
    pub fn write_json(&self, filename: &str, value: &serde_json::Value) -> CkResult<()> {
        validate_filename(filename)?;

        let s = serde_json::to_string_pretty(value)?;
        self.enforce_size(&s)?;

        self.entries.write().insert(filename.to_string(), s);
        Ok(())
    }

    /// Store a raw JSON string
    pub fn insert_raw(&self, filename: &str, raw_json: &str) -> CkResult<()> {
        validate_filename(filename)?;
        self.enforce_size(raw_json)?;
        self.entries.write().insert(filename.to_string(), raw_json.to_string());
        Ok(())
    }

    pub fn remove(&self, filename: &str) {
        self.entries.write().remove(filename);
    }

    pub fn clear(&self) {
        self.entries.write().clear();
    }

    pub fn list_filenames(&self) -> Vec<String> {
        self.entries.read().keys().cloned().collect()
    }

    fn enforce_size(&self, s: &str) -> CkResult<()> {
        if let Some(max) = self.max_bytes
            && s.len() > max
        {
            return Err(CkError::MasterKey("payload too large for memory store".into()));
        }
        Ok(())
    }
}

fn validate_filename(filename: &str) -> CkResult<()> {
    if filename.is_empty() {
        return Err(CkError::MasterKey("invalid filename: empty".into()));
    }
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(CkError::MasterKey("invalid filename".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> serde_json::Value {
        serde_json::json!({"key": "value", "num": 42})
    }

    // ---- new / contains / write / read ----

    #[test]
    fn new_store_is_empty() {
        let store = MemoryStore::new();
        assert!(!store.contains("anything.json"));
        assert!(store.list_filenames().is_empty());
    }

    #[test]
    fn write_and_read_roundtrip() {
        let store = MemoryStore::new();
        store.write_json("test.json", &sample_json()).unwrap();
        assert!(store.contains("test.json"));
        let content = store.read_to_string("test.json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["key"], "value");
    }

    #[test]
    fn read_missing_file_is_error() {
        let store = MemoryStore::new();
        assert!(store.read_to_string("ghost.json").is_err());
    }

    #[test]
    fn overwrite_replaces_content() {
        let store = MemoryStore::new();
        store.write_json("f.json", &serde_json::json!({"v": 1})).unwrap();
        store.write_json("f.json", &serde_json::json!({"v": 2})).unwrap();
        let content = store.read_to_string("f.json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["v"], 2);
    }

    // ---- insert_raw ----

    #[test]
    fn insert_raw_and_read() {
        let store = MemoryStore::new();
        store.insert_raw("raw.json", r#"{"raw": true}"#).unwrap();
        let s = store.read_to_string("raw.json").unwrap();
        assert!(s.contains("raw"));
    }

    // ---- remove / clear ----

    #[test]
    fn remove_deletes_entry() {
        let store = MemoryStore::new();
        store.write_json("to-remove.json", &sample_json()).unwrap();
        assert!(store.contains("to-remove.json"));
        store.remove("to-remove.json");
        assert!(!store.contains("to-remove.json"));
    }

    #[test]
    fn clear_removes_all_entries() {
        let store = MemoryStore::new();
        store.write_json("a.json", &sample_json()).unwrap();
        store.write_json("b.json", &sample_json()).unwrap();
        store.clear();
        assert!(store.list_filenames().is_empty());
    }

    // ---- list_filenames ----

    #[test]
    fn list_filenames_returns_all_keys() {
        let store = MemoryStore::new();
        store.write_json("x.json", &sample_json()).unwrap();
        store.write_json("y.json", &sample_json()).unwrap();
        let mut names = store.list_filenames();
        names.sort();
        assert_eq!(names, vec!["x.json", "y.json"]);
    }

    // ---- filename validation ----

    #[test]
    fn empty_filename_is_rejected() {
        let store = MemoryStore::new();
        assert!(store.write_json("", &sample_json()).is_err());
    }

    #[test]
    fn dotdot_filename_is_rejected() {
        let store = MemoryStore::new();
        assert!(store.write_json("../escape.json", &sample_json()).is_err());
    }

    #[test]
    fn slash_filename_is_rejected() {
        let store = MemoryStore::new();
        assert!(store.write_json("sub/dir.json", &sample_json()).is_err());
    }

    #[test]
    fn backslash_filename_is_rejected() {
        let store = MemoryStore::new();
        assert!(store.insert_raw("sub\\dir.json", "{}").is_err());
    }

    // ---- with_max_bytes ----

    #[test]
    fn max_bytes_allows_small_payload() {
        let store = MemoryStore::with_max_bytes(10_000);
        assert!(store.write_json("small.json", &sample_json()).is_ok());
    }

    #[test]
    fn max_bytes_rejects_large_payload() {
        let store = MemoryStore::with_max_bytes(5); // 5 bytes max
        assert!(store.write_json("big.json", &sample_json()).is_err());
    }
}
