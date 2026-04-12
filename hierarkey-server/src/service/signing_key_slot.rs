// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! Thread-safe holder for the currently active plaintext signing key.
//!
//! The slot starts empty.  Once the master key is unlocked the service layer
//! decrypts the signing key and loads it here via [`SigningKeySlot::load`].
//! On master-key rotation / lock the slot is cleared with [`SigningKeySlot::clear`].
//!
//! All managers that need to sign or verify row HMACs receive an
//! `Arc<SigningKeySlot>` and call [`SigningKeySlot::peek`] to borrow the key.
//! When the slot is empty (key not yet loaded) HMAC operations are skipped.

use crate::global::keys::SigningKey;
use parking_lot::RwLock;
use std::sync::Arc;

pub struct SigningKeySlot {
    inner: RwLock<Option<Arc<SigningKey>>>,
}

impl Default for SigningKeySlot {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningKeySlot {
    /// Create an empty slot (no key loaded yet).
    pub fn new() -> Self {
        Self { inner: RwLock::new(None) }
    }

    /// Replace the current key with a newly decrypted one.
    pub fn load(&self, key: SigningKey) {
        *self.inner.write() = Some(Arc::new(key));
    }

    /// Remove the key from the slot (called when the master key is locked or rotated).
    pub fn clear(&self) {
        *self.inner.write() = None;
    }

    /// Borrow a reference-counted handle to the current key, if any.
    /// Returns `None` when the slot is empty.
    pub fn peek(&self) -> Option<Arc<SigningKey>> {
        self.inner.read().clone()
    }

    /// Returns `true` when a key is currently loaded.
    pub fn is_loaded(&self) -> bool {
        self.inner.read().is_some()
    }
}
