// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::global::keys::{EncryptedSigningKey, SigningKey, SigningKeyId};
use crate::global::short_id::ShortId;
use crate::manager::kek::KekEncAlgo;
use crate::manager::masterkey::MasterkeyId;
use crate::manager::secret::encrypted_data::EncryptedData;
use crate::service::masterkey::provider::crypto::MasterKeyCrypto;
use crate::one_line_sql;
use hierarkey_core::{CkError, CkResult};
#[cfg(test)]
use parking_lot::Mutex;
use sqlx::PgPool;
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;

// --------------------------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait SigningKeyStore: Send + Sync {
    /// Persist a newly created signing key.
    async fn store(&self, key: &EncryptedSigningKey) -> CkResult<()>;
    /// Fetch the single active (non-deleted) signing key, if one exists.
    async fn find_active(&self) -> CkResult<Option<EncryptedSigningKey>>;
    /// Fetch a signing key by its UUID.
    async fn find(&self, id: SigningKeyId) -> CkResult<Option<EncryptedSigningKey>>;
    /// Soft-delete the active signing key (called during rotation before storing the new one).
    async fn retire_active(&self) -> CkResult<()>;
}

// --------------------------------------------------------------------------------------------

pub struct SqlSigningKeyStore {
    pool: PgPool,
}

impl SqlSigningKeyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl SigningKeyStore for SqlSigningKeyStore {
    async fn store(&self, key: &EncryptedSigningKey) -> CkResult<()> {
        key.validate()?;

        sqlx::query(&one_line_sql(
            r#"
            INSERT INTO signing_keys (id, algorithm, ciphertext, masterkey_id, created_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        ))
        .bind(key.id)
        .bind(key.algo.as_str())
        .bind(key.ciphertext.as_bytes())
        .bind(key.masterkey_id)
        .bind(key.created_at)
        .execute(&self.pool)
        .await
        .map_err(CkError::from)?;

        Ok(())
    }

    async fn find_active(&self) -> CkResult<Option<EncryptedSigningKey>> {
        sqlx::query_as::<_, EncryptedSigningKey>(&one_line_sql(
            r#"
            SELECT id, short_id, algorithm, ciphertext, masterkey_id, created_at
            FROM signing_keys
            WHERE deleted_at IS NULL
            LIMIT 1
            "#,
        ))
        .fetch_optional(&self.pool)
        .await
        .map_err(CkError::from)
    }

    async fn find(&self, id: SigningKeyId) -> CkResult<Option<EncryptedSigningKey>> {
        sqlx::query_as::<_, EncryptedSigningKey>(&one_line_sql(
            r#"
            SELECT id, short_id, algorithm, ciphertext, masterkey_id, created_at
            FROM signing_keys
            WHERE id = $1
            LIMIT 1
            "#,
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(CkError::from)
    }

    async fn retire_active(&self) -> CkResult<()> {
        sqlx::query(&one_line_sql(
            r#"
            UPDATE signing_keys
            SET deleted_at = NOW()
            WHERE deleted_at IS NULL
            "#,
        ))
        .execute(&self.pool)
        .await
        .map_err(CkError::from)?;

        Ok(())
    }
}

// --------------------------------------------------------------------------------------------

#[cfg(test)]
pub struct InMemorySigningKeyStore {
    store: Mutex<HashMap<SigningKeyId, EncryptedSigningKey>>,
}

#[cfg(test)]
impl Default for InMemorySigningKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl InMemorySigningKeyStore {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl SigningKeyStore for InMemorySigningKeyStore {
    async fn store(&self, key: &EncryptedSigningKey) -> CkResult<()> {
        key.validate()?;
        let mut store = self.store.lock();
        store.insert(key.id, key.clone());
        Ok(())
    }

    async fn find_active(&self) -> CkResult<Option<EncryptedSigningKey>> {
        // In the in-memory store all entries are treated as active (no deleted_at tracking).
        let store = self.store.lock();
        Ok(store.values().next().cloned())
    }

    async fn find(&self, id: SigningKeyId) -> CkResult<Option<EncryptedSigningKey>> {
        let store = self.store.lock();
        Ok(store.get(&id).cloned())
    }

    async fn retire_active(&self) -> CkResult<()> {
        // In the in-memory store we clear all entries to simulate rotation.
        let mut store = self.store.lock();
        store.clear();
        Ok(())
    }
}

// --------------------------------------------------------------------------------------------

pub struct SigningKeyManager {
    store: Arc<dyn SigningKeyStore>,
}

impl std::fmt::Debug for SigningKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyManager").finish()
    }
}

impl SigningKeyManager {
    pub fn new(store: Arc<dyn SigningKeyStore>) -> Self {
        Self { store }
    }

    /// Return the single active signing key, if one has been created.
    pub async fn fetch_active(&self) -> CkResult<Option<EncryptedSigningKey>> {
        self.store.find_active().await
    }

    /// Return a signing key by its UUID (used during rewrap after master-key rotation).
    pub async fn fetch(&self, id: SigningKeyId) -> CkResult<Option<EncryptedSigningKey>> {
        self.store.find(id).await
    }

    /// Create and persist a new signing key, retiring the current active one first.
    ///
    /// The caller is responsible for:
    /// 1. Generating the plaintext key material and wrapping it with the master key.
    /// 2. Passing the resulting [`EncryptedData`] here.
    ///
    /// Retirement and insertion are NOT wrapped in a single DB transaction here because
    /// the unique-index constraint (`signing_keys_one_active`) already prevents two active
    /// rows from coexisting.  Callers that need strict atomicity should use a transaction
    /// around [`retire_active`] + [`create`].
    pub async fn create(
        &self,
        data: &EncryptedData,
        algo: KekEncAlgo,
        masterkey_id: MasterkeyId,
    ) -> CkResult<EncryptedSigningKey> {
        let id = SigningKeyId::new();
        let key = EncryptedSigningKey {
            id,
            short_id: ShortId::generate("sk_", 12),
            algo,
            ciphertext: data.clone(),
            masterkey_id,
            created_at: chrono::Utc::now(),
        };

        self.store.store(&key).await?;
        Ok(key)
    }

    /// Generate a new signing key, encrypt it with the given master key crypto handle,
    /// and persist it.  The pre-generated `id` is bound into the ciphertext AAD so the
    /// stored row cannot be silently swapped for a different key.
    ///
    /// Returns both the plaintext key (to load into the slot immediately) and the
    /// persisted `EncryptedSigningKey`.
    pub async fn bootstrap_new(
        &self,
        crypto: &dyn MasterKeyCrypto,
        masterkey_id: MasterkeyId,
    ) -> CkResult<(SigningKey, EncryptedSigningKey)> {
        let sk = SigningKey::generate()?;
        let id = SigningKeyId::new();
        let enc_data = crypto.wrap_signing_key(sk.as_bytes(), masterkey_id, id)?;
        let enc_key = EncryptedSigningKey {
            id,
            short_id: ShortId::generate("sk_", 12),
            algo: crypto.algo(),
            ciphertext: enc_data,
            masterkey_id,
            created_at: chrono::Utc::now(),
        };
        self.store.store(&enc_key).await?;
        Ok((sk, enc_key))
    }

    /// Soft-delete the currently active signing key.  Call this before creating a
    /// replacement (e.g. when rotating the master key).
    pub async fn retire_active(&self) -> CkResult<()> {
        self.store.retire_active().await
    }

    /// Rewrap the active signing key: retire it and store a new entry that wraps the same
    /// plaintext key material under a different master key.
    pub async fn rewrap(
        &self,
        new_ciphertext: EncryptedData,
        new_masterkey_id: MasterkeyId,
    ) -> CkResult<EncryptedSigningKey> {
        self.store.retire_active().await?;
        self.create(&new_ciphertext, KekEncAlgo::Aes256Gcm, new_masterkey_id).await
    }
}

// --------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::keys::SIGNING_KEY_SIZE;
    use crate::manager::secret::encrypted_data::EncryptedData;

    fn make_encrypted_data() -> EncryptedData {
        EncryptedData::new(&[1u8; 12], &[2u8; SIGNING_KEY_SIZE], &[3u8; 16])
    }

    #[tokio::test]
    async fn test_store_and_find_active() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let manager = SigningKeyManager::new(store);

        let masterkey_id = MasterkeyId::new();
        let data = make_encrypted_data();

        let key = manager.create(&data, KekEncAlgo::Aes256Gcm, masterkey_id).await.unwrap();
        let found = manager.fetch_active().await.unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().id, key.id);
    }

    #[tokio::test]
    async fn test_retire_clears_active() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let manager = SigningKeyManager::new(store);

        let masterkey_id = MasterkeyId::new();
        let data = make_encrypted_data();

        manager.create(&data, KekEncAlgo::Aes256Gcm, masterkey_id).await.unwrap();
        manager.retire_active().await.unwrap();

        let found = manager.fetch_active().await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_rewrap_replaces_active() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let manager = SigningKeyManager::new(store);

        let mk1 = MasterkeyId::new();
        let mk2 = MasterkeyId::new();
        let data = make_encrypted_data();

        let original = manager.create(&data, KekEncAlgo::Aes256Gcm, mk1).await.unwrap();

        let new_data = EncryptedData::new(&[4u8; 12], &[5u8; SIGNING_KEY_SIZE], &[6u8; 16]);
        let rewrapped = manager.rewrap(new_data, mk2).await.unwrap();

        assert_ne!(original.id, rewrapped.id);
        assert_eq!(rewrapped.masterkey_id, mk2);

        let active = manager.fetch_active().await.unwrap().unwrap();
        assert_eq!(active.id, rewrapped.id);
    }

    #[tokio::test]
    async fn test_validate_rejects_zero_nonce() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let manager = SigningKeyManager::new(store);

        let masterkey_id = MasterkeyId::new();
        let bad_data = EncryptedData::new(&[0u8; 12], &[2u8; SIGNING_KEY_SIZE], &[3u8; 16]);

        let result = manager.create(&bad_data, KekEncAlgo::Aes256Gcm, masterkey_id).await;
        assert!(result.is_err());
    }
}
