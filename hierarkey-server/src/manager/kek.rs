// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::keys::{EncryptedKek, KekId};
use crate::global::short_id::ShortId;
use crate::manager::masterkey::MasterkeyId;
use crate::manager::namespace::NamespaceId;
use crate::manager::secret::encrypted_data::EncryptedData;
use crate::one_line_sql;
use hierarkey_core::error::crypto::CryptoError;
use hierarkey_core::{CkError, CkResult};
#[cfg(test)]
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
// --------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KekEncAlgo {
    Aes256Gcm,
}

impl KekEncAlgo {
    pub fn as_str(&self) -> &'static str {
        match self {
            KekEncAlgo::Aes256Gcm => "AES-GCM-256",
        }
    }
}

impl TryFrom<String> for KekEncAlgo {
    type Error = CkError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "AES-GCM-256" => Ok(KekEncAlgo::Aes256Gcm),
            _ => Err(CryptoError::UnsupportedAlgorithm { algorithm: s }.into()),
        }
    }
}

// --------------------------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait KekStore: Send + Sync {
    // Store new revision of KEK
    async fn store(&self, enc_kek: &EncryptedKek) -> CkResult<()>;
    // Find active revision of KEK
    async fn find(&self, kek_id: KekId) -> CkResult<Option<EncryptedKek>>;
    // List all KEKs (only active revisions)
    async fn list(&self) -> CkResult<Vec<EncryptedKek>>;
    // List all KEKs wrapped by a specific master key, with their associated namespace IDs
    async fn list_by_masterkey_with_namespace(&self, mk_id: MasterkeyId) -> CkResult<Vec<(EncryptedKek, NamespaceId)>>;
    // Find a KEK by its short ID (e.g. "kek_abc123")
    async fn find_by_short_id(&self, short_id: &str) -> CkResult<Option<EncryptedKek>>;
    // Count KEKs grouped by master key ID (excludes deleted KEKs)
    async fn count_all_by_masterkey(&self) -> CkResult<HashMap<MasterkeyId, usize>>;
    // Rewrap a KEK: replace its ciphertext and update its masterkey reference
    async fn rewrap_kek(
        &self,
        kek_id: KekId,
        new_ciphertext: EncryptedData,
        new_masterkey_id: MasterkeyId,
    ) -> CkResult<()>;
}

pub struct SqlKekStore {
    pool: PgPool,
}

impl SqlKekStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl KekStore for SqlKekStore {
    async fn store(&self, enc_kek: &EncryptedKek) -> CkResult<()> {
        enc_kek.validate()?;

        let mut tx = self.pool.begin().await?;

        sqlx::query(&one_line_sql(
            r#"
            INSERT INTO keks (
                id, algorithm, ciphertext, masterkey_id, rotation_count, last_rotated_at, rotate_by, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8
            )
            "#,
        ))
        .bind(enc_kek.id)
        .bind(enc_kek.algo.as_str())
        .bind(enc_kek.ciphertext.as_bytes())
        .bind(enc_kek.masterkey_id)
        .bind(enc_kek.rotation_count as i32)
        .bind(enc_kek.last_rotated_at)
        .bind(enc_kek.rotate_by)
        .bind(enc_kek.created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    async fn find(&self, kek_id: KekId) -> CkResult<Option<EncryptedKek>> {
        sqlx::query_as::<_, EncryptedKek>(
            &one_line_sql(r#"
            SELECT
                id, short_id, algorithm, ciphertext, masterkey_id, rotation_count, last_rotated_at, rotate_by, created_at, deleted_at
            FROM keks
            WHERE id = $1
            LIMIT 1
            "#),
        )
        .bind(kek_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(CkError::from)
    }

    async fn find_by_short_id(&self, short_id: &str) -> CkResult<Option<EncryptedKek>> {
        sqlx::query_as::<_, EncryptedKek>(&one_line_sql(
            r#"
            SELECT
                id, short_id, algorithm, ciphertext, masterkey_id, rotation_count, last_rotated_at, rotate_by, created_at, deleted_at
            FROM keks
            WHERE short_id = $1
            LIMIT 1
            "#,
        ))
        .bind(short_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(CkError::from)
    }

    async fn count_all_by_masterkey(&self) -> CkResult<HashMap<MasterkeyId, usize>> {
        let rows: Vec<(MasterkeyId, i64)> = sqlx::query_as(&one_line_sql(
            r#"
            SELECT masterkey_id, COUNT(*) AS count
            FROM keks
            WHERE deleted_at IS NULL
            GROUP BY masterkey_id
            "#,
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(CkError::from)?;

        Ok(rows.into_iter().map(|(id, count)| (id, count as usize)).collect())
    }

    async fn list(&self) -> CkResult<Vec<EncryptedKek>> {
        sqlx::query_as::<_, EncryptedKek>(&one_line_sql(
            r#"
            SELECT
                id, short_id, algorithm, ciphertext, masterkey_id, rotation_count, last_rotated_at, rotate_by, created_at
            FROM keks
            "#,
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(CkError::from)
    }

    async fn list_by_masterkey_with_namespace(&self, mk_id: MasterkeyId) -> CkResult<Vec<(EncryptedKek, NamespaceId)>> {
        let rows = sqlx::query(&one_line_sql(
            r#"
            SELECT k.id, k.short_id, k.algorithm, k.ciphertext, k.masterkey_id,
                   k.rotation_count, k.last_rotated_at, k.rotate_by, k.created_at,
                   nka.namespace_id
            FROM keks k
            JOIN namespace_kek_assignments nka ON nka.kek_id = k.id AND nka.is_active = TRUE
            WHERE k.masterkey_id = $1
              AND k.deleted_at IS NULL
            "#,
        ))
        .bind(mk_id)
        .fetch_all(&self.pool)
        .await
        .map_err(CkError::from)?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            use sqlx::Row;
            let enc_kek = EncryptedKek {
                id: row.try_get("id")?,
                short_id: row.try_get("short_id")?,
                algo: {
                    let s: String = row.try_get("algorithm")?;
                    KekEncAlgo::try_from(s)?
                },
                ciphertext: {
                    let bytes: Vec<u8> = row.try_get("ciphertext")?;
                    EncryptedData::try_from(bytes)?
                },
                masterkey_id: row.try_get("masterkey_id")?,
                rotation_count: {
                    let n: i32 = row.try_get("rotation_count")?;
                    n as usize
                },
                last_rotated_at: row.try_get("last_rotated_at")?,
                rotate_by: row.try_get("rotate_by")?,
                created_at: row.try_get("created_at")?,
            };
            let namespace_id: NamespaceId = row.try_get("namespace_id")?;
            result.push((enc_kek, namespace_id));
        }
        Ok(result)
    }

    async fn rewrap_kek(
        &self,
        kek_id: KekId,
        new_ciphertext: EncryptedData,
        new_masterkey_id: MasterkeyId,
    ) -> CkResult<()> {
        sqlx::query(&one_line_sql(
            r#"
            UPDATE keks
            SET ciphertext = $1,
                masterkey_id = $2,
                last_rotated_at = NOW(),
                rotation_count = rotation_count + 1
            WHERE id = $3
              AND deleted_at IS NULL
            "#,
        ))
        .bind(new_ciphertext.as_bytes())
        .bind(new_masterkey_id)
        .bind(kek_id)
        .execute(&self.pool)
        .await
        .map_err(CkError::from)?;
        Ok(())
    }
}

// --------------------------------------------------------------------------------------------
#[cfg(test)]
pub struct InMemoryKekStore {
    store: Mutex<HashMap<KekId, EncryptedKek>>,
}

#[cfg(test)]
impl Default for InMemoryKekStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl InMemoryKekStore {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl KekStore for InMemoryKekStore {
    async fn store(&self, enc_kek: &EncryptedKek) -> CkResult<()> {
        enc_kek.validate()?;

        let mut store = self.store.lock();
        store.insert(enc_kek.id, enc_kek.clone());
        Ok(())
    }

    async fn find(&self, kek_id: KekId) -> CkResult<Option<EncryptedKek>> {
        let store = self.store.lock();
        let kek = store.get(&kek_id).cloned();

        Ok(kek)
    }

    async fn find_by_short_id(&self, short_id: &str) -> CkResult<Option<EncryptedKek>> {
        let store = self.store.lock();
        let kek = store.values().find(|k| k.short_id.to_string() == short_id).cloned();
        Ok(kek)
    }

    async fn count_all_by_masterkey(&self) -> CkResult<HashMap<MasterkeyId, usize>> {
        let store = self.store.lock();
        let mut counts: HashMap<MasterkeyId, usize> = HashMap::new();
        for kek in store.values() {
            *counts.entry(kek.masterkey_id).or_insert(0) += 1;
        }
        Ok(counts)
    }

    async fn list(&self) -> CkResult<Vec<EncryptedKek>> {
        let store = self.store.lock();

        let result = store.values().cloned().collect::<Vec<EncryptedKek>>();
        Ok(result)
    }

    async fn list_by_masterkey_with_namespace(&self, mk_id: MasterkeyId) -> CkResult<Vec<(EncryptedKek, NamespaceId)>> {
        // In-memory store has no namespace tracking — returns entries with nil namespace IDs.
        // Sufficient for unit tests that do not exercise rewrap paths.
        let store = self.store.lock();
        let result = store
            .values()
            .filter(|k| k.masterkey_id == mk_id)
            .map(|k| (k.clone(), NamespaceId(uuid::Uuid::nil())))
            .collect();
        Ok(result)
    }

    async fn rewrap_kek(
        &self,
        kek_id: KekId,
        new_ciphertext: EncryptedData,
        new_masterkey_id: MasterkeyId,
    ) -> CkResult<()> {
        let mut store = self.store.lock();
        let kek = store.get_mut(&kek_id).ok_or(CkError::ResourceNotFound {
            kind: "kek",
            id: kek_id.to_string(),
        })?;
        kek.ciphertext = new_ciphertext;
        kek.masterkey_id = new_masterkey_id;
        kek.mark_rotated();
        Ok(())
    }
}

// --------------------------------------------------------------------------------------------

pub struct KekManager {
    store: Arc<dyn KekStore>,
}

impl std::fmt::Debug for KekManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KekManager").finish()
    }
}

impl KekManager {
    /// Create a new KEK manager
    pub fn new(store: Arc<dyn KekStore>) -> Self {
        Self { store }
    }

    /// Fetch a KEK by its ID
    pub async fn fetch(&self, kek_id: KekId) -> CkResult<Option<EncryptedKek>> {
        let res = self.store.find(kek_id).await?;
        Ok(res)
    }

    /// Fetch a KEK by its short ID (e.g. "kek_abc123")
    pub async fn find_by_short_id(&self, short_id: &str) -> CkResult<Option<EncryptedKek>> {
        self.store.find_by_short_id(short_id).await
    }

    /// Count KEKs grouped by master key ID (single query, excludes deleted KEKs).
    pub async fn count_all_by_masterkey(&self) -> CkResult<HashMap<MasterkeyId, usize>> {
        self.store.count_all_by_masterkey().await
    }

    /// List all KEKs wrapped by `mk_id`, with their namespace IDs for AAD reconstruction.
    pub async fn list_by_masterkey_with_namespace(
        &self,
        mk_id: MasterkeyId,
    ) -> CkResult<Vec<(EncryptedKek, NamespaceId)>> {
        self.store.list_by_masterkey_with_namespace(mk_id).await
    }

    /// Replace the ciphertext and master-key reference of an existing KEK (rewrap).
    pub async fn rewrap_kek(
        &self,
        kek_id: KekId,
        new_ciphertext: EncryptedData,
        new_masterkey_id: MasterkeyId,
    ) -> CkResult<()> {
        self.store.rewrap_kek(kek_id, new_ciphertext, new_masterkey_id).await
    }

    pub async fn create(
        &self,
        _ctx: &CallContext,
        data: &EncryptedData,
        algo: KekEncAlgo,
        masterkey_id: MasterkeyId,
    ) -> CkResult<EncryptedKek> {
        let enc_kek = EncryptedKek {
            id: KekId::new(),
            short_id: ShortId::generate("kek_", 12),
            algo,
            ciphertext: data.clone(),
            masterkey_id,
            created_at: chrono::Utc::now(),
            last_rotated_at: None,
            rotate_by: None,
            rotation_count: 0,
        };

        self.store.store(&enc_kek).await?;
        Ok(enc_kek)
    }
}
