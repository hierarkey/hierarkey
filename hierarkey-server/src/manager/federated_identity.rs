// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::manager::account::AccountId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hierarkey_core::{CkError, CkResult};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FederatedIdentityRow {
    pub id: Uuid,
    pub account_id: AccountId,
    pub provider_id: String,
    pub external_issuer: String,
    pub external_subject: String,
    pub created_at: DateTime<Utc>,
    pub created_by: AccountId,
}

// ---------------------------------------------------------------------------
// Store trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait FederatedIdentityStore: Send + Sync + 'static {
    async fn link(
        &self,
        account_id: AccountId,
        provider_id: &str,
        external_issuer: &str,
        external_subject: &str,
        created_by: AccountId,
    ) -> CkResult<FederatedIdentityRow>;

    async fn find_by_account(&self, account_id: AccountId) -> CkResult<Option<FederatedIdentityRow>>;

    async fn find_by_provider_and_subject(
        &self,
        provider_id: &str,
        external_issuer: &str,
        external_subject: &str,
    ) -> CkResult<Option<FederatedIdentityRow>>;

    async fn unlink(&self, account_id: AccountId) -> CkResult<bool>;
}

// ---------------------------------------------------------------------------
// Postgres implementation
// ---------------------------------------------------------------------------

pub struct PgFederatedIdentityStore {
    pool: PgPool,
}

impl PgFederatedIdentityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn map_row(row: &sqlx::postgres::PgRow) -> Result<FederatedIdentityRow, sqlx::Error> {
        Ok(FederatedIdentityRow {
            id: row.try_get("id")?,
            account_id: AccountId(row.try_get("account_id")?),
            provider_id: row.try_get("provider_id")?,
            external_issuer: row.try_get("external_issuer")?,
            external_subject: row.try_get("external_subject")?,
            created_at: row.try_get("created_at")?,
            created_by: AccountId(row.try_get("created_by")?),
        })
    }
}

#[async_trait]
impl FederatedIdentityStore for PgFederatedIdentityStore {
    async fn find_by_provider_and_subject(
        &self,
        provider_id: &str,
        external_issuer: &str,
        external_subject: &str,
    ) -> CkResult<Option<FederatedIdentityRow>> {
        let row = sqlx::query(
            "SELECT id, account_id, provider_id, external_issuer, external_subject, created_at, created_by \
             FROM federated_identities \
             WHERE provider_id = $1 AND external_issuer = $2 AND external_subject = $3",
        )
        .bind(provider_id)
        .bind(external_issuer)
        .bind(external_subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(CkError::from)?;

        row.as_ref().map(Self::map_row).transpose().map_err(CkError::from)
    }

    async fn find_by_account(&self, account_id: AccountId) -> CkResult<Option<FederatedIdentityRow>> {
        let row = sqlx::query(
            "SELECT id, account_id, provider_id, external_issuer, external_subject, created_at, created_by \
             FROM federated_identities \
             WHERE account_id = $1",
        )
        .bind(account_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(CkError::from)?;

        row.as_ref().map(Self::map_row).transpose().map_err(CkError::from)
    }

    async fn link(
        &self,
        account_id: AccountId,
        provider_id: &str,
        external_issuer: &str,
        external_subject: &str,
        created_by: AccountId,
    ) -> CkResult<FederatedIdentityRow> {
        let row = sqlx::query(
            "INSERT INTO federated_identities \
                 (account_id, provider_id, external_issuer, external_subject, created_by) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, account_id, provider_id, external_issuer, external_subject, created_at, created_by",
        )
        .bind(account_id.0)
        .bind(provider_id)
        .bind(external_issuer)
        .bind(external_subject)
        .bind(created_by.0)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e
                && db_err.is_unique_violation()
            {
                return CkError::ResourceExists {
                    kind: "federated_identity",
                    id: format!("{provider_id}/{external_issuer}/{external_subject}"),
                };
            }
            CkError::from(e)
        })?;

        Self::map_row(&row).map_err(CkError::from)
    }

    async fn unlink(&self, account_id: AccountId) -> CkResult<bool> {
        let result = sqlx::query("DELETE FROM federated_identities WHERE account_id = $1")
            .bind(account_id.0)
            .execute(&self.pool)
            .await
            .map_err(CkError::from)?;

        Ok(result.rows_affected() > 0)
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation (for tests)
// ---------------------------------------------------------------------------

#[cfg(any(test, test))]
pub mod memory_store {
    use super::*;
    use parking_lot::Mutex;

    pub struct InMemoryFederatedIdentityStore {
        rows: Mutex<Vec<FederatedIdentityRow>>,
    }

    impl InMemoryFederatedIdentityStore {
        pub fn new() -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
            }
        }
    }

    impl Default for InMemoryFederatedIdentityStore {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl FederatedIdentityStore for InMemoryFederatedIdentityStore {
        async fn link(
            &self,
            account_id: AccountId,
            provider_id: &str,
            external_issuer: &str,
            external_subject: &str,
            created_by: AccountId,
        ) -> CkResult<FederatedIdentityRow> {
            let mut rows = self.rows.lock();

            // Enforce both unique constraints the DB would.
            let account_conflict = rows.iter().any(|r| r.account_id == account_id);
            let identity_conflict = rows.iter().any(|r| {
                r.provider_id == provider_id
                    && r.external_issuer == external_issuer
                    && r.external_subject == external_subject
            });

            if account_conflict || identity_conflict {
                return Err(CkError::ResourceExists {
                    kind: "federated_identity",
                    id: format!("{provider_id}/{external_issuer}/{external_subject}"),
                });
            }

            let row = FederatedIdentityRow {
                id: Uuid::new_v4(),
                account_id,
                provider_id: provider_id.to_string(),
                external_issuer: external_issuer.to_string(),
                external_subject: external_subject.to_string(),
                created_at: Utc::now(),
                created_by,
            };
            rows.push(row.clone());
            Ok(row)
        }

        async fn find_by_account(&self, account_id: AccountId) -> CkResult<Option<FederatedIdentityRow>> {
            Ok(self.rows.lock().iter().find(|r| r.account_id == account_id).cloned())
        }

        async fn find_by_provider_and_subject(
            &self,
            provider_id: &str,
            external_issuer: &str,
            external_subject: &str,
        ) -> CkResult<Option<FederatedIdentityRow>> {
            Ok(self
                .rows
                .lock()
                .iter()
                .find(|r| {
                    r.provider_id == provider_id
                        && r.external_issuer == external_issuer
                        && r.external_subject == external_subject
                })
                .cloned())
        }

        async fn unlink(&self, account_id: AccountId) -> CkResult<bool> {
            let mut rows = self.rows.lock();
            let before = rows.len();
            rows.retain(|r| r.account_id != account_id);
            Ok(rows.len() < before)
        }
    }
}

// ---------------------------------------------------------------------------
// Manager (delegates to a store)
// ---------------------------------------------------------------------------

pub struct FederatedIdentityManager {
    store: Arc<dyn FederatedIdentityStore>,
}

impl FederatedIdentityManager {
    pub fn new(pool: PgPool) -> Self {
        Self {
            store: Arc::new(PgFederatedIdentityStore::new(pool)),
        }
    }

    #[cfg(any(test, test))]
    pub fn in_memory() -> Self {
        Self {
            store: Arc::new(memory_store::InMemoryFederatedIdentityStore::new()),
        }
    }

    pub async fn find_by_provider_and_subject(
        &self,
        provider_id: &str,
        external_issuer: &str,
        external_subject: &str,
    ) -> CkResult<Option<FederatedIdentityRow>> {
        self.store
            .find_by_provider_and_subject(provider_id, external_issuer, external_subject)
            .await
    }

    pub async fn find_by_account(&self, account_id: AccountId) -> CkResult<Option<FederatedIdentityRow>> {
        self.store.find_by_account(account_id).await
    }

    pub async fn link(
        &self,
        account_id: AccountId,
        provider_id: &str,
        external_issuer: &str,
        external_subject: &str,
        created_by: AccountId,
    ) -> CkResult<FederatedIdentityRow> {
        self.store
            .link(account_id, provider_id, external_issuer, external_subject, created_by)
            .await
    }

    pub async fn unlink(&self, account_id: AccountId) -> CkResult<bool> {
        self.store.unlink(account_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory_store::InMemoryFederatedIdentityStore;

    fn make_manager() -> FederatedIdentityManager {
        FederatedIdentityManager {
            store: Arc::new(InMemoryFederatedIdentityStore::new()),
        }
    }

    #[tokio::test]
    async fn link_and_find_round_trip() {
        let manager = make_manager();
        let account_id = AccountId::new();
        let actor_id = AccountId::new();

        let row = manager
            .link(account_id, "oidc", "https://issuer.example.com", "subject-abc", actor_id)
            .await
            .unwrap();

        assert_eq!(row.account_id, account_id);
        assert_eq!(row.provider_id, "oidc");
        assert_eq!(row.external_issuer, "https://issuer.example.com");
        assert_eq!(row.external_subject, "subject-abc");

        let found = manager.find_by_account(account_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().external_subject, "subject-abc");

        let found = manager
            .find_by_provider_and_subject("oidc", "https://issuer.example.com", "subject-abc")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().account_id, account_id);

        let deleted = manager.unlink(account_id).await.unwrap();
        assert!(deleted);

        let gone = manager.find_by_account(account_id).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn unlink_nonexistent_returns_false() {
        let manager = make_manager();
        let result = manager.unlink(AccountId::new()).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn find_by_account_returns_none_when_not_linked() {
        let manager = make_manager();
        let result = manager.find_by_account(AccountId::new()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn duplicate_link_returns_resource_exists_error() {
        let manager = make_manager();
        let account_id = AccountId::new();
        let actor_id = AccountId::new();

        manager
            .link(account_id, "oidc", "https://issuer.example.com", "dup-subject", actor_id)
            .await
            .unwrap();

        let err = manager
            .link(account_id, "oidc", "https://issuer.example.com", "dup-subject", actor_id)
            .await
            .unwrap_err();

        assert!(matches!(err, CkError::ResourceExists { .. }));
    }
}
