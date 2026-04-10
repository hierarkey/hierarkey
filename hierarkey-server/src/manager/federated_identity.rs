// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::manager::account::AccountId;
use chrono::{DateTime, Utc};
use hierarkey_core::{CkError, CkResult};
use sqlx::{PgPool, Row};
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
// Manager
// ---------------------------------------------------------------------------

pub struct FederatedIdentityManager {
    pool: PgPool,
}

impl FederatedIdentityManager {
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

    /// Look up the identity row that matches a specific (provider, issuer, subject) triple.
    /// Returns `None` if no account has been linked to this external identity.
    pub async fn find_by_provider_and_subject(
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

    /// Look up the federated identity linked to a given service account, if any.
    pub async fn find_by_account(&self, account_id: AccountId) -> CkResult<Option<FederatedIdentityRow>> {
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

    /// Link an external identity to a service account.
    ///
    /// Returns an error if the account already has a linked identity (unique constraint
    /// on `account_id`) or if the same external identity is already linked to a
    /// different account (unique constraint on `(provider_id, external_issuer, external_subject)`).
    pub async fn link(
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

    /// Remove the federated identity link for an account.
    /// Returns `true` if a row was deleted, `false` if none existed.
    pub async fn unlink(&self, account_id: AccountId) -> CkResult<bool> {
        let result = sqlx::query("DELETE FROM federated_identities WHERE account_id = $1")
            .bind(account_id.0)
            .execute(&self.pool)
            .await
            .map_err(CkError::from)?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_creates_manager() {
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let manager = FederatedIdentityManager::new(pool);
        // Verify the manager was constructed without panicking.
        drop(manager);
    }

    // The remaining operations (link, find_by_account, find_by_provider_and_subject, unlink)
    // require a live PostgreSQL database with migrations applied and are covered by the
    // integration test suite. Mark them as ignored so they can be run selectively with
    // `cargo test -- --ignored` when a test database is available.

    #[tokio::test]
    #[ignore = "requires live PostgreSQL with migrations"]
    async fn link_and_find_round_trip() {
        let pool = sqlx::PgPool::connect("postgres://localhost/hierarkey_test")
            .await
            .unwrap();
        let manager = FederatedIdentityManager::new(pool);

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

        // find_by_account
        let found = manager.find_by_account(account_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().external_subject, "subject-abc");

        // find_by_provider_and_subject
        let found = manager
            .find_by_provider_and_subject("oidc", "https://issuer.example.com", "subject-abc")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().account_id, account_id);

        // unlink
        let deleted = manager.unlink(account_id).await.unwrap();
        assert!(deleted);

        // verify gone
        let gone = manager.find_by_account(account_id).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    #[ignore = "requires live PostgreSQL with migrations"]
    async fn unlink_nonexistent_returns_false() {
        let pool = sqlx::PgPool::connect("postgres://localhost/hierarkey_test")
            .await
            .unwrap();
        let manager = FederatedIdentityManager::new(pool);
        let result = manager.unlink(AccountId::new()).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    #[ignore = "requires live PostgreSQL with migrations"]
    async fn find_by_account_returns_none_when_not_linked() {
        let pool = sqlx::PgPool::connect("postgres://localhost/hierarkey_test")
            .await
            .unwrap();
        let manager = FederatedIdentityManager::new(pool);
        let result = manager.find_by_account(AccountId::new()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    #[ignore = "requires live PostgreSQL with migrations"]
    async fn duplicate_link_returns_resource_exists_error() {
        let pool = sqlx::PgPool::connect("postgres://localhost/hierarkey_test")
            .await
            .unwrap();
        let manager = FederatedIdentityManager::new(pool);
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
