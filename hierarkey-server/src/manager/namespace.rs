// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::global::keys::KekId;
use crate::global::resource::ResourceStatus;
use crate::global::short_id::ShortId;
use crate::global::utils::sql::escape_ilike;
use crate::global::{DEFAULT_LIMIT_VALUE, DEFAULT_OFFSET_VALUE, MAX_LIMIT_VALUE};
use crate::manager::masterkey::MasterkeyId;
use crate::service::namespace::NamespaceSearchQuery;
use crate::{ResolveOne, one_line_sql, uuid_id};
use hierarkey_core::resources::NamespaceString;
use hierarkey_core::{CkError, Metadata};
use hierarkey_core::{CkResult, resources::Revision};
#[cfg(test)]
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, trace};
use uuid::Uuid;

use crate::global::uuid_id::Identifier;

uuid_id!(NamespaceId, "ns_");

// ------------------------------------------------------------------------------------

#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    /// Unique ID
    pub id: NamespaceId,
    /// Short human-friendly ID
    pub short_id: ShortId,
    /// Namespace lifecycle status: active / disabled / deleted
    pub status: ResourceStatus,
    /// Namespace path
    pub namespace: NamespaceString,
    /// Metadata associated with this namespace
    pub metadata: Metadata,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Account UUID of the creator
    pub created_by: Option<uuid::Uuid>,
    /// Updated timestamp
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Account UUID of the last modifier
    pub updated_by: Option<uuid::Uuid>,
    /// When the namespace was soft/hard deleted (if at all)
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KekAssignment {
    /// Namespace ID
    pub namespace_id: NamespaceId,
    /// Assignment revision
    pub revision: Revision,
    /// Whether this assignment is active
    pub is_active: bool,
    /// KEK ID
    pub kek_id: KekId,
    /// Short human-friendly ID for the KEK
    pub kek_short_id: ShortId,
    /// Metadata associated with this assignment (
    pub metadata: Metadata,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Masterkey ID (from KEK)
    pub masterkey_id: MasterkeyId,
    /// Short human-friendly ID for the masterkey
    pub masterkey_short_id: ShortId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceKekState {
    pub namespace: Namespace,
    pub latest_kek_revision: Revision,
    pub active_kek_revision: Option<Revision>,
    pub total_secrets: usize,
}

// ------------------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait NamespaceStore: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn create_namespace(
        &self,
        namespace_id: Option<NamespaceId>,
        ns_path: &NamespaceString,
        metadata: Metadata,
        status: ResourceStatus,
        kek_id: KekId,
        masterkey_id: MasterkeyId,
        created_by: Option<uuid::Uuid>,
    ) -> CkResult<Namespace>;
    async fn update_namespace(
        &self,
        namespace_id: NamespaceId,
        metadata: Metadata,
        updated_by: Option<uuid::Uuid>,
    ) -> CkResult<Namespace>;

    // Returns the namespace that is NOT deleted (i.e., active or disabled)
    async fn fetch_namespace(&self, ns_path: &NamespaceString) -> CkResult<Option<Namespace>>;
    async fn fetch_namespace_by_id(&self, namespace_id: NamespaceId) -> CkResult<Option<Namespace>>;

    async fn rotate_kek(
        &self,
        namespace_id: NamespaceId,
        new_kek_id: KekId,
        new_masterkey_id: MasterkeyId,
        metadata: Metadata,
    ) -> CkResult<KekAssignment>;
    async fn list_kek_assignments(&self, namespace_id: NamespaceId) -> CkResult<Vec<KekAssignment>>;

    async fn list_active(&self) -> CkResult<Vec<Namespace>>;
    async fn search(&self, q: &NamespaceSearchQuery) -> CkResult<(Vec<NamespaceKekState>, usize)>;
    /// Like `search` but returns all matching results without any pagination applied.
    /// Used internally for RBAC-filtered listing.
    async fn search_all(&self, q: &NamespaceSearchQuery) -> CkResult<Vec<NamespaceKekState>>;

    async fn disable(&self, namespace_id: NamespaceId) -> CkResult<bool>;
    async fn delete(&self, namespace_id: NamespaceId) -> CkResult<bool>;
    async fn enable(&self, namespace_id: NamespaceId) -> CkResult<bool>;

    async fn resolve_short_namespace_id(&self, prefix: &str) -> CkResult<ResolveOne<NamespaceId>>;
}

// ------------------------------------------------------------------------------------

pub struct SqlNamespaceStore {
    pool: PgPool,
}

impl SqlNamespaceStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl NamespaceStore for SqlNamespaceStore {
    async fn create_namespace(
        &self,
        namespace_id: Option<NamespaceId>,
        ns_path: &NamespaceString,
        metadata: Metadata,
        status: ResourceStatus,
        kek_id: KekId,
        _masterkey_id: MasterkeyId,
        created_by: Option<uuid::Uuid>,
    ) -> CkResult<Namespace> {
        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Insert into namespaces table
        let ns_row = sqlx::query(&one_line_sql(
            r#"
        INSERT INTO namespaces (id, namespace, status, metadata, created_at, created_by)
        VALUES ($1, $2, $3, $4::jsonb, NOW(), $5)
        RETURNING id, short_id, namespace, status, metadata, created_at, created_by, updated_at, updated_by, deleted_at
        "#,
        ))
        .bind(namespace_id.unwrap_or_default())
        .bind(ns_path.as_str())
        .bind(status.as_str())
        .bind(json!(metadata))
        .bind(created_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.is_unique_violation()
            {
                return CkError::ResourceExists {
                    kind: "namespace",
                    id: ns_path.to_string(),
                };
            }
            CkError::from(e)
        })?;

        let namespace_id: NamespaceId = ns_row.try_get("id")?;
        let short_id: ShortId = ns_row.try_get("short_id")?;

        // Insert into namespace_kek_assignments table with revision 1, is_active = true
        sqlx::query(&one_line_sql(
            r#"
        INSERT INTO namespace_kek_assignments (namespace_id, revision, is_active, kek_id, metadata)
        VALUES ($1, 1, TRUE, $2, '{}'::jsonb)
        "#,
        ))
        .bind(namespace_id)
        .bind(kek_id)
        .execute(&mut *tx)
        .await?;

        // Commit transaction
        tx.commit().await?;

        let namespace: String = ns_row.try_get("namespace")?;
        let status_str: String = ns_row.try_get("status")?;
        let metadata_json: serde_json::Value = ns_row.try_get("metadata")?;
        let created_at: chrono::DateTime<chrono::Utc> = ns_row.try_get("created_at")?;
        let created_by: Option<uuid::Uuid> = ns_row.try_get("created_by")?;
        let updated_at: Option<chrono::DateTime<chrono::Utc>> = ns_row.try_get("updated_at")?;
        let updated_by: Option<uuid::Uuid> = ns_row.try_get("updated_by")?;
        let deleted_at: Option<chrono::DateTime<chrono::Utc>> = ns_row.try_get("deleted_at")?;

        let metadata: Metadata = serde_json::from_value(metadata_json)?;

        Ok(Namespace {
            id: namespace_id,
            short_id,
            namespace: NamespaceString::try_from(namespace)?,
            status: ResourceStatus::try_from(status_str.as_str())?,
            metadata,
            created_at,
            created_by,
            updated_at,
            updated_by,
            deleted_at,
        })
    }

    async fn update_namespace(
        &self,
        namespace_id: NamespaceId,
        metadata: Metadata,
        updated_by: Option<uuid::Uuid>,
    ) -> CkResult<Namespace> {
        let sql = &one_line_sql(
            r#"
            UPDATE namespaces
            SET metadata = $2::jsonb, updated_at = NOW(), updated_by = $3
            WHERE id = $1
            RETURNING id, short_id, namespace, status, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            "#,
        );

        let query = sqlx::query(sql).bind(namespace_id).bind(metadata).bind(updated_by);

        let row = query.fetch_one(&self.pool).await?;

        let namespace_id = row.try_get("id")?;
        let short_id: ShortId = row.try_get("short_id")?;
        let namespace: String = row.try_get("namespace")?;
        let status_str: String = row.try_get("status")?;
        let metadata_json: serde_json::Value = row.try_get("metadata")?;
        let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
        let created_by: Option<uuid::Uuid> = row.try_get("created_by")?;
        let updated_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("updated_at")?;
        let updated_by: Option<uuid::Uuid> = row.try_get("updated_by")?;
        let deleted_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("deleted_at")?;

        let metadata: Metadata = serde_json::from_value(metadata_json)?;

        Ok(Namespace {
            id: namespace_id,
            short_id,
            namespace: NamespaceString::try_from(namespace)?,
            status: ResourceStatus::try_from(status_str.as_str())?,
            metadata,
            created_at,
            created_by,
            updated_at,
            updated_by,
            deleted_at,
        })
    }

    async fn fetch_namespace(&self, ns_path: &NamespaceString) -> CkResult<Option<Namespace>> {
        let row = sqlx::query(&one_line_sql(
            r#"
            SELECT id, short_id, namespace, status, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            FROM namespaces
            WHERE namespace = $1 AND (status = 'active' OR status = 'disabled')
            "#,
        ))
        .bind(ns_path.as_str())
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let namespace_id = row.try_get("id")?;
        let short_id: ShortId = row.try_get("short_id")?;
        let namespace: String = row.try_get("namespace")?;
        let status_str: String = row.try_get("status")?;
        let metadata_json: serde_json::Value = row.try_get("metadata")?;
        let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
        let created_by: Option<uuid::Uuid> = row.try_get("created_by")?;
        let updated_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("updated_at")?;
        let updated_by: Option<uuid::Uuid> = row.try_get("updated_by")?;
        let deleted_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("deleted_at")?;

        let metadata: Metadata = serde_json::from_value(metadata_json)?;

        Ok(Some(Namespace {
            id: namespace_id,
            short_id,
            namespace: NamespaceString::try_from(namespace)?,
            status: ResourceStatus::try_from(status_str.as_str())?,
            metadata,
            created_at,
            created_by,
            updated_at,
            updated_by,
            deleted_at,
        }))
    }

    async fn fetch_namespace_by_id(&self, namespace_id: NamespaceId) -> CkResult<Option<Namespace>> {
        let row = sqlx::query(&one_line_sql(
            r#"
            SELECT id, short_id, namespace, status, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            FROM namespaces
            WHERE id = $1 AND (status = 'active' OR status = 'disabled')
            "#,
        ))
        .bind(namespace_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let namespace_id = row.try_get("id")?;
        let short_id: ShortId = row.try_get("short_id")?;
        let namespace: String = row.try_get("namespace")?;
        let status_str: String = row.try_get("status")?;
        let metadata_json: serde_json::Value = row.try_get("metadata")?;
        let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
        let created_by: Option<uuid::Uuid> = row.try_get("created_by")?;
        let updated_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("updated_at")?;
        let updated_by: Option<uuid::Uuid> = row.try_get("updated_by")?;
        let deleted_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("deleted_at")?;

        let metadata: Metadata = serde_json::from_value(metadata_json)?;

        Ok(Some(Namespace {
            id: namespace_id,
            short_id,
            namespace: NamespaceString::try_from(namespace)?,
            status: ResourceStatus::try_from(status_str.as_str())?,
            metadata,
            created_at,
            created_by,
            updated_at,
            updated_by,
            deleted_at,
        }))
    }

    async fn rotate_kek(
        &self,
        namespace_id: NamespaceId,
        kek_id: KekId,
        masterkey_id: MasterkeyId,
        assignment_metadata: Metadata,
    ) -> CkResult<KekAssignment> {
        // Kek rotation involves multiple steps and must be done within a transaction to ensure consistency.
        let mut tx = self.pool.begin().await?;

        // Lock namespace row (serialize rotations per namespace)
        let locked = sqlx::query_scalar::<_, Uuid>(&one_line_sql(
            r#"
            SELECT id
            FROM namespaces
            WHERE id = $1
            FOR UPDATE
            "#,
        ))
        .bind(namespace_id)
        .fetch_optional(&mut *tx)
        .await?;

        if locked.is_none() {
            tx.rollback().await?;
            return Err(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            });
        }

        // Compute next revision based on the current max revision
        let next_rev: i32 = sqlx::query_scalar(&one_line_sql(
            r#"
            SELECT COALESCE(MAX(revision), 0) + 1
            FROM namespace_kek_assignments
            WHERE namespace_id = $1
            "#,
        ))
        .bind(namespace_id)
        .fetch_one(&mut *tx)
        .await?;

        // Deactivate current active assignment (if any)
        sqlx::query(&one_line_sql(
            r#"
            UPDATE namespace_kek_assignments
            SET is_active = FALSE
            WHERE namespace_id = $1 AND is_active = TRUE
            "#,
        ))
        .bind(namespace_id)
        .execute(&mut *tx)
        .await?;

        // Insert new active assignment
        let row = sqlx::query(&one_line_sql(
            r#"
            INSERT INTO namespace_kek_assignments
                (namespace_id, revision, is_active, kek_id, metadata)
            VALUES
                ($1, $2, TRUE, $3, $4::jsonb)
            RETURNING namespace_id, revision, is_active, kek_id, metadata, created_at
            "#,
        ))
        .bind(namespace_id)
        .bind(next_rev)
        .bind(kek_id)
        .bind(assignment_metadata)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        let namespace_id = row.try_get("namespace_id")?;
        let revision = row.try_get("revision")?;
        let is_active: bool = row.try_get("is_active")?;
        let kek_id: KekId = row.try_get("kek_id")?;
        let metadata_json: serde_json::Value = row.try_get("metadata")?;
        let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
        let metadata: Metadata = serde_json::from_value(metadata_json)?;

        // Fetch short_ids for kek and masterkey
        let short_ids_row = sqlx::query(&one_line_sql(
            r#"
            SELECT k.short_id as kek_short_id, mk.short_id as masterkey_short_id
            FROM keks k
            JOIN masterkeys mk ON mk.id = k.masterkey_id
            WHERE k.id = $1
            "#,
        ))
        .bind(kek_id)
        .fetch_one(&self.pool)
        .await?;
        let kek_short_id: ShortId = short_ids_row.try_get("kek_short_id")?;
        let masterkey_short_id: ShortId = short_ids_row.try_get("masterkey_short_id")?;

        Ok(KekAssignment {
            namespace_id,
            revision,
            is_active,
            kek_id,
            kek_short_id,
            metadata,
            created_at,
            masterkey_id,
            masterkey_short_id,
        })
    }

    async fn list_kek_assignments(&self, namespace_id: NamespaceId) -> CkResult<Vec<KekAssignment>> {
        let rows = sqlx::query(&one_line_sql(
            r#"
            SELECT nka.namespace_id, nka.revision, nka.is_active, nka.kek_id, nka.metadata, nka.created_at,
                   k.masterkey_id, k.short_id as kek_short_id, mk.short_id as masterkey_short_id
            FROM namespace_kek_assignments AS nka
            JOIN keks AS k ON k.id = nka.kek_id
            JOIN masterkeys mk ON mk.id = k.masterkey_id
            WHERE nka.namespace_id = $1
            ORDER BY nka.revision
            "#,
        ))
        .bind(namespace_id)
        .fetch_all(&self.pool)
        .await?;

        let assignments = rows
            .into_iter()
            .map(|r| {
                let namespace_id = r.try_get("namespace_id")?;
                let revision = r.try_get("revision")?;
                let is_active: bool = r.try_get("is_active")?;
                let kek_id = r.try_get("kek_id")?;
                let metadata_json: serde_json::Value = r.try_get("metadata")?;
                let created_at: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
                let metadata: Metadata = serde_json::from_value(metadata_json)?;
                let masterkey_id: MasterkeyId = r.try_get("masterkey_id")?;
                let kek_short_id: ShortId = r.try_get("kek_short_id")?;
                let masterkey_short_id: ShortId = r.try_get("masterkey_short_id")?;

                Ok(KekAssignment {
                    namespace_id,
                    revision,
                    is_active,
                    kek_id,
                    kek_short_id,
                    metadata,
                    created_at,
                    masterkey_id,
                    masterkey_short_id,
                })
            })
            .collect::<CkResult<Vec<_>>>()?;

        Ok(assignments)
    }

    // We only return active namespaces here, as the name implies.
    async fn list_active(&self) -> CkResult<Vec<Namespace>> {
        let rows = sqlx::query(&one_line_sql(
            r#"
            SELECT id, short_id, namespace, status, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            FROM namespaces
            WHERE status = 'active'
            ORDER BY namespace
            "#,
        ))
        .fetch_all(&self.pool)
        .await?;

        let namespaces = rows
            .into_iter()
            .map(|r| {
                let namespace_id = r.try_get("id")?;
                let short_id: ShortId = r.try_get("short_id")?;
                let namespace: String = r.try_get("namespace")?;
                let status_str: String = r.try_get("status")?;
                let metadata_json: serde_json::Value = r.try_get("metadata")?;
                let created_at: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
                let created_by: Option<uuid::Uuid> = r.try_get("created_by")?;
                let updated_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("updated_at")?;
                let updated_by: Option<uuid::Uuid> = r.try_get("updated_by")?;
                let deleted_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("deleted_at")?;

                let metadata: Metadata = serde_json::from_value(metadata_json)?;

                Ok(Namespace {
                    id: namespace_id,
                    short_id,
                    namespace: NamespaceString::try_from(namespace)?,
                    status: ResourceStatus::try_from(status_str.as_str())?,
                    metadata,
                    created_at,
                    created_by,
                    updated_at,
                    updated_by,
                    deleted_at,
                })
            })
            .collect::<CkResult<Vec<_>>>()?;

        Ok(namespaces)
    }

    async fn search(&self, q: &NamespaceSearchQuery) -> CkResult<(Vec<NamespaceKekState>, usize)> {
        let (limit, offset) = normalize_limit_offset(q);

        fn apply_filters(qb: &mut QueryBuilder<Postgres>, q: &NamespaceSearchQuery) {
            qb.push(" WHERE 1=1");

            if q.status.is_empty() {
                // Default: hide deleted namespaces (same behaviour as fetch_namespace by path).
                // Callers that want deleted results must pass status=deleted explicitly.
                qb.push(" AND status != 'deleted'");
            } else {
                qb.push(" AND status IN (");

                let mut sep = qb.separated(", ");
                for status in &q.status {
                    sep.push_bind(status.to_string());
                }

                qb.push(")");
            }

            if let Some(term) = &q.q {
                let like = format!("%{}%", escape_ilike(term));
                qb.push(" AND namespace ILIKE ");
                qb.push_bind(like);
            }
        }

        let mut count_qb = QueryBuilder::<Postgres>::new("SELECT COUNT(*)::bigint FROM namespaces");
        apply_filters(&mut count_qb, q);

        let total: i64 = count_qb.build_query_scalar().fetch_one(&self.pool).await?;

        #[derive(sqlx::FromRow)]
        struct Row {
            id: NamespaceId,
            short_id: ShortId,
            namespace: String,
            status: String,
            metadata: Metadata,
            created_at: chrono::DateTime<chrono::Utc>,
            created_by: Option<uuid::Uuid>,
            updated_at: Option<chrono::DateTime<chrono::Utc>>,
            updated_by: Option<uuid::Uuid>,
            deleted_at: Option<chrono::DateTime<chrono::Utc>>,

            latest_kek_revision: Revision,
            active_kek_revision: Option<Revision>,

            total_secrets: i64,
        }

        let mut list_qb = QueryBuilder::<Postgres>::new(one_line_sql(
            r#"
                WITH kek AS (
                    SELECT
                        namespace_id,
                        COALESCE(MAX(revision), 0) AS latest_kek_revision,
                        MAX(revision) FILTER (WHERE is_active = TRUE) AS active_kek_revision
                    FROM namespace_kek_assignments
                    GROUP BY namespace_id
                ),
                sec AS (
                    SELECT
                        namespace_id,
                        COUNT(*)::bigint AS total_secrets
                    FROM secrets
                    GROUP BY namespace_id
                )
                SELECT
                    n.id,
                    n.short_id,
                    n.status,
                    n.namespace,
                    n.metadata,
                    n.created_at,
                    n.created_by,
                    n.updated_at,
                    n.updated_by,
                    n.deleted_at,
                    COALESCE(kek.latest_kek_revision, 0) AS latest_kek_revision,
                    kek.active_kek_revision,
                    COALESCE(sec.total_secrets, 0) AS total_secrets
                FROM namespaces n
                LEFT JOIN kek ON kek.namespace_id = n.id
                LEFT JOIN sec ON sec.namespace_id = n.id
        "#,
        ));

        apply_filters(&mut list_qb, q);

        // list_qb.push(" GROUP BY n.id, n.status, n.namespace, n.metadata, n.created_at, n.updated_at, n.deleted_at");
        list_qb.push(" ORDER BY n.namespace ASC");
        list_qb.push(" LIMIT ");
        list_qb.push_bind(limit as i64);
        list_qb.push(" OFFSET ");
        list_qb.push_bind(offset as i64);

        let rows: Vec<Row> = list_qb
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .inspect_err(|e| error!("namespace search query failed: {}", e))?;

        let entries = rows
            .into_iter()
            .map(|r| {
                let namespace = Namespace {
                    id: r.id,
                    short_id: r.short_id,
                    namespace: NamespaceString::try_from(r.namespace)?,
                    status: ResourceStatus::try_from(r.status.as_str())?,
                    metadata: r.metadata,
                    created_at: r.created_at,
                    created_by: r.created_by,
                    updated_at: r.updated_at,
                    updated_by: r.updated_by,
                    deleted_at: r.deleted_at,
                };

                Ok(NamespaceKekState {
                    namespace,
                    latest_kek_revision: r.latest_kek_revision,
                    active_kek_revision: r.active_kek_revision,
                    total_secrets: r.total_secrets as usize,
                })
            })
            .collect::<CkResult<Vec<_>>>()?;

        Ok((entries, total as usize))
    }

    async fn search_all(&self, q: &NamespaceSearchQuery) -> CkResult<Vec<NamespaceKekState>> {
        fn apply_filters_all(qb: &mut QueryBuilder<Postgres>, q: &NamespaceSearchQuery) {
            qb.push(" WHERE 1=1");
            if q.status.is_empty() {
                qb.push(" AND status != 'deleted'");
            } else {
                qb.push(" AND status IN (");
                let mut sep = qb.separated(", ");
                for status in &q.status {
                    sep.push_bind(status.to_string());
                }
                qb.push(")");
            }
            if let Some(term) = &q.q {
                let like = format!("%{}%", escape_ilike(term));
                qb.push(" AND namespace ILIKE ");
                qb.push_bind(like);
            }
        }

        #[derive(sqlx::FromRow)]
        struct Row {
            id: NamespaceId,
            short_id: ShortId,
            namespace: String,
            status: String,
            metadata: Metadata,
            created_at: chrono::DateTime<chrono::Utc>,
            created_by: Option<uuid::Uuid>,
            updated_at: Option<chrono::DateTime<chrono::Utc>>,
            updated_by: Option<uuid::Uuid>,
            deleted_at: Option<chrono::DateTime<chrono::Utc>>,
            latest_kek_revision: Revision,
            active_kek_revision: Option<Revision>,
            total_secrets: i64,
        }

        let mut list_qb = QueryBuilder::<Postgres>::new(one_line_sql(
            r#"
                WITH kek AS (
                    SELECT
                        namespace_id,
                        COALESCE(MAX(revision), 0) AS latest_kek_revision,
                        MAX(revision) FILTER (WHERE is_active = TRUE) AS active_kek_revision
                    FROM namespace_kek_assignments
                    GROUP BY namespace_id
                ),
                sec AS (
                    SELECT
                        namespace_id,
                        COUNT(*)::bigint AS total_secrets
                    FROM secrets
                    GROUP BY namespace_id
                )
                SELECT
                    n.id,
                    n.short_id,
                    n.status,
                    n.namespace,
                    n.metadata,
                    n.created_at,
                    n.created_by,
                    n.updated_at,
                    n.updated_by,
                    n.deleted_at,
                    COALESCE(kek.latest_kek_revision, 0) AS latest_kek_revision,
                    kek.active_kek_revision,
                    COALESCE(sec.total_secrets, 0) AS total_secrets
                FROM namespaces n
                LEFT JOIN kek ON kek.namespace_id = n.id
                LEFT JOIN sec ON sec.namespace_id = n.id
        "#,
        ));

        apply_filters_all(&mut list_qb, q);
        list_qb.push(" ORDER BY n.namespace ASC");

        let rows: Vec<Row> = list_qb
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .inspect_err(|e| error!("namespace search_all query failed: {}", e))?;

        rows.into_iter()
            .map(|r| {
                let namespace = Namespace {
                    id: r.id,
                    short_id: r.short_id,
                    namespace: NamespaceString::try_from(r.namespace)?,
                    status: ResourceStatus::try_from(r.status.as_str())?,
                    metadata: r.metadata,
                    created_at: r.created_at,
                    created_by: r.created_by,
                    updated_at: r.updated_at,
                    updated_by: r.updated_by,
                    deleted_at: r.deleted_at,
                };
                Ok(NamespaceKekState {
                    namespace,
                    latest_kek_revision: r.latest_kek_revision,
                    active_kek_revision: r.active_kek_revision,
                    total_secrets: r.total_secrets as usize,
                })
            })
            .collect::<CkResult<Vec<_>>>()
    }

    async fn disable(&self, namespace_id: NamespaceId) -> CkResult<bool> {
        let mut tx = self.pool.begin().await?;

        let result = sqlx::query(&one_line_sql(
            r#"
        UPDATE namespaces
        SET status = 'disabled', deleted_at = NOW()
        WHERE id = $1 AND status = 'active'
        "#,
        ))
        .bind(namespace_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }

        // Deactivate all KEK assignments
        sqlx::query(&one_line_sql(
            r#"
        UPDATE namespace_kek_assignments
        SET is_active = FALSE
        WHERE namespace_id = $1
        "#,
        ))
        .bind(namespace_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    async fn delete(&self, namespace_id: NamespaceId) -> CkResult<bool> {
        let mut tx = self.pool.begin().await?;

        let row: Option<String> = sqlx::query_scalar(&one_line_sql(
            r#"
        SELECT status
        FROM namespaces
        WHERE id = $1
        FOR UPDATE
        "#,
        ))
        .bind(namespace_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(status) = row else {
            tx.rollback().await?;
            return Ok(false);
        };

        if status != "disabled" {
            tx.rollback().await?;
            return Err(CkError::Conflict {
                what: format!("namespace must be disabled before destruction (current status: {status})"),
            });
        }

        // status = disabled is a catch to make sure we cannot delete active namespaces directly by accident
        let result = sqlx::query(&one_line_sql(
            r#"
        UPDATE namespaces
        SET status = 'deleted', deleted_at = COALESCE(deleted_at, NOW())
        WHERE id = $1 AND status = 'disabled'
        "#,
        ))
        .bind(namespace_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }

        // Deactivate all KEK assignments (already deactivated from disable, but be explicit)
        sqlx::query(&one_line_sql(
            r#"
        UPDATE namespace_kek_assignments
        SET is_active = FALSE
        WHERE namespace_id = $1
        "#,
        ))
        .bind(namespace_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    async fn enable(&self, namespace_id: NamespaceId) -> CkResult<bool> {
        let mut tx = self.pool.begin().await?;

        let row: Option<(String, Option<i32>)> = sqlx::query_as(&one_line_sql(
            r#"
        SELECT
            n.status,
            (SELECT MAX(revision)
             FROM namespace_kek_assignments
             WHERE namespace_id = n.id) AS latest_revision
        FROM namespaces n
        WHERE n.id = $1
        FOR UPDATE
        "#,
        ))
        .bind(namespace_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((status, latest_rev_opt)) = row else {
            tx.rollback().await?;
            return Ok(false);
        };

        if status != "disabled" {
            tx.rollback().await?;
            return Err(CkError::Conflict {
                what: format!("namespace must be disabled to enable (current status: {status})"),
            });
        }

        // Restore namespace to active
        let res = sqlx::query(&one_line_sql(
            r#"
        UPDATE namespaces
        SET status = 'active', deleted_at = NULL
        WHERE id = $1 AND status = 'disabled'
        "#,
        ))
        .bind(namespace_id)
        .execute(&mut *tx)
        .await?;

        if res.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }

        // Reactivate latest KEK revision if exists
        if let Some(latest_rev) = latest_rev_opt {
            // First deactivate all (safety)
            sqlx::query(&one_line_sql(
                r#"
            UPDATE namespace_kek_assignments
            SET is_active = FALSE
            WHERE namespace_id = $1
            "#,
            ))
            .bind(namespace_id)
            .execute(&mut *tx)
            .await?;

            // Then activate the latest
            sqlx::query(&one_line_sql(
                r#"
            UPDATE namespace_kek_assignments
            SET is_active = TRUE
            WHERE namespace_id = $1 AND revision = $2
            "#,
            ))
            .bind(namespace_id)
            .bind(latest_rev)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(true)
    }

    async fn resolve_short_namespace_id(&self, prefix: &str) -> CkResult<ResolveOne<NamespaceId>> {
        let sql = one_line_sql(
            r#"
            SELECT id FROM namespaces WHERE short_id ILIKE $1 AND deleted_at IS NULL
        "#,
        );

        let rows = sqlx::query_as::<_, (NamespaceId,)>(&sql)
            .bind(format!("{}%", escape_ilike(prefix)))
            .fetch_all(&self.pool)
            .await?;

        match rows.len() {
            0 => Ok(ResolveOne::None),
            1 => Ok(ResolveOne::One(rows[0].0)),
            n => Ok(ResolveOne::Many(Some(n))),
        }
    }
}

// ------------------------------------------------------------------------------------
#[cfg(test)]
pub struct InMemoryNamespaceStore {
    // there can be multiple namespace strings with a namespace entry. BUT only when
    // old ones are set to DELETED. We can NEVER get from DELETED back to ACTIVE state.
    namespaces: Mutex<HashMap<NamespaceId, Namespace>>,
    namespace_kek_assignments: Mutex<HashMap<(NamespaceId, Revision), KekAssignment>>,
}

#[cfg(test)]
impl Default for InMemoryNamespaceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl InMemoryNamespaceStore {
    pub fn new() -> Self {
        Self {
            namespaces: Mutex::new(HashMap::new()),
            namespace_kek_assignments: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl NamespaceStore for InMemoryNamespaceStore {
    async fn create_namespace(
        &self,
        namespace_id: Option<NamespaceId>,
        ns_path: &NamespaceString,
        metadata: Metadata,
        status: ResourceStatus,
        kek_id: KekId,
        masterkey_id: MasterkeyId,
        created_by: Option<uuid::Uuid>,
    ) -> CkResult<Namespace> {
        let mut ns_store = self.namespaces.lock();
        let mut ka_store = self.namespace_kek_assignments.lock();

        // Check if an ACTIVE or DISABLED namespace already exists with this path
        for ns in ns_store.values() {
            if ns.namespace == *ns_path
                && (ns.status == ResourceStatus::Active || ns.status == ResourceStatus::Disabled)
            {
                return Err(CkError::ResourceExists {
                    kind: "namespace",
                    id: ns_path.to_string(),
                });
            }
        }

        // Create new namespace
        let new_ns = Namespace {
            id: namespace_id.unwrap_or_default(),
            short_id: ShortId::generate("ns_", 12),
            status,
            namespace: ns_path.clone(),
            metadata,
            created_at: chrono::Utc::now(),
            created_by,
            updated_at: None,
            updated_by: None,
            deleted_at: None,
        };

        // Create initial KEK assignment (revision 1, is_active = true)
        let kek_assignment = KekAssignment {
            namespace_id: new_ns.id,
            revision: Revision::Number(1),
            is_active: true,
            kek_id,
            kek_short_id: ShortId::generate("kek_", 12),
            metadata: Metadata::default(),
            created_at: chrono::Utc::now(),
            masterkey_id,
            masterkey_short_id: ShortId::generate("mk_", 12),
        };

        // Insert namespace
        ns_store.insert(new_ns.id, new_ns.clone());

        // Insert KEK assignment
        ka_store.insert((new_ns.id, Revision::Number(1)), kek_assignment);

        Ok(new_ns)
    }

    async fn update_namespace(
        &self,
        namespace_id: NamespaceId,
        metadata: Metadata,
        updated_by: Option<uuid::Uuid>,
    ) -> CkResult<Namespace> {
        let mut store = self.namespaces.lock();

        for ns in store.values_mut() {
            if ns.id == namespace_id {
                ns.metadata = metadata;
                ns.updated_at = Some(chrono::Utc::now());
                ns.updated_by = updated_by;
                return Ok(ns.clone());
            }
        }

        Err(CkError::ResourceNotFound {
            kind: "namespace",
            id: namespace_id.to_string(),
        })
    }

    async fn fetch_namespace(&self, ns_path: &NamespaceString) -> CkResult<Option<Namespace>> {
        let store = self.namespaces.lock();

        // Find the ACTIVE namespace with this path
        for ns in store.values() {
            if ns.namespace == *ns_path
                && (ns.status == ResourceStatus::Active || ns.status == ResourceStatus::Disabled)
            {
                return Ok(Some(ns.clone()));
            }
        }

        Ok(None)
    }

    async fn fetch_namespace_by_id(&self, namespace_id: NamespaceId) -> CkResult<Option<Namespace>> {
        let store = self.namespaces.lock();

        let result = store
            .get(&namespace_id)
            .filter(|ns| ns.status != ResourceStatus::Deleted)
            .cloned();
        Ok(result)
    }

    async fn rotate_kek(
        &self,
        ns_id: NamespaceId,
        new_kek_id: KekId,
        new_masterkey_id: MasterkeyId,
        metadata: Metadata,
    ) -> CkResult<KekAssignment> {
        let mut assignments_store = self.namespace_kek_assignments.lock();

        // Find the current latest revision for this namespace
        let current_max_revision = assignments_store
            .keys()
            .filter(|(id, _)| *id == ns_id)
            .map(|(_, rev)| *rev)
            .max()
            .unwrap_or(Revision::Number(0));

        let Some(max_rev) = current_max_revision.as_number() else {
            return Err(CkError::InvariantViolation {
                what: "invalid revision type stored in memory".to_string(),
            });
        };

        let new_revision = Revision::Number(max_rev + 1);

        // Mark all existing assignments as inactive
        for ((id, _), assignment) in assignments_store.iter_mut() {
            if *id == ns_id {
                assignment.is_active = false;
            }
        }

        // Create new assignment
        let new_assignment = KekAssignment {
            namespace_id: ns_id,
            revision: new_revision,
            is_active: true,
            kek_id: new_kek_id,
            kek_short_id: ShortId::generate("kek_", 12),
            metadata,
            created_at: chrono::Utc::now(),
            masterkey_id: new_masterkey_id,
            masterkey_short_id: ShortId::generate("mk_", 12),
        };

        assignments_store.insert((ns_id, new_revision), new_assignment.clone());

        Ok(new_assignment)
    }

    async fn list_kek_assignments(&self, ns_id: NamespaceId) -> CkResult<Vec<KekAssignment>> {
        let store = self.namespace_kek_assignments.lock();

        let assignments: Vec<KekAssignment> = store
            .iter()
            .filter(|((id, _), _)| *id == ns_id)
            .map(|(_, assignment)| assignment.clone())
            .collect();

        // Sort for deterministic order
        let mut assignments = assignments;
        assignments.sort_by_key(|a| a.revision);

        Ok(assignments)
    }

    async fn list_active(&self) -> CkResult<Vec<Namespace>> {
        let store = self.namespaces.lock();

        let mut namespaces = Vec::new();
        for ns in store.values() {
            namespaces.push(ns.clone());
        }

        Ok(namespaces)
    }

    async fn search(&self, query: &NamespaceSearchQuery) -> CkResult<(Vec<NamespaceKekState>, usize)> {
        let (limit, offset) = normalize_limit_offset(query);

        let namespaces = self.namespaces.lock();
        let assignments = self.namespace_kek_assignments.lock();

        let mut matched: Vec<NamespaceKekState> = namespaces
            .values()
            .filter(|ns| {
                if query.status.is_empty() {
                    // Default: hide deleted, same as SQL behaviour.
                    ns.status != ResourceStatus::Deleted
                } else {
                    query.status.contains(&ns.status)
                }
            })
            .filter(|ns| {
                if let Some(term) = &query.q {
                    ns.namespace.as_str().to_lowercase().contains(&term.to_lowercase())
                } else {
                    true
                }
            })
            .map(|ns| {
                let ns_assignments: Vec<_> = assignments
                    .iter()
                    .filter(|((namespace_id, _), _)| namespace_id == &ns.id)
                    .map(|(_, assignment)| assignment)
                    .collect();

                let latest_kek_revision = ns_assignments
                    .iter()
                    .map(|a| a.revision)
                    .max()
                    .unwrap_or(Revision::Number(1));

                // Find the active assignment revision
                let active_kek_revision = ns_assignments.iter().find(|a| a.is_active).map(|a| a.revision);

                NamespaceKekState {
                    namespace: ns.clone(),
                    latest_kek_revision,
                    active_kek_revision,
                    total_secrets: 0, // In-memory store does not track secrets
                }
            })
            .collect();

        matched.sort_by(|a, b| a.namespace.namespace.as_str().cmp(b.namespace.namespace.as_str()));

        let total = matched.len();
        let entries = matched.into_iter().skip(offset).take(limit).collect();

        Ok((entries, total))
    }

    async fn search_all(&self, query: &NamespaceSearchQuery) -> CkResult<Vec<NamespaceKekState>> {
        let namespaces = self.namespaces.lock();
        let assignments = self.namespace_kek_assignments.lock();

        let mut matched: Vec<NamespaceKekState> = namespaces
            .values()
            .filter(|ns| {
                if query.status.is_empty() {
                    ns.status != ResourceStatus::Deleted
                } else {
                    query.status.contains(&ns.status)
                }
            })
            .filter(|ns| {
                if let Some(term) = &query.q {
                    ns.namespace.as_str().to_lowercase().contains(&term.to_lowercase())
                } else {
                    true
                }
            })
            .map(|ns| {
                let ns_assignments: Vec<_> = assignments
                    .iter()
                    .filter(|((namespace_id, _), _)| namespace_id == &ns.id)
                    .map(|(_, assignment)| assignment)
                    .collect();

                let latest_kek_revision = ns_assignments
                    .iter()
                    .map(|a| a.revision)
                    .max()
                    .unwrap_or(Revision::Number(1));

                let active_kek_revision = ns_assignments.iter().find(|a| a.is_active).map(|a| a.revision);

                NamespaceKekState {
                    namespace: ns.clone(),
                    latest_kek_revision,
                    active_kek_revision,
                    total_secrets: 0,
                }
            })
            .collect();

        matched.sort_by(|a, b| a.namespace.namespace.as_str().cmp(b.namespace.namespace.as_str()));

        Ok(matched)
    }

    async fn disable(&self, namespace_id: NamespaceId) -> CkResult<bool> {
        let mut store = self.namespaces.lock();

        let Some(namespace) = store.get_mut(&namespace_id) else {
            return Ok(false);
        };

        if namespace.status != ResourceStatus::Active {
            return Err(CkError::Conflict {
                what: format!(
                    "namespace must be active to disable (current status: {})",
                    namespace.status.as_str()
                ),
            });
        }

        namespace.updated_at = Some(chrono::Utc::now());
        namespace.status = ResourceStatus::Disabled;
        Ok(true)
    }

    async fn delete(&self, namespace_id: NamespaceId) -> CkResult<bool> {
        let mut store = self.namespaces.lock();

        // Find namespace in DISABLED state in store
        let Some(namespace) = store.get_mut(&namespace_id) else {
            return Ok(false);
        };

        if namespace.status != ResourceStatus::Disabled {
            return Err(CkError::Conflict {
                what: format!(
                    "namespace must be disabled to delete (current status: {})",
                    namespace.status.as_str()
                ),
            });
        }

        namespace.status = ResourceStatus::Deleted;
        namespace.deleted_at = Some(chrono::Utc::now());
        namespace.updated_at = Some(chrono::Utc::now());
        Ok(true)
    }

    async fn enable(&self, namespace_id: NamespaceId) -> CkResult<bool> {
        let mut store = self.namespaces.lock();

        // Find namespace in DISABLED state in store
        let Some(namespace) = store.get_mut(&namespace_id) else {
            return Ok(false);
        };

        if namespace.status != ResourceStatus::Disabled {
            return Err(CkError::Conflict {
                what: format!(
                    "namespace must be disabled to enable (current status: {})",
                    namespace.status.as_str()
                ),
            });
        }

        namespace.updated_at = Some(chrono::Utc::now());
        namespace.status = ResourceStatus::Active;
        Ok(true)
    }

    async fn resolve_short_namespace_id(&self, prefix: &str) -> CkResult<ResolveOne<NamespaceId>> {
        let store = self.namespaces.lock();
        let prefix_lower = prefix.to_lowercase();
        let matches: Vec<NamespaceId> = store
            .values()
            .filter(|ns| ns.deleted_at.is_none() && ns.short_id.to_string().to_lowercase().starts_with(&prefix_lower))
            .map(|ns| ns.id)
            .collect();
        match matches.len() {
            0 => Ok(ResolveOne::None),
            1 => Ok(ResolveOne::One(matches[0])),
            n => Ok(ResolveOne::Many(Some(n))),
        }
    }
}

// ------------------------------------------------------------------------------------

pub struct NamespaceManager {
    store: Arc<dyn NamespaceStore>,
}

impl NamespaceManager {
    pub fn new(store: Arc<dyn NamespaceStore>) -> Self {
        Self { store }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_namespace(
        &self,
        ctx: &CallContext,
        namespace_id: Option<NamespaceId>,
        ns_path: &NamespaceString,
        metadata: Metadata,
        status: ResourceStatus,
        kek_id: KekId,
        masterkey_id: MasterkeyId,
    ) -> CkResult<Namespace> {
        let created_by = ctx.actor.account_id().map(|id| id.0);
        trace!("Creating namespace '{}'", ns_path);
        self.store
            .create_namespace(namespace_id, ns_path, metadata, status, kek_id, masterkey_id, created_by)
            .await
    }

    pub async fn update_namespace(
        &self,
        ctx: &CallContext,
        namespace_id: NamespaceId,
        metadata: Metadata,
    ) -> CkResult<Namespace> {
        // Check if namespace exists (TOCTOU, but it's fine since update_namespace will fail otherwise)
        let exists = self.store.fetch_namespace_by_id(namespace_id).await?;
        if exists.is_none() {
            return Err(CkError::ResourceNotFound {
                kind: "namespace",
                id: namespace_id.to_string(),
            });
        }

        let updated_by = ctx.actor.account_id().map(|id| id.0);
        self.store.update_namespace(namespace_id, metadata, updated_by).await
    }

    pub async fn fetch_namespace(&self, ns_path: &NamespaceString) -> CkResult<Option<Namespace>> {
        self.store.fetch_namespace(ns_path).await
    }

    pub async fn fetch_namespace_by_id(&self, namespace_id: NamespaceId) -> CkResult<Option<Namespace>> {
        self.store.fetch_namespace_by_id(namespace_id).await
    }

    pub async fn find_all_namespaces(&self) -> CkResult<Vec<Namespace>> {
        self.store.list_active().await
    }

    pub async fn rotate_kek(
        &self,
        namespace_id: NamespaceId,
        new_kek_id: KekId,
        new_masterkey_id: MasterkeyId,
        metadata: Metadata,
    ) -> CkResult<KekAssignment> {
        self.store
            .rotate_kek(namespace_id, new_kek_id, new_masterkey_id, metadata)
            .await
    }

    pub async fn list_kek_assignments(&self, ns_id: NamespaceId) -> CkResult<Vec<KekAssignment>> {
        let res = self.store.list_kek_assignments(ns_id).await?;
        Ok(res)
    }

    pub async fn is_namespace_disabled(&self, ns_path: &NamespaceString) -> CkResult<bool> {
        let ns_opt = self.store.fetch_namespace(ns_path).await?;
        match ns_opt {
            Some(ns) => Ok(ns.status == ResourceStatus::Disabled),
            None => Err(CkError::ResourceNotFound {
                kind: "namespace",
                id: ns_path.to_string(),
            }),
        }
    }

    /// Soft-delete (disable) a namespace.
    pub async fn disable(&self, _ctx: &CallContext, namespace_id: NamespaceId) -> CkResult<bool> {
        debug!("Disabling namespace '{}'", namespace_id);
        self.store.disable(namespace_id).await
    }

    /// Hard delete a namespace (cryptographic erase + tombstone).
    pub async fn delete(&self, _ctx: &CallContext, namespace_id: NamespaceId) -> CkResult<bool> {
        debug!("Deleting namespace '{}'", namespace_id);
        self.store.delete(namespace_id).await
    }

    pub async fn enable(&self, _ctx: &CallContext, namespace_id: NamespaceId) -> CkResult<bool> {
        debug!("Enabling namespace '{}'", namespace_id);
        self.store.enable(namespace_id).await
    }

    pub async fn search(&self, q: &NamespaceSearchQuery) -> CkResult<(Vec<NamespaceKekState>, usize)> {
        self.store.search(q).await
    }

    pub async fn search_all(&self, q: &NamespaceSearchQuery) -> CkResult<Vec<NamespaceKekState>> {
        self.store.search_all(q).await
    }

    pub async fn fetch_kek_assignments(&self, ns_id: NamespaceId) -> CkResult<Vec<KekAssignment>> {
        self.store.list_kek_assignments(ns_id).await
    }

    pub async fn resolve_short_namespace_id(&self, prefix: &str) -> CkResult<ResolveOne<NamespaceId>> {
        self.store.resolve_short_namespace_id(prefix).await
    }
}

fn normalize_limit_offset(q: &NamespaceSearchQuery) -> (usize, usize) {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT_VALUE).min(MAX_LIMIT_VALUE);
    let offset = q.offset.unwrap_or(DEFAULT_OFFSET_VALUE);
    (limit, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_context::CallContext;
    use hierarkey_core::resources::NamespaceString;

    fn test_kek_id() -> KekId {
        KekId::new()
    }

    fn test_namespace_string(s: &str) -> NamespaceString {
        NamespaceString::try_from(s).unwrap()
    }

    #[tokio::test]
    async fn test_create_namespace() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await
            .unwrap();

        assert_eq!(ns.namespace, ns_path);
        assert_eq!(ns.status, ResourceStatus::Active);
    }

    #[tokio::test]
    async fn test_create_duplicate_namespace() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        manager
            .create_namespace(
                &ctx,
                None,
                &ns_path,
                metadata.clone(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
            )
            .await
            .unwrap();

        let result = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await;

        assert!(matches!(result, Err(CkError::ResourceExists { .. })));
    }

    #[tokio::test]
    async fn test_fetch_namespace() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let created = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await
            .unwrap();

        let fetched = manager.fetch_namespace(&ns_path).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id, created.id);
    }

    #[tokio::test]
    async fn test_fetch_nonexistent_namespace() {
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/nonexistent");
        let result = manager.fetch_namespace(&ns_path).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update_namespace() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let created = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await
            .unwrap();

        let mut new_metadata = Metadata::default();
        new_metadata.insert("key", json!("value"));

        let updated = manager
            .update_namespace(&ctx, created.id, new_metadata.clone())
            .await
            .unwrap();

        assert_eq!(updated.metadata, new_metadata);
        assert!(updated.updated_at.is_some());
    }

    #[tokio::test]
    async fn test_rotate_kek() {
        let store = Arc::new(InMemoryNamespaceStore::new());

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns = store
            .create_namespace(
                None,
                &ns_path,
                metadata.clone(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
                None,
            )
            .await
            .unwrap();

        let new_kek_id = test_kek_id();
        let new_masterkey_id = MasterkeyId::new();
        let assignment = store
            .rotate_kek(ns.id, new_kek_id, new_masterkey_id, metadata)
            .await
            .unwrap();

        assert_eq!(assignment.revision.as_number(), Some(2));
        assert!(assignment.is_active);
        assert_eq!(assignment.kek_id, new_kek_id);
        assert_eq!(assignment.masterkey_id, new_masterkey_id);
    }

    #[tokio::test]
    async fn test_list_kek_assignments() {
        let store = Arc::new(InMemoryNamespaceStore::new());

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns = store
            .create_namespace(
                None,
                &ns_path,
                metadata.clone(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
                None,
            )
            .await
            .unwrap();

        let new_kek_id = test_kek_id();
        let new_masterkey_id = MasterkeyId::new();
        store
            .rotate_kek(ns.id, new_kek_id, new_masterkey_id, metadata)
            .await
            .unwrap();

        let assignments = store.list_kek_assignments(ns.id).await.unwrap();
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0].revision.as_number(), Some(1));
        assert!(!assignments[0].is_active);
        assert_eq!(assignments[1].revision.as_number(), Some(2));
        assert!(assignments[1].is_active);
    }

    #[tokio::test]
    async fn test_disable_namespace() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await
            .unwrap();

        let result = manager.disable(&ctx, ns.id).await.unwrap();
        assert!(result);

        let disabled_ns = manager.fetch_namespace_by_id(ns.id).await.unwrap().unwrap();
        assert_eq!(disabled_ns.status, ResourceStatus::Disabled);
    }

    #[tokio::test]
    async fn test_delete_namespace() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await
            .unwrap();

        manager.disable(&ctx, ns.id).await.unwrap();

        let result = manager.delete(&ctx, ns.id).await.unwrap();
        assert!(result);

        // A deleted namespace must no longer be visible via fetch_namespace_by_id
        let deleted_ns = manager.fetch_namespace_by_id(ns.id).await.unwrap();
        assert!(
            deleted_ns.is_none(),
            "deleted namespace should not be returned by fetch_namespace_by_id"
        );

        // Also must not be visible via path lookup
        let deleted_by_path = manager.fetch_namespace(&ns_path).await.unwrap();
        assert!(
            deleted_by_path.is_none(),
            "deleted namespace should not be returned by fetch_namespace (path)"
        );
    }

    #[tokio::test]
    async fn test_deleted_without_disable_fails() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await
            .unwrap();

        let result = manager.delete(&ctx, ns.id).await;
        assert!(matches!(result, Err(CkError::Conflict { .. })));
    }

    #[tokio::test]
    async fn test_enable_namespace() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await
            .unwrap();

        manager.disable(&ctx, ns.id).await.unwrap();

        let result = manager.enable(&ctx, ns.id).await.unwrap();
        assert!(result);

        let restored_ns = manager.fetch_namespace_by_id(ns.id).await.unwrap().unwrap();
        assert_eq!(restored_ns.status, ResourceStatus::Active);
    }

    #[tokio::test]
    async fn test_search_namespaces() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();
        manager
            .create_namespace(
                &ctx,
                None,
                &test_namespace_string("/prod/api"),
                Metadata::default(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
            )
            .await
            .unwrap();
        manager
            .create_namespace(
                &ctx,
                None,
                &test_namespace_string("/prod/web"),
                Metadata::default(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
            )
            .await
            .unwrap();
        manager
            .create_namespace(
                &ctx,
                None,
                &test_namespace_string("/dev/api"),
                Metadata::default(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
            )
            .await
            .unwrap();

        let q = NamespaceSearchQuery {
            q: Some("prod/".to_string()),
            status: vec![ResourceStatus::Active],
            limit: Some(10),
            offset: Some(0),
        };
        let (entries, total) = manager.search(&q).await.unwrap();

        assert_eq!(total, 2);
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_search_with_pagination() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        for i in 0..5 {
            manager
                .create_namespace(
                    &ctx,
                    None,
                    &test_namespace_string(&format!("/test/ns{i}")),
                    Metadata::default(),
                    ResourceStatus::Active,
                    kek_id,
                    masterkey_id,
                )
                .await
                .unwrap();
        }

        let q = NamespaceSearchQuery {
            q: Some("test/".to_string()),
            status: vec![ResourceStatus::Active],
            limit: Some(2),
            offset: Some(0),
        };
        let (result, total) = manager.search(&q).await.unwrap();

        assert_eq!(total, 5);
        assert_eq!(result.len(), 2);

        let q = NamespaceSearchQuery {
            q: Some("test/".to_string()),
            status: vec![ResourceStatus::Active],
            limit: Some(2),
            offset: Some(2),
        };
        let (result2, total2) = manager.search(&q).await.unwrap();

        assert_eq!(total2, 5);
        assert_eq!(result2.len(), 2);
    }

    #[tokio::test]
    async fn test_search_with_status_filter() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns1 = manager
            .create_namespace(
                &ctx,
                None,
                &test_namespace_string("/test/active"),
                Metadata::default(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
            )
            .await
            .unwrap();

        let ns2 = manager
            .create_namespace(
                &ctx,
                None,
                &test_namespace_string("/test/to-disable"),
                Metadata::default(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
            )
            .await
            .unwrap();

        manager.disable(&ctx, ns2.id).await.unwrap();

        let q = NamespaceSearchQuery {
            q: Some("test/".to_string()),
            status: vec![ResourceStatus::Active],
            limit: Some(10),
            offset: Some(0),
        };
        let (active_result, total) = manager.search(&q).await.unwrap();

        assert_eq!(total, 1);
        assert_eq!(active_result[0].namespace.namespace, ns1.namespace);

        let q = NamespaceSearchQuery {
            q: Some("test/".to_string()),
            status: vec![ResourceStatus::Disabled],
            limit: Some(10),
            offset: Some(0),
        };
        let (disabled_result, total) = manager.search(&q).await.unwrap();

        assert_eq!(total, 1);
        assert_eq!(disabled_result[0].namespace.namespace, ns2.namespace);
    }

    #[tokio::test]
    async fn search_default_excludes_deleted() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let active = manager
            .create_namespace(
                &ctx,
                None,
                &test_namespace_string("/ns/active"),
                Metadata::default(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
            )
            .await
            .unwrap();

        let to_delete = manager
            .create_namespace(
                &ctx,
                None,
                &test_namespace_string("/ns/deleted"),
                Metadata::default(),
                ResourceStatus::Active,
                kek_id,
                masterkey_id,
            )
            .await
            .unwrap();

        // Disable then delete so it reaches Deleted status
        manager.disable(&ctx, to_delete.id).await.unwrap();
        manager.delete(&ctx, to_delete.id).await.unwrap();

        // Default search (no status filter) must not return the deleted namespace
        let q = NamespaceSearchQuery {
            q: None,
            status: vec![],
            limit: Some(10),
            offset: Some(0),
        };
        let (entries, total) = manager.search(&q).await.unwrap();

        assert_eq!(total, 1, "default search should exclude the deleted namespace");
        assert_eq!(entries[0].namespace.id, active.id);

        // Explicit status=deleted must still return it
        let q_deleted = NamespaceSearchQuery {
            q: None,
            status: vec![ResourceStatus::Deleted],
            limit: Some(10),
            offset: Some(0),
        };
        let (deleted_entries, deleted_total) = manager.search(&q_deleted).await.unwrap();
        assert_eq!(deleted_total, 1);
        assert_eq!(deleted_entries[0].namespace.id, to_delete.id);
    }

    #[tokio::test]
    async fn test_is_namespace_disabled() {
        let ctx = CallContext::system();
        let store = Arc::new(InMemoryNamespaceStore::new());
        let manager = NamespaceManager::new(store);

        let ns_path = test_namespace_string("/test/namespace");
        let metadata = Metadata::default();
        let kek_id = test_kek_id();
        let masterkey_id = MasterkeyId::new();

        let ns = manager
            .create_namespace(&ctx, None, &ns_path, metadata, ResourceStatus::Active, kek_id, masterkey_id)
            .await
            .unwrap();

        assert!(!manager.is_namespace_disabled(&ns_path).await.unwrap());

        manager.disable(&ctx, ns.id).await.unwrap();

        assert!(manager.is_namespace_disabled(&ns_path).await.unwrap());
    }
}
