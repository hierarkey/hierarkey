// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ResolveOne;
use crate::global::keys::{EncryptedDek, KekId};
use crate::global::resource::ResourceStatus;
use crate::global::{DEFAULT_LIMIT_VALUE, MAX_LIMIT_VALUE};
use crate::manager::namespace::NamespaceId;
use crate::manager::secret::{
    RevisionDto, SearchResponse, Secret, SecretDto, SecretId, SecretRevision, SecretRevisionId, SecretStore,
};
use crate::one_line_sql;
use chrono::{DateTime, Utc};
use hierarkey_core::api::search::query::{SecretSearchRequest, SecretSortKey};
use hierarkey_core::resources::KeyString;
use hierarkey_core::{CkError, CkResult, Metadata, resources::Revision};
use serde_json::json;
use sqlx::{PgPool, QueryBuilder, Row};

// ----------------------------------------------------------------------------------------------

pub fn escape_like(s: &str) -> String {
    // Escape % and _ for LIKE/ILIKE
    s.replace('\\', r"\\").replace('%', r"\%").replace('_', r"\_")
}

/// Parse "k=v" or "k" from strings (same format as your API request uses)
fn split_label_expr(expr: &str) -> (String, Option<String>) {
    if let Some((k, v)) = expr.split_once('=') {
        (k.trim().to_string(), Some(v.trim().to_string()))
    } else {
        (expr.trim().to_string(), None)
    }
}

/// Used when you store timestamps in metadata as RFC3339 strings
#[allow(unused)]
fn to_rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ----------------------------------------------------------------------------------------------

pub struct SqlSecretStore {
    pool: PgPool,
}

impl SqlSecretStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl SecretStore for SqlSecretStore {
    async fn create_first_revision(&self, sd: &SecretDto, rd: &RevisionDto) -> CkResult<(Secret, SecretRevision)> {
        let mut tx = self.pool.begin().await?;

        let secret = sqlx::query_as::<_, Secret>(
            &one_line_sql(r#"
            INSERT INTO secrets (id, namespace_id, ref_ns, ref_key, status, metadata, created_by)
            VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
            RETURNING id, short_id, namespace_id, ref_ns, ref_key, status, active_revision, latest_revision, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            "#),
        )
            .bind(sd.secret_id)
            .bind(sd.namespace_id)
            .bind(sd.secret_ref.namespace.as_str())
            .bind(sd.secret_ref.key.as_str())
            .bind(sd.status.as_str())
            .bind(json!(sd.metadata))
            .bind(sd.created_by)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                if let sqlx::Error::Database(db_err) = &e
                    && db_err.is_unique_violation() {
                        return CkError::ResourceExists {
                            kind: "secret",
                            id: sd.secret_ref.to_string(),
                        }
                    }
                CkError::from(e)
            })?;

        // Insert the new revision
        let secret_revision = sqlx::query_as::<_, SecretRevision>(
            &one_line_sql(r#"
            INSERT INTO secret_revisions (id, secret_id, revision, encrypted_secret, encrypted_dek, kek_id, secret_alg, dek_alg, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
            RETURNING id, secret_id, revision, encrypted_secret, encrypted_dek, kek_id, secret_alg, dek_alg, metadata, created_at, deleted_at
            "#),
        )
            .bind(rd.secret_revision_id)
            .bind(secret.id)
            .bind(Revision::Number(1))        // Initial revision
            .bind(rd.encrypted_secret.as_bytes())
            .bind(rd.encrypted_dek.as_bytes())
            .bind(rd.kek_id)
            .bind(rd.secret_alg.as_str())
            .bind(rd.dek_alg.as_str())
            .bind(json!(rd.metadata))
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                if let sqlx::Error::Database(db_err) = &e
                    && db_err.is_unique_violation() {
                        return CkError::ResourceExists {
                            kind: "secret_revision",
                            id: sd.secret_ref.to_string(),
                        }
                    }
                CkError::from(e)
            })?;

        tx.commit().await?;

        Ok((secret, secret_revision))
    }

    async fn create_next_revision(&self, secret_id: SecretId, rd: &RevisionDto) -> CkResult<SecretRevision> {
        let mut tx = self.pool.begin().await?;

        // Get the next revision number
        let latest_rev_row = sqlx::query(&one_line_sql(
            r#"
            SELECT latest_revision FROM secrets WHERE id = $1 FOR UPDATE
            "#,
        ))
        .bind(secret_id)
        .fetch_one(&mut *tx)
        .await?;

        let current_latest: i32 = latest_rev_row.try_get("latest_revision")?;
        let new_revision = current_latest + 1;

        // Insert the new revision
        let rev = sqlx::query_as::<_, SecretRevision>(
            &one_line_sql(r#"
            INSERT INTO secret_revisions (id, secret_id, revision, encrypted_secret, encrypted_dek, kek_id, secret_alg, dek_alg, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
            RETURNING id, secret_id, revision, encrypted_secret, encrypted_dek, kek_id, secret_alg, dek_alg, metadata, created_at, deleted_at
            "#),
        )
            .bind(rd.secret_revision_id)
            .bind(secret_id)
            .bind(new_revision)
            .bind(rd.encrypted_secret.as_bytes())
            .bind(rd.encrypted_dek.as_bytes())
            .bind(rd.kek_id)
            .bind(rd.secret_alg.as_str())
            .bind(rd.dek_alg.as_str())
            .bind(json!(rd.metadata))
            .fetch_one(&mut *tx)
            .await?;

        // Update latest_revision in secrets table
        sqlx::query(&one_line_sql(
            r#"
            UPDATE secrets
            SET latest_revision = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        ))
        .bind(secret_id)
        .bind(new_revision)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(rev)
    }

    async fn update(
        &self,
        secret_id: SecretId,
        metadata: &Metadata,
        updated_by: Option<uuid::Uuid>,
    ) -> CkResult<Secret> {
        sqlx::query_as::<_, Secret>(
            &one_line_sql(r#"
            UPDATE secrets
            SET metadata = $2::jsonb, updated_at = NOW(), updated_by = $3
            WHERE id = $1
            RETURNING id, short_id, namespace_id, ref_ns, ref_key, status, active_revision, latest_revision, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            "#),
        )
            .bind(secret_id)
            .bind(json!(metadata))
            .bind(updated_by)
            .fetch_one(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn find_by_id(&self, secret_id: SecretId) -> CkResult<Option<Secret>> {
        sqlx::query_as::<_, Secret>(
            &one_line_sql(r#"
            SELECT id, short_id, namespace_id, ref_ns, ref_key, status, active_revision, latest_revision, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            FROM secrets
            WHERE id = $1 AND deleted_at IS NULL
            "#),
        )
            .bind(secret_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn find_by_ref(&self, namespace_id: NamespaceId, ref_key: &KeyString) -> CkResult<Option<Secret>> {
        sqlx::query_as::<_, Secret>(
            &one_line_sql(r#"
            SELECT id, short_id, namespace_id, ref_ns, ref_key, status, active_revision, latest_revision, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            FROM secrets
            WHERE namespace_id = $1 AND ref_key = $2 AND deleted_at IS NULL
            "#),
        )
            .bind(namespace_id)
            .bind(ref_key.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn find_revision(&self, secret_id: SecretId, revision: Revision) -> CkResult<Option<SecretRevision>> {
        sqlx::query_as::<_, SecretRevision>(
            &one_line_sql(r#"
            SELECT id, secret_id, revision, encrypted_secret, encrypted_dek, kek_id, secret_alg, dek_alg, metadata, created_at, deleted_at
            FROM secret_revisions
            WHERE secret_id = $1 AND revision = $2 AND deleted_at IS NULL
            "#),
        )
            .bind(secret_id)
            .bind(revision)
            .fetch_optional(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn find_revision_by_id(&self, secret_revision_id: SecretRevisionId) -> CkResult<Option<SecretRevision>> {
        sqlx::query_as::<_, SecretRevision>(
            &one_line_sql(r#"
            SELECT id, secret_id, revision, encrypted_secret, encrypted_dek, kek_id, secret_alg, dek_alg, metadata, created_at, deleted_at
            FROM secret_revisions
            WHERE id = $1 AND deleted_at IS NULL
            "#),
        )
            .bind(secret_revision_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn get_revisions(&self, secret_id: SecretId) -> CkResult<Vec<SecretRevision>> {
        sqlx::query_as::<_, SecretRevision>(
            &one_line_sql(r#"
            SELECT id, secret_id, revision, encrypted_secret, encrypted_dek, kek_id, secret_alg, dek_alg, metadata, created_at, deleted_at
            FROM secret_revisions
            WHERE secret_id = $1
            ORDER BY revision DESC
            "#),
        )
            .bind(secret_id)
            .fetch_all(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn get_by_namespace(&self, namespace_id: NamespaceId) -> CkResult<Vec<Secret>> {
        sqlx::query_as::<_, Secret>(
            &one_line_sql(r#"
            SELECT id, short_id, namespace_id, ref_ns, ref_key, status, active_revision, latest_revision, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            FROM secrets
            WHERE namespace_id = $1 AND deleted_at IS NULL
            ORDER BY ref_key
            "#),
        )
            .bind(namespace_id)
            .fetch_all(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn find_by_id_any(&self, secret_id: SecretId) -> CkResult<Option<Secret>> {
        sqlx::query_as::<_, Secret>(
            &one_line_sql(r#"
            SELECT id, short_id, namespace_id, ref_ns, ref_key, status, active_revision, latest_revision, metadata, created_at, created_by, updated_at, updated_by, deleted_at
            FROM secrets
            WHERE id = $1
            "#),
        )
            .bind(secret_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn count_secrets(&self, namespace_id: NamespaceId) -> CkResult<usize> {
        let count: i64 = sqlx::query_scalar(&one_line_sql(
            r#"
            SELECT COUNT(*) as count FROM secrets
            WHERE namespace_id = $1 AND status != 'deleted'
            "#,
        ))
        .bind(namespace_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize)
    }

    async fn count_secrets_by_status(&self, namespace_id: NamespaceId, status: ResourceStatus) -> CkResult<usize> {
        let count: i64 = sqlx::query_scalar(&one_line_sql(
            r#"
            SELECT COUNT(*) FROM secrets
            WHERE namespace_id = $1 AND status = $2 AND deleted_at IS NULL
            "#,
        ))
        .bind(namespace_id)
        .bind(status.as_str())
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize)
    }

    async fn update_revision_metadata(
        &self,
        secret_revision_id: SecretRevisionId,
        metadata: &Metadata,
    ) -> CkResult<SecretRevision> {
        sqlx::query_as::<_, SecretRevision>(
            &one_line_sql(r#"
            UPDATE secret_revisions
            SET metadata = $2::jsonb
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING id, secret_id, revision, encrypted_secret, encrypted_dek, kek_id, secret_alg, dek_alg, metadata, created_at, deleted_at
            "#),
        )
            .bind(secret_revision_id)
            .bind(json!(metadata))
            .fetch_one(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn set_status(&self, secret_id: SecretId, status: ResourceStatus) -> CkResult<bool> {
        // Keep deleted_at in sync with status: set when marking Deleted, clear otherwise.
        let result = sqlx::query(&one_line_sql(
            r#"
            UPDATE secrets
            SET status = $2,
                deleted_at = CASE WHEN $2 = 'deleted' THEN NOW() ELSE NULL END,
                updated_at = NOW()
            WHERE id = $1
            "#,
        ))
        .bind(secret_id)
        .bind(status.as_str())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
    async fn set_active_revision(&self, secret_revision_id: SecretRevisionId) -> CkResult<bool> {
        let rev_row = sqlx::query(&one_line_sql(
            r#"
            SELECT secret_id, revision FROM secret_revisions
            WHERE id = $1 AND deleted_at IS NULL
            "#,
        ))
        .bind(secret_revision_id)
        .fetch_one(&self.pool)
        .await?;

        let secret_id: SecretId = rev_row.try_get("secret_id")?;
        let revision: Revision = rev_row.try_get("revision")?;
        let result = sqlx::query(&one_line_sql(
            r#"
            UPDATE secrets
            SET active_revision = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        ))
        .bind(revision)
        .bind(secret_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn set_active_revision_by_rev(&self, secret_id: SecretId, revision: Revision) -> CkResult<bool> {
        let Some(secret) = self.find_by_id(secret_id).await? else {
            return Err(CkError::ResourceNotFound {
                kind: "secret",
                id: secret_id.to_string(),
            });
        };

        if secret.latest_revision < revision {
            return Err(CkError::ResourceNotFound {
                kind: "secret revision",
                id: format!("{secret_id}@{revision}"),
            });
        }

        let result = sqlx::query(&one_line_sql(
            r#"
            UPDATE secrets
            SET active_revision = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        ))
        .bind(secret_id)
        .bind(revision)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn search(&self, req: &SecretSearchRequest) -> CkResult<SearchResponse> {
        let limit = req
            .page
            .limit
            .clamp(1, MAX_LIMIT_VALUE as u32)
            .max(DEFAULT_LIMIT_VALUE as u32);
        let sort_key = req.page.sort.unwrap_or(SecretSortKey::Created);
        let desc = req.page.desc;

        let sort_col = match sort_key {
            SecretSortKey::Name => "s.ref_key",
            SecretSortKey::Created => "s.created_at",
            SecretSortKey::Updated => "s.updated_at",
            SecretSortKey::Accessed => "s.updated_at",
            SecretSortKey::RotationDue => {
                "COALESCE((s.metadata->>'next_rotation_at')::timestamptz, 'infinity'::timestamptz)"
            }
        };

        // Count query
        let mut count_qb = QueryBuilder::new("SELECT COUNT(*) FROM secrets s");
        Self::apply_search_filters(&mut count_qb, req);
        let total: i64 = count_qb.build_query_scalar().fetch_one(&self.pool).await?;

        // Select query — LEFT JOIN active revision to get its plaintext length (encrypted_len - nonce(12) - tag(16))
        let mut select_qb = QueryBuilder::new(
            "SELECT s.id, s.short_id, s.namespace_id, s.ref_ns, s.ref_key, s.status, \
             s.active_revision, s.latest_revision, s.metadata, \
             s.created_at, s.created_by, s.updated_at, s.updated_by, s.deleted_at, \
             GREATEST(OCTET_LENGTH(sr.encrypted_secret) - 28, 0) AS active_revision_length \
             FROM secrets s \
             LEFT JOIN secret_revisions sr ON sr.secret_id = s.id AND sr.revision = s.active_revision",
        );
        Self::apply_search_filters(&mut select_qb, req);

        select_qb.push(" ORDER BY ");
        select_qb.push(sort_col);
        select_qb.push(if desc { " DESC" } else { " ASC" });
        select_qb.push(", s.id ");
        select_qb.push(if desc { "DESC" } else { "ASC" });
        select_qb.push(" LIMIT ");
        select_qb.push_bind((limit + 1) as i64);

        let secrets = select_qb.build_query_as::<Secret>().fetch_all(&self.pool).await?;

        let has_more = secrets.len() > limit as usize;
        let secrets: Vec<Secret> = secrets.into_iter().take(limit as usize).collect();

        Ok(SearchResponse {
            secrets,
            total: total as usize,
            next_cursor: None,
            has_more,
            limit: limit as usize,
            offset: req.page.offset as usize,
        })
    }

    async fn search_all(&self, req: &SecretSearchRequest) -> CkResult<Vec<Secret>> {
        let sort_key = req.page.sort.unwrap_or(SecretSortKey::Created);
        let desc = req.page.desc;

        let sort_col = match sort_key {
            SecretSortKey::Name => "s.ref_key",
            SecretSortKey::Created => "s.created_at",
            SecretSortKey::Updated => "s.updated_at",
            SecretSortKey::Accessed => "s.updated_at",
            SecretSortKey::RotationDue => {
                "COALESCE((s.metadata->>'next_rotation_at')::timestamptz, 'infinity'::timestamptz)"
            }
        };

        let mut select_qb = QueryBuilder::new(
            "SELECT s.id, s.short_id, s.namespace_id, s.ref_ns, s.ref_key, s.status, \
             s.active_revision, s.latest_revision, s.metadata, \
             s.created_at, s.created_by, s.updated_at, s.updated_by, s.deleted_at, \
             GREATEST(OCTET_LENGTH(sr.encrypted_secret) - 28, 0) AS active_revision_length \
             FROM secrets s \
             LEFT JOIN secret_revisions sr ON sr.secret_id = s.id AND sr.revision = s.active_revision",
        );
        Self::apply_search_filters(&mut select_qb, req);
        select_qb.push(" ORDER BY ");
        select_qb.push(sort_col);
        select_qb.push(if desc { " DESC" } else { " ASC" });
        select_qb.push(", s.id ");
        select_qb.push(if desc { "DESC" } else { "ASC" });

        select_qb
            .build_query_as::<Secret>()
            .fetch_all(&self.pool)
            .await
            .map_err(CkError::from)
    }

    async fn delete(&self, secret_id: SecretId) -> CkResult<bool> {
        let result = sqlx::query(&one_line_sql(
            r#"
            UPDATE secrets
            SET status = 'deleted', deleted_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
        ))
        .bind(secret_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn resolve_short_secret_id(&self, prefix: &str) -> CkResult<ResolveOne<SecretId>> {
        let sql = one_line_sql(
            r#"
            SELECT id FROM secrets WHERE short_id ILIKE $1 AND deleted_at IS NULL
        "#,
        );

        let rows = sqlx::query_as::<_, (SecretId,)>(&sql)
            .bind(format!("{}%", escape_like(prefix)))
            .fetch_all(&self.pool)
            .await?;

        match rows.len() {
            0 => Ok(ResolveOne::None),
            1 => Ok(ResolveOne::One(rows[0].0)),
            n => Ok(ResolveOne::Many(Some(n))),
        }
    }

    async fn list_revisions_not_using_kek(
        &self,
        namespace_id: NamespaceId,
        active_kek_id: KekId,
    ) -> CkResult<Vec<SecretRevision>> {
        sqlx::query_as::<_, SecretRevision>(&one_line_sql(
            r#"
            SELECT sr.id, sr.secret_id, sr.revision, sr.encrypted_secret, sr.encrypted_dek,
                   sr.kek_id, sr.secret_alg, sr.dek_alg, sr.metadata, sr.created_at, sr.deleted_at
            FROM secret_revisions sr
            JOIN secrets s ON s.id = sr.secret_id
            WHERE s.namespace_id = $1
              AND sr.kek_id != $2
              AND sr.deleted_at IS NULL
              AND s.deleted_at IS NULL
            "#,
        ))
        .bind(namespace_id)
        .bind(active_kek_id)
        .fetch_all(&self.pool)
        .await
        .map_err(CkError::from)
    }

    async fn update_revision_dek(
        &self,
        secret_revision_id: SecretRevisionId,
        new_kek_id: KekId,
        new_encrypted_dek: EncryptedDek,
    ) -> CkResult<()> {
        sqlx::query(&one_line_sql(
            r#"
            UPDATE secret_revisions
            SET kek_id = $2, encrypted_dek = $3
            WHERE id = $1
            "#,
        ))
        .bind(secret_revision_id)
        .bind(new_kek_id)
        .bind(new_encrypted_dek.as_bytes())
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(CkError::from)
    }
}

impl SqlSecretStore {
    fn apply_search_filters<'a>(qb: &mut QueryBuilder<'a, sqlx::Postgres>, req: &'a SecretSearchRequest) {
        qb.push(" WHERE s.deleted_at IS NULL");

        // Scope: namespaces
        if !req.scope.all_namespaces {
            if !req.scope.namespaces.is_empty() {
                qb.push(" AND s.ref_ns = ANY(");
                qb.push_bind(&req.scope.namespaces);
                qb.push(")");
            }

            if !req.scope.namespace_prefixes.is_empty() {
                qb.push(" AND (");
                for (i, p) in req.scope.namespace_prefixes.iter().enumerate() {
                    if i > 0 {
                        qb.push(" OR ");
                    }
                    qb.push("s.ref_ns LIKE ");
                    qb.push_bind(format!("{}%", escape_like(p)));
                    qb.push(r" ESCAPE '\'");
                }
                qb.push(")");
            }
        }

        // Identity
        if let Some(id) = &req.identity.id {
            match id.parse::<uuid::Uuid>() {
                Ok(uuid) => {
                    qb.push(" AND s.id = ");
                    qb.push_bind(uuid);
                }
                Err(_) => {
                    qb.push(" AND s.id::text LIKE ");
                    qb.push_bind(format!("{}%", escape_like(id)));
                    qb.push(r" ESCAPE '\'");
                }
            }
        }

        if let Some(name) = &req.identity.name {
            qb.push(" AND s.ref_key ILIKE ");
            qb.push_bind(format!("%{}%", escape_like(name)));
            qb.push(r" ESCAPE '\'");
        }

        // Labels
        for expr in &req.labels.all {
            let (k, v) = split_label_expr(expr);
            if k.is_empty() {
                continue;
            }
            match v {
                Some(val) => {
                    qb.push(" AND s.metadata->'labels' @> ");
                    qb.push_bind(json!({ k: val }));
                }
                None => {
                    qb.push(" AND s.metadata->'labels' ? ");
                    qb.push_bind(k);
                }
            }
        }

        for expr in &req.labels.none {
            let (k, v) = split_label_expr(expr);
            if k.is_empty() {
                continue;
            }
            match v {
                Some(val) => {
                    qb.push(" AND NOT (s.metadata->'labels' @> ");
                    qb.push_bind(json!({ k: val }));
                    qb.push(")");
                }
                None => {
                    qb.push(" AND NOT (s.metadata->'labels' ? ");
                    qb.push_bind(k);
                    qb.push(")");
                }
            }
        }

        // Time filters
        if let Some(dt) = req.time.created_after {
            qb.push(" AND s.created_at >= ");
            qb.push_bind(dt);
        }
        if let Some(dt) = req.time.created_before {
            qb.push(" AND s.created_at <= ");
            qb.push_bind(dt);
        }
        if let Some(dt) = req.time.updated_after {
            qb.push(" AND s.updated_at >= ");
            qb.push_bind(dt);
        }
        if let Some(dt) = req.time.updated_before {
            qb.push(" AND s.updated_at <= ");
            qb.push_bind(dt);
        }

        // State
        if let Some(status) = req.state.status {
            qb.push(" AND s.status = ");
            qb.push_bind(status.as_str());
        }

        if let Some(stale_secs) = req.state.stale_seconds {
            qb.push(" AND s.updated_at < NOW() - make_interval(secs => ");
            qb.push_bind(stale_secs as f64);
            qb.push(")");
        }

        if let Some(pol) = req.state.rotation_policy {
            qb.push(" AND s.metadata @> ");
            qb.push_bind(json!({ "rotation_policy": format!("{pol:?}").to_lowercase() }));
        }

        if let Some(st) = req.r#type.secret_type {
            qb.push(" AND s.metadata @> ");
            qb.push_bind(json!({ "type": format!("{st:?}").to_lowercase() }));
        }

        if req.state.needs_rotation {
            qb.push(" AND (s.metadata->>'next_rotation_at')::timestamptz <= NOW()");
        }

        // Free text: search ref_key and ref_ns by substring match
        if let Some(q) = &req.q {
            let pattern = format!("%{}%", escape_like(q));
            qb.push(" AND (s.ref_key ILIKE ");
            qb.push_bind(pattern.clone());
            qb.push(r" ESCAPE '\' OR s.ref_ns ILIKE ");
            qb.push_bind(pattern);
            qb.push(r" ESCAPE '\')");
        }
    }
}
