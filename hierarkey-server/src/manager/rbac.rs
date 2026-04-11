// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::manager::account::AccountId;
use crate::manager::rbac::role::{AccountBindings, Role, RoleRow, RoleWithRules};
use crate::manager::rbac::rule::{Rule, RuleRow};
use crate::manager::secret::sql_store::escape_like;
use crate::rbac::spec::RuleSpec;
use crate::rbac::{
    NearMissReason, PolicyEffect, RbacAllowedRequest, RbacAllowedResponse, RbacExplainResponse, RbacNearMiss, RoleId,
    RuleId,
};
use crate::service::rbac::RuleListItem;
use crate::{ResolveOne, one_line_sql};
#[cfg(test)]
use chrono::Utc;
use hierarkey_core::error::rbac::RbacError;
use hierarkey_core::{CkError, CkResult, Metadata};
#[cfg(test)]
use parking_lot::Mutex;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::trace;
use uuid::Uuid;

pub mod cache;
pub mod role;
pub mod rule;

// ----------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct RolePatch {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct RuleListRow {
    #[sqlx(flatten)]
    pub rule: RuleRow,

    // Aggregates
    pub role_count: i64,    // How many roles is this rule part of
    pub account_count: i64, // How many accounts have this rule directly bound (not via role)
}

impl TryFrom<RuleListRow> for Rule {
    type Error = RbacError;

    fn try_from(row: RuleListRow) -> Result<Self, Self::Error> {
        row.rule
            .try_into()
            .map_err(|e| RbacError::Validation(format!("Failed to convert RuleRow to Rule: {e}")))
    }
}

// ----------------------------------------------------------------------------------------------

// Trait for RbacStore
#[async_trait::async_trait]
pub trait RbacStore: Send + Sync + 'static {
    async fn get_rules_for_account(&self, account_id: AccountId) -> CkResult<Vec<Rule>>;
    async fn get_bindings_for_account(&self, account_id: AccountId) -> CkResult<AccountBindings>;
    /// Returns (internal_id, short_id_string) for every non-deleted account, ordered by name.
    async fn list_all_account_ids(&self) -> CkResult<Vec<(AccountId, String)>>;

    async fn resolve_short_rule_id(&self, prefix: &str) -> CkResult<ResolveOne<RuleId>>;
    async fn resolve_short_role_id(&self, prefix: &str) -> CkResult<ResolveOne<RoleId>>;

    async fn role_create(&self, actor: AccountId, name: String, metadata: Metadata) -> CkResult<Role>;
    async fn role_update(&self, actor: AccountId, id: RoleId, patch: RolePatch) -> CkResult<Role>;
    async fn role_delete(&self, actor: AccountId, id: RoleId) -> CkResult<()>;
    async fn role_get_by_name(&self, name: &str) -> CkResult<RoleWithRules>;
    async fn role_get(&self, id: RoleId) -> CkResult<RoleWithRules>;
    async fn role_search(&self) -> CkResult<Vec<RoleWithRules>>;
    async fn add_rule_to_role(&self, actor: AccountId, role_id: RoleId, rule_id: RuleId) -> CkResult<()>;
    async fn delete_rule_from_role(&self, actor: AccountId, role_id: RoleId, rule_id: RuleId) -> CkResult<()>;

    async fn rule_get(&self, rule_id: RuleId) -> CkResult<Rule>;
    async fn rule_create(&self, actor: AccountId, spec: RuleSpec, metadata: Metadata) -> CkResult<Rule>;
    async fn rule_delete(&self, actor: AccountId, id: RuleId) -> CkResult<()>;
    async fn rule_search(&self) -> CkResult<Vec<RuleListItem>>;

    async fn bind_rule_to_user(&self, actor: AccountId, rule_id: RuleId, account_id: AccountId) -> CkResult<()>;
    async fn bind_rule_to_label(&self, actor: AccountId, rule_id: RuleId, key: &str, value: &str) -> CkResult<()>;
    async fn bind_role_to_user(&self, actor: AccountId, role_id: RoleId, account_id: AccountId) -> CkResult<()>;
    async fn bind_role_to_label(&self, actor: AccountId, role_id: RoleId, key: &str, value: &str) -> CkResult<()>;

    async fn unbind_rule_from_user(&self, actor: AccountId, rule_id: RuleId, account_id: AccountId) -> CkResult<()>;
    async fn unbind_rule_from_label(&self, actor: AccountId, rule_id: RuleId, key: &str, value: &str) -> CkResult<()>;
    async fn unbind_role_from_user(&self, actor: AccountId, role_id: RoleId, account_id: AccountId) -> CkResult<()>;
    async fn unbind_role_from_label(&self, actor: AccountId, role_id: RoleId, key: &str, value: &str) -> CkResult<()>;
}

// ----------------------------------------------------------------------------------------------
pub struct SqlRbacStore {
    pool: PgPool,
}

impl SqlRbacStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl RbacStore for SqlRbacStore {
    async fn get_rules_for_account(&self, account_id: AccountId) -> CkResult<Vec<Rule>> {
        let mut tx = self.pool.begin().await?;

        let sql = one_line_sql(
            r#"
            WITH direct_rules AS (
                SELECT r.*
                FROM rbac_account_rules ar
                JOIN rbac_rules r ON r.id = ar.rule_id
                WHERE ar.account_id = $1
                  AND (ar.valid_from  IS NULL OR ar.valid_from  <= now())
                  AND (ar.valid_until IS NULL OR now() < ar.valid_until)
                  AND r.deleted_at IS NULL
            ),
            role_rules AS (
                SELECT r.*
                FROM rbac_account_roles ar
                JOIN rbac_role_rules rr ON rr.role_id = ar.role_id
                JOIN rbac_rules r ON r.id = rr.rule_id
                WHERE ar.account_id = $1
                  AND (ar.valid_from  IS NULL OR ar.valid_from  <= now())
                  AND (ar.valid_until IS NULL OR now() < ar.valid_until)
                  AND rr.removed_at IS NULL
                  AND r.deleted_at IS NULL
            )
            SELECT DISTINCT ON (id)
                id,
                short_id,
                raw_spec,
                spec_version,
                effect,
                permission,
                target_kind,
                pattern_raw,
                condition,
                metadata,
                created_at,
                created_by,
                updated_at,
                updated_by
            FROM (
                SELECT * FROM direct_rules
                UNION ALL
                SELECT * FROM role_rules
            ) all_rules
            ORDER BY id
        "#,
        );

        let rows = sqlx::query_as::<_, RuleRow>(&sql)
            .bind(account_id)
            .fetch_all(&mut *tx)
            .await?;

        tx.commit().await?;

        let rules = rows
            .into_iter()
            .map(|r| r.try_into())
            .collect::<Result<Vec<Rule>, _>>()?;

        Ok(rules)
    }

    async fn get_bindings_for_account(&self, account_id: AccountId) -> CkResult<AccountBindings> {
        let mut tx = self.pool.begin().await?;

        // Fetch role IDs bound to this account
        let role_ids: Vec<Uuid> = sqlx::query_as::<_, (RoleId,)>(&one_line_sql(
            r#"
            SELECT role_id FROM rbac_account_roles WHERE account_id = $1
        "#,
        ))
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|(id,)| id.0)
        .collect();

        // Fetch roles
        let role_rows: Vec<RoleRow> = if role_ids.is_empty() {
            vec![]
        } else {
            sqlx::query_as::<_, RoleRow>(&one_line_sql(
                r#"
                SELECT id, short_id, name, metadata, is_system, created_at, created_by, updated_at, updated_by
                FROM rbac_roles
                WHERE id = ANY($1)
                ORDER BY name
            "#,
            ))
            .bind(&role_ids)
            .fetch_all(&mut *tx)
            .await?
        };

        // Fetch role->rule bindings
        #[derive(Debug, Clone, sqlx::FromRow)]
        struct RoleRuleBindingRow {
            role_id: RoleId,
            rule_id: RuleId,
        }

        let bindings: Vec<RoleRuleBindingRow> = if role_ids.is_empty() {
            vec![]
        } else {
            sqlx::query_as(&one_line_sql(
                r#"
                SELECT role_id, rule_id FROM rbac_role_rules WHERE role_id = ANY($1)
            "#,
            ))
            .bind(&role_ids)
            .fetch_all(&mut *tx)
            .await?
        };

        let bound_rule_ids: Vec<Uuid> = bindings.iter().map(|b| b.rule_id.0).collect();

        let role_rule_rows: Vec<RuleRow> = if bound_rule_ids.is_empty() {
            vec![]
        } else {
            sqlx::query_as::<_, RuleRow>(&one_line_sql(
                r#"
                SELECT id, short_id, raw_spec, spec_version, effect, permission, target_kind, pattern_raw,
                       condition, metadata, created_at, created_by, updated_at, updated_by
                FROM rbac_rules WHERE id = ANY($1)
            "#,
            ))
            .bind(&bound_rule_ids)
            .fetch_all(&mut *tx)
            .await?
        };

        let rule_map: HashMap<RuleId, RuleRow> = role_rule_rows.into_iter().map(|r| (r.id, r)).collect();
        let mut rules_by_role: HashMap<RoleId, Vec<RuleRow>> = HashMap::new();
        for b in bindings {
            if let Some(rule) = rule_map.get(&b.rule_id) {
                rules_by_role.entry(b.role_id).or_default().push(rule.clone());
            }
        }

        let roles: CkResult<Vec<RoleWithRules>> = role_rows
            .into_iter()
            .map(|role_row| {
                let rules: CkResult<Vec<Rule>> = rules_by_role
                    .remove(&role_row.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect();
                rules.map(|rules| RoleWithRules {
                    role: Role::from(&role_row),
                    rules,
                })
            })
            .collect();

        // Fetch direct rules for this account
        let direct_rule_rows: Vec<RuleRow> = sqlx::query_as::<_, RuleRow>(&one_line_sql(
            r#"
            SELECT r.id, r.short_id, r.raw_spec, r.spec_version, r.effect, r.permission, r.target_kind,
                   r.pattern_raw, r.condition, r.metadata, r.created_at, r.created_by,
                   r.updated_at, r.updated_by
            FROM rbac_account_rules ar
            JOIN rbac_rules r ON r.id = ar.rule_id
            WHERE ar.account_id = $1
        "#,
        ))
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;

        let direct_rules: CkResult<Vec<Rule>> = direct_rule_rows.into_iter().map(TryInto::try_into).collect();

        Ok(AccountBindings {
            roles: roles?,
            direct_rules: direct_rules?,
        })
    }

    async fn list_all_account_ids(&self) -> CkResult<Vec<(AccountId, String)>> {
        let rows: Vec<(AccountId, String)> =
            sqlx::query_as("SELECT id, name FROM accounts WHERE deleted_at IS NULL ORDER BY name")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows)
    }

    async fn resolve_short_rule_id(&self, prefix: &str) -> CkResult<ResolveOne<RuleId>> {
        let sql = one_line_sql(
            r#"
            SELECT id FROM rbac_rules WHERE short_id ILIKE $1 AND deleted_at IS NULL
        "#,
        );

        let rows = sqlx::query_as::<_, (RuleId,)>(&sql)
            .bind(format!("{}%", escape_like(prefix)))
            .fetch_all(&self.pool)
            .await?;

        match rows.len() {
            0 => Ok(ResolveOne::None),
            1 => Ok(ResolveOne::One(rows[0].0)),
            n => Ok(ResolveOne::Many(Some(n))),
        }
    }

    async fn resolve_short_role_id(&self, prefix: &str) -> CkResult<ResolveOne<RoleId>> {
        let sql = one_line_sql(
            r#"
            SELECT id FROM rbac_roles WHERE short_id ILIKE $1 AND deleted_at IS NULL
        "#,
        );

        let rows = sqlx::query_as::<_, (RoleId,)>(&sql)
            .bind(format!("{}%", escape_like(prefix)))
            .fetch_all(&self.pool)
            .await?;

        match rows.len() {
            0 => Ok(ResolveOne::None),
            1 => Ok(ResolveOne::One(rows[0].0)),
            n => Ok(ResolveOne::Many(Some(n))),
        }
    }

    async fn role_create(&self, actor: AccountId, name: String, metadata: Metadata) -> CkResult<Role> {
        let role_id = RoleId::new();

        let sql = one_line_sql(
            r#"
        INSERT INTO rbac_roles (
            id, name, metadata, is_system,
            created_at, created_by, updated_at, updated_by
        ) VALUES ($1, $2, $3, false, now(), $4, NULL, NULL)
        RETURNING id, short_id, name, metadata, is_system, created_at, created_by, updated_at, updated_by
    "#,
        );

        let row = sqlx::query_as::<_, RoleRow>(&sql)
            .bind(role_id)
            .bind(name)
            .bind(metadata)
            .bind(actor)
            .fetch_one(&self.pool)
            .await?;

        Ok(Role::from(&row))
    }

    async fn role_update(&self, actor: AccountId, id: RoleId, patch: RolePatch) -> CkResult<Role> {
        let sql = one_line_sql(
            r#"
        UPDATE rbac_roles
        SET
            name = COALESCE($2, name),
            metadata = CASE WHEN $3 THEN
                CASE WHEN $4::text IS NULL THEN
                    metadata - 'description'
                ELSE
                    jsonb_set(metadata, '{description}', to_jsonb($4::text))
                END
            ELSE metadata END,
            updated_at = now(),
            updated_by = $5
        WHERE id = $1
        RETURNING id, short_id, name, metadata, is_system, created_at, created_by, updated_at, updated_by
    "#,
        );

        // description tri-state:
        // - None => don't touch
        // - Some(None) => set NULL (remove)
        // - Some(Some(v)) => set v
        let (desc_is_set, desc_value): (bool, Option<String>) = match patch.description {
            None => (false, None),
            Some(v) => (true, v),
        };

        let row = sqlx::query_as::<_, RoleRow>(&sql)
            .bind(id)
            .bind(patch.name)
            .bind(desc_is_set)
            .bind(desc_value)
            .bind(actor)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                if let sqlx::Error::Database(ref db_err) = e
                    && db_err.is_unique_violation()
                {
                    return CkError::Conflict {
                        what: "A role with that name already exists".to_string(),
                    };
                }
                CkError::from(e)
            })?
            .ok_or_else(|| CkError::from(RbacError::NotFound("Role not found")))?;

        Ok(Role::from(&row))
    }

    async fn role_delete(&self, actor: AccountId, id: RoleId) -> CkResult<()> {
        let result = sqlx::query(&one_line_sql(
            r#"
            UPDATE rbac_roles
            SET deleted_at = now(), deleted_by = $2
            WHERE id = $1 AND deleted_at IS NULL
        "#,
        ))
        .bind(id)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(RbacError::NotFound("Role not found").into());
        }

        Ok(())
    }

    async fn role_get_by_name(&self, name: &str) -> CkResult<RoleWithRules> {
        let mut tx = self.pool.begin().await?;

        let role_row = sqlx::query_as::<_, RoleRow>(&one_line_sql(
            r#"
            SELECT id, short_id, name, metadata, is_system, created_at, created_by, updated_at, updated_by
            FROM rbac_roles
            WHERE name = $1 AND deleted_at IS NULL
        "#,
        ))
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(RbacError::NotFound("Role not found"))?;

        let rule_rows = sqlx::query_as::<_, RuleRow>(&one_line_sql(
            r#"
            SELECT
                r.id,
                r.short_id,
                r.raw_spec,
                r.spec_version,
                r.effect,
                r.permission,
                r.target_kind,
                r.pattern_raw,
                r.condition,
                r.metadata,
                r.created_at,
                r.created_by,
                r.updated_at,
                r.updated_by
            FROM rbac_role_rules rr
            JOIN rbac_rules r ON r.id = rr.rule_id
            WHERE rr.role_id = $1
              AND rr.removed_at IS NULL
              AND r.deleted_at IS NULL
            ORDER BY r.permission, r.target_kind, r.id
        "#,
        ))
        .bind(role_row.id) // or id
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;

        let role = Role::from(&role_row);
        let rules: Vec<Rule> = rule_rows.into_iter().map(|r| r.try_into()).collect::<Result<_, _>>()?;

        Ok(RoleWithRules { role, rules })
    }

    async fn role_get(&self, id: RoleId) -> CkResult<RoleWithRules> {
        let mut tx = self.pool.begin().await?;

        let role_row = sqlx::query_as::<_, RoleRow>(&one_line_sql(
            r#"
            SELECT id, short_id, name, metadata, is_system, created_at, created_by, updated_at, updated_by
            FROM rbac_roles
            WHERE id = $1 AND deleted_at IS NULL
        "#,
        ))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(RbacError::NotFound("Role not found"))?;

        let rule_rows = sqlx::query_as::<_, RuleRow>(&one_line_sql(
            r#"
            SELECT
                r.id,
                r.short_id,
                r.raw_spec,
                r.spec_version,
                r.effect,
                r.permission,
                r.target_kind,
                r.pattern_raw,
                r.condition,
                r.metadata,
                r.created_at,
                r.created_by,
                r.updated_at,
                r.updated_by
            FROM rbac_role_rules rr
            JOIN rbac_rules r ON r.id = rr.rule_id
            WHERE rr.role_id = $1
              AND rr.removed_at IS NULL
              AND r.deleted_at IS NULL
            ORDER BY r.permission, r.target_kind, r.id
        "#,
        ))
        .bind(role_row.id) // or id
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;

        let role = Role::from(&role_row);
        let rules: Vec<Rule> = rule_rows.into_iter().map(|r| r.try_into()).collect::<Result<_, _>>()?;

        Ok(RoleWithRules { role, rules })
    }

    async fn role_search(&self) -> CkResult<Vec<RoleWithRules>> {
        let mut tx = self.pool.begin().await?;

        // Find all roles that matches our query (for now, we query all roles)
        let roles: Vec<RoleRow> = sqlx::query_as::<_, RoleRow>(&one_line_sql(
            r#"
            SELECT id, short_id, name, metadata, is_system, created_at, created_by, updated_at, updated_by
            FROM rbac_roles
            WHERE deleted_at IS NULL
            ORDER BY name
        "#,
        ))
        .fetch_all(&mut *tx)
        .await?;

        // Create list of role IDs that we can query in one statement
        let role_ids: Vec<Uuid> = roles.iter().map(|r| r.id.0).collect();

        // Next, fetch the "bindings". Basically, we want to fetch all the rules, BUT we need to
        // somehow know which rule belongs to which role. This information is not present in the RuleRow
        // and the only way to do that, is to add a "role_id" to the rule row, which doesn't belong in there.
        // Alternatively, we could create a duplicated RuleRow with extra role_id field, but that also does
        // not feel right. So instead, we do a separate query to fetch the bindings (role_id <-> rule_id).
        // Then we do another query to fetch all the rules for all the roles in one go, and then we
        // combine the data in Rust code.
        #[derive(Debug, Clone, sqlx::FromRow)]
        struct RoleRuleBindingRow {
            role_id: RoleId,
            rule_id: RuleId,
        }

        let bindings: Vec<RoleRuleBindingRow> = sqlx::query_as(&one_line_sql(
            r#"
            SELECT role_id, rule_id
            FROM rbac_role_rules
            WHERE role_id = ANY($1)
              AND removed_at IS NULL
        "#,
        ))
        .bind(&role_ids)
        .fetch_all(&mut *tx)
        .await?;

        let rule_ids: Vec<Uuid> = bindings.iter().map(|b| b.rule_id.0).collect();

        let rules: Vec<RuleRow> = if rule_ids.is_empty() {
            vec![]
        } else {
            sqlx::query_as::<_, RuleRow>(&one_line_sql(
                r#"
                SELECT
                    id,
                    short_id,
                    raw_spec,
                    spec_version,
                    effect,
                    permission,
                    target_kind,
                    pattern_raw,
                    condition,
                    metadata,
                    created_at,
                    created_by,
                    updated_at,
                    updated_by
                FROM rbac_rules
                WHERE id = ANY($1)
                  AND deleted_at IS NULL
            "#,
            ))
            .bind(&rule_ids)
            .fetch_all(&mut *tx)
            .await?
        };

        // Group the rules per role
        let rule_map: HashMap<RuleId, RuleRow> = rules.into_iter().map(|r| (r.id, r)).collect();

        let mut rules_by_role: HashMap<RoleId, Vec<RuleRow>> = HashMap::new();
        for b in bindings {
            if let Some(rule) = rule_map.get(&b.rule_id) {
                rules_by_role.entry(b.role_id).or_default().push(rule.clone());
            }
        }

        // Finally, create a list of role_with_rules by combining the roles and their rules.
        let out: CkResult<Vec<RoleWithRules>> = roles
            .into_iter()
            .map(|role_row| {
                let rules: CkResult<Vec<Rule>> = rules_by_role
                    .remove(&role_row.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(TryInto::try_into) // RuleRow -> Rule
                    .collect();

                rules.map(|rules| RoleWithRules {
                    role: Role::from(&role_row),
                    rules,
                })
            })
            .collect();

        tx.commit().await?;
        Ok(out?)
    }

    async fn add_rule_to_role(&self, actor: AccountId, role_id: RoleId, rule_id: RuleId) -> CkResult<()> {
        let sql = one_line_sql(
            r#"
        INSERT INTO rbac_role_rules (role_id, rule_id, created_at, created_by, removed_at, removed_by)
        VALUES ($1, $2, now(), $3, NULL, NULL)
        ON CONFLICT (role_id, rule_id) DO UPDATE
            SET removed_at = NULL, removed_by = NULL
    "#,
        );

        sqlx::query(&sql)
            .bind(role_id)
            .bind(rule_id)
            .bind(actor)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_rule_from_role(&self, actor: AccountId, role_id: RoleId, rule_id: RuleId) -> CkResult<()> {
        let result = sqlx::query(&one_line_sql(
            r#"
        UPDATE rbac_role_rules
        SET removed_at = now(), removed_by = $3
        WHERE role_id = $1 AND rule_id = $2 AND removed_at IS NULL
    "#,
        ))
        .bind(role_id)
        .bind(rule_id)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(RbacError::NotFound("Rule not found in role").into());
        }

        Ok(())
    }

    async fn rule_get(&self, rule_id: RuleId) -> CkResult<Rule> {
        let row = sqlx::query_as::<_, RuleRow>(&one_line_sql(
            r#"
            SELECT
                id,
                short_id,
                raw_spec,
                spec_version,
                effect,
                permission,
                target_kind,
                pattern_raw,
                condition,
                metadata,
                created_at,
                created_by,
                updated_at,
                updated_by
            FROM rbac_rules
            WHERE id = $1 AND deleted_at IS NULL
        "#,
        ))
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RbacError::NotFound("Rule not found"))?;

        Ok(row.try_into()?)
    }

    async fn rule_create(&self, actor: AccountId, spec: RuleSpec, metadata: Metadata) -> CkResult<Rule> {
        let rule_id = RuleId::new();

        let condition_json: Option<serde_json::Value> = match &spec.condition {
            None => None,
            Some(expr) => Some(serde_json::to_value(expr)?),
        };

        let insert_sql = one_line_sql(
            r#"
        INSERT INTO rbac_rules (
            id, raw_spec, spec_version, effect,
            permission, target_kind, pattern_raw, condition, metadata,
            created_at, created_by, updated_at, updated_by
        ) VALUES (
            $1, $2, 1, $3,
            $4, $5, $6, $7, $8,
            now(), $9, NULL, NULL
        )
        RETURNING
            id, short_id, raw_spec, spec_version, effect, permission, target_kind, pattern_raw,
            condition, metadata, created_at, created_by, updated_at, updated_by
    "#,
        );

        let row = sqlx::query_as::<_, RuleRow>(&insert_sql)
            .bind(rule_id)
            .bind(spec.to_string())
            .bind(spec.effect)
            .bind(spec.permission.to_string())
            .bind(spec.target.kind())
            .bind(spec.target.pattern())
            .bind(condition_json)
            .bind(metadata)
            .bind(actor)
            .fetch_one(&self.pool)
            .await?;

        Ok(row.try_into()?)
    }

    async fn rule_delete(&self, actor: AccountId, id: RuleId) -> CkResult<()> {
        let result = sqlx::query(&one_line_sql(
            r#"
        UPDATE rbac_rules
        SET deleted_at = now(), deleted_by = $2
        WHERE id = $1 AND deleted_at IS NULL
    "#,
        ))
        .bind(id)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(RbacError::NotFound("Rule not found").into());
        }

        Ok(())
    }

    async fn rule_search(&self) -> CkResult<Vec<RuleListItem>> {
        // We need to fetch all rules from rbac_rules
        // and do a count of how often that rbac_rule is inside rbac_role_rules
        // and do a count of how often that rbac_rule is inside rbac_account_rules
        let sql = one_line_sql(
            r#"
            SELECT
                r.id,
                r.short_id,
                r.raw_spec,
                r.spec_version,
                r.effect,
                r.permission,
                r.target_kind,
                r.pattern_raw,
                r.condition,
                r.metadata,
                r.created_at,
                r.created_by,
                r.updated_at,
                r.updated_by,
                (SELECT COUNT(*) FROM rbac_role_rules rr WHERE rr.rule_id = r.id AND rr.removed_at IS NULL) AS role_count,
                (SELECT COUNT(*) FROM rbac_account_rules ar WHERE ar.rule_id = r.id) AS account_count
            FROM rbac_rules r
            WHERE r.deleted_at IS NULL
            ORDER BY r.created_at DESC
        "#,
        );

        let rows: Vec<RuleListRow> = sqlx::query_as::<_, RuleListRow>(&sql).fetch_all(&self.pool).await?;

        let items = rows
            .into_iter()
            .map(|row| {
                let rc = row.role_count as usize;
                let ac = row.account_count as usize;

                let rule: Rule = row
                    .try_into()
                    .map_err(|e| RbacError::Validation(format!("Failed to convert RuleRow to Rule: {e}")))?;
                Ok(RuleListItem {
                    rule,
                    role_count: rc,
                    account_count: ac,
                })
            })
            .collect::<Result<Vec<RuleListItem>, RbacError>>()?;

        Ok(items)
    }

    async fn bind_rule_to_user(&self, actor: AccountId, rule_id: RuleId, account_id: AccountId) -> CkResult<()> {
        // we need to add the role to rbac_account_rule table
        let sql = one_line_sql(
            r#"
            INSERT INTO rbac_account_rules (account_id, rule_id, created_at, created_by)
            VALUES ($1, $2, now(), $3)
            ON CONFLICT (account_id, rule_id) DO NOTHING
        "#,
        );

        sqlx::query(&sql)
            .bind(account_id)
            .bind(rule_id)
            .bind(actor)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn bind_rule_to_label(&self, actor: AccountId, rule_id: RuleId, key: &str, value: &str) -> CkResult<()> {
        let sql = one_line_sql(
            r#"
            INSERT INTO rbac_label_rules (rule_id, label_key, label_value, created_at, created_by)
            VALUES ($1, $2, $3, now(), $4)
            ON CONFLICT (rule_id, label_key, label_value) DO NOTHING
        "#,
        );

        sqlx::query(&sql)
            .bind(rule_id)
            .bind(key)
            .bind(value)
            .bind(actor)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn bind_role_to_user(&self, actor: AccountId, role_id: RoleId, account_id: AccountId) -> CkResult<()> {
        // we need to add the role to rbac_account_role table
        let sql = one_line_sql(
            r#"
            INSERT INTO rbac_account_roles (account_id, role_id, created_at, created_by)
            VALUES ($1, $2, now(), $3)
            ON CONFLICT (account_id, role_id) DO NOTHING
        "#,
        );

        sqlx::query(&sql)
            .bind(account_id)
            .bind(role_id)
            .bind(actor)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn bind_role_to_label(&self, actor: AccountId, role_id: RoleId, key: &str, value: &str) -> CkResult<()> {
        let sql = one_line_sql(
            r#"
            INSERT INTO rbac_label_roles (role_id, label_key, label_value, created_at, created_by)
            VALUES ($1, $2, $3, now(), $4)
            ON CONFLICT (role_id, label_key, label_value) DO NOTHING
        "#,
        );

        sqlx::query(&sql)
            .bind(role_id)
            .bind(key)
            .bind(value)
            .bind(actor)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn unbind_rule_from_user(&self, _actor: AccountId, rule_id: RuleId, account_id: AccountId) -> CkResult<()> {
        let sql = one_line_sql("DELETE FROM rbac_account_rules WHERE account_id = $1 AND rule_id = $2");
        sqlx::query(&sql)
            .bind(account_id)
            .bind(rule_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn unbind_rule_from_label(&self, _actor: AccountId, rule_id: RuleId, key: &str, value: &str) -> CkResult<()> {
        let sql =
            one_line_sql("DELETE FROM rbac_label_rules WHERE rule_id = $1 AND label_key = $2 AND label_value = $3");
        sqlx::query(&sql)
            .bind(rule_id)
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn unbind_role_from_user(&self, _actor: AccountId, role_id: RoleId, account_id: AccountId) -> CkResult<()> {
        let sql = one_line_sql("DELETE FROM rbac_account_roles WHERE account_id = $1 AND role_id = $2");
        sqlx::query(&sql)
            .bind(account_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn unbind_role_from_label(&self, _actor: AccountId, role_id: RoleId, key: &str, value: &str) -> CkResult<()> {
        let sql =
            one_line_sql("DELETE FROM rbac_label_roles WHERE role_id = $1 AND label_key = $2 AND label_value = $3");
        sqlx::query(&sql)
            .bind(role_id)
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ----------------------------------------------------------------------------------------------

#[cfg(test)]
pub struct InMemoryRbacStore {
    roles: Mutex<HashMap<RoleId, RoleRow>>,                  // Just the roles
    rules: Mutex<HashMap<RuleId, Rule>>,                     // Just the rules
    roles_with_rules: Mutex<HashMap<RoleId, RoleWithRules>>, // Join table for roles x rules
    actor_roles: Mutex<HashMap<AccountId, Vec<RoleId>>>,     // Actor to roles
    actor_rules: Mutex<HashMap<AccountId, Vec<RuleId>>>,     // Actor to rules
}

#[cfg(test)]
impl Default for InMemoryRbacStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl InMemoryRbacStore {
    pub fn new() -> Self {
        InMemoryRbacStore {
            roles: Mutex::new(HashMap::new()),
            rules: Mutex::new(HashMap::new()),
            roles_with_rules: Mutex::new(HashMap::new()),
            actor_roles: Mutex::new(HashMap::new()),
            actor_rules: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl RbacStore for InMemoryRbacStore {
    async fn get_rules_for_account(&self, account_id: AccountId) -> CkResult<Vec<Rule>> {
        let mut result = Vec::new();

        let actor_rules = self.actor_rules.lock();
        let rules = self.rules.lock();
        for rule_id in actor_rules.get(&account_id).unwrap_or(&Vec::new()) {
            if let Some(rule) = rules.get(rule_id) {
                result.push(rule.clone());
            }
        }
        drop(actor_rules);

        let actor_roles = self.actor_roles.lock();
        let roles_with_rules = self.roles_with_rules.lock();
        for role_id in actor_roles.get(&account_id).unwrap_or(&Vec::new()) {
            if let Some(entity) = roles_with_rules.get(role_id) {
                for rule in &entity.rules {
                    result.push(rule.clone());
                }
            }
        }
        drop(actor_roles);

        Ok(result)
    }

    async fn get_bindings_for_account(&self, account_id: AccountId) -> CkResult<AccountBindings> {
        let actor_roles = self.actor_roles.lock();
        let roles_with_rules = self.roles_with_rules.lock();
        let mut roles = Vec::new();
        for role_id in actor_roles.get(&account_id).unwrap_or(&Vec::new()) {
            if let Some(rwr) = roles_with_rules.get(role_id) {
                roles.push(rwr.clone());
            }
        }
        drop(actor_roles);
        drop(roles_with_rules);

        let actor_rules = self.actor_rules.lock();
        let rules_store = self.rules.lock();
        let mut direct_rules = Vec::new();
        for rule_id in actor_rules.get(&account_id).unwrap_or(&Vec::new()) {
            if let Some(rule) = rules_store.get(rule_id) {
                direct_rules.push(rule.clone());
            }
        }
        drop(actor_rules);
        drop(rules_store);

        Ok(AccountBindings { roles, direct_rules })
    }

    async fn list_all_account_ids(&self) -> CkResult<Vec<(AccountId, String)>> {
        let mut ids: std::collections::HashSet<AccountId> = std::collections::HashSet::new();
        ids.extend(self.actor_roles.lock().keys().cloned());
        ids.extend(self.actor_rules.lock().keys().cloned());
        Ok(ids.into_iter().map(|id| (id, id.to_string())).collect())
    }

    async fn resolve_short_rule_id(&self, _prefix: &str) -> CkResult<ResolveOne<RuleId>> {
        Ok(ResolveOne::None)
    }

    async fn resolve_short_role_id(&self, _prefix: &str) -> CkResult<ResolveOne<RoleId>> {
        Ok(ResolveOne::None)
    }

    async fn role_create(&self, actor: AccountId, name: String, metadata: Metadata) -> CkResult<Role> {
        let role = RoleRow {
            id: RoleId::new(),
            short_id: crate::global::short_id::ShortId::generate("rol_", 12),
            name,
            metadata,
            is_system: false,
            created_at: Utc::now(),
            created_by: actor,
            updated_at: None,
            updated_by: None,
        };

        let role_ref = Role::from(&role);
        self.roles.lock().insert(role.id, role.clone());
        // Also seed roles_with_rules so role_get / add_rule_to_role work immediately.
        self.roles_with_rules.lock().insert(
            role.id,
            RoleWithRules {
                role: role_ref.clone(),
                rules: vec![],
            },
        );

        Ok(role_ref)
    }

    async fn role_update(&self, actor: AccountId, id: RoleId, patch_req: RolePatch) -> CkResult<Role> {
        let mut roles = self.roles.lock();
        let role_row = roles.get_mut(&id).ok_or(RbacError::NotFound("Role not found"))?;

        if let Some(name) = patch_req.name {
            role_row.name = name;
        }
        if let Some(description_opt) = patch_req.description {
            match description_opt {
                None => role_row.metadata.clear_description(),
                Some(desc) => role_row.metadata.add_description(&desc),
            }
        }
        role_row.updated_at = Some(Utc::now());
        role_row.updated_by = Some(actor);

        Ok(Role::from(&*role_row))
    }

    async fn role_delete(&self, _actor: AccountId, id: RoleId) -> CkResult<()> {
        let removed = self.roles.lock().remove(&id);
        if removed.is_none() {
            return Err(RbacError::NotFound("Role not found").into());
        }
        self.roles_with_rules.lock().remove(&id);
        Ok(())
    }

    async fn role_get_by_name(&self, name: &str) -> CkResult<RoleWithRules> {
        let roles_with_rules = self.roles_with_rules.lock();
        roles_with_rules
            .values()
            .find(|r| r.role.name == name)
            .cloned()
            .ok_or(RbacError::NotFound("Role not found").into())
    }

    async fn role_get(&self, id: RoleId) -> CkResult<RoleWithRules> {
        let roles_with_rules = self.roles_with_rules.lock();
        roles_with_rules
            .get(&id)
            .cloned()
            .ok_or(RbacError::NotFound("Role not found").into())
    }

    async fn role_search(&self) -> CkResult<Vec<RoleWithRules>> {
        let roles_with_rules = self.roles_with_rules.lock();
        Ok(roles_with_rules.values().cloned().collect())
    }

    async fn add_rule_to_role(&self, _actor: AccountId, role_id: RoleId, rule_id: RuleId) -> CkResult<()> {
        let mut roles_with_rules = self.roles_with_rules.lock();
        let Some(entity) = roles_with_rules.get_mut(&role_id) else {
            return Err(RbacError::NotFound("Role not found").into());
        };

        let rules = self.rules.lock();
        if let Some(rule) = rules.get(&rule_id) {
            // Make sure the rule does not exist already
            if entity.rules.iter().any(|r| r.id == rule_id) {
                return Ok(());
            }
            entity.rules.push(rule.clone());
        }

        Ok(())
    }

    async fn delete_rule_from_role(&self, _actor: AccountId, role_id: RoleId, rule_id: RuleId) -> CkResult<()> {
        let mut roles_with_rules = self.roles_with_rules.lock();
        if let Some(role_with_rules) = roles_with_rules.get_mut(&role_id) {
            role_with_rules.rules.retain(|r| r.id != rule_id);
        }
        Ok(())
    }

    async fn rule_get(&self, rule_id: RuleId) -> CkResult<Rule> {
        let rules = self.rules.lock();
        let rule = rules.get(&rule_id).ok_or(RbacError::NotFound("Rule not found"))?;
        Ok(rule.clone())
    }

    async fn rule_create(&self, actor: AccountId, spec: RuleSpec, metadata: Metadata) -> CkResult<Rule> {
        let new_rule = Rule {
            id: RuleId::new(),
            short_id: crate::global::short_id::ShortId::generate("rul_", 12),
            spec: spec.clone(),
            metadata,
            created_at: Utc::now(),
            created_by: actor,
            updated_at: None,
            updated_by: None,
        };

        let mut rules = self.rules.lock();
        rules.insert(new_rule.id, new_rule.clone());
        Ok(new_rule)
    }

    async fn rule_delete(&self, _actor: AccountId, id: RuleId) -> CkResult<()> {
        let mut rules = self.rules.lock();
        rules.remove(&id).ok_or(RbacError::NotFound("Rule not found"))?;
        Ok(())
    }

    async fn rule_search(&self) -> CkResult<Vec<RuleListItem>> {
        Ok(Vec::new())
    }

    async fn bind_rule_to_user(&self, _actor: AccountId, rule_id: RuleId, account_id: AccountId) -> CkResult<()> {
        let mut actor_rules = self.actor_rules.lock();
        let rules = actor_rules.entry(account_id).or_default();
        if !rules.contains(&rule_id) {
            rules.push(rule_id);
        }
        Ok(())
    }

    async fn bind_rule_to_label(&self, _actor: AccountId, _rule_id: RuleId, _key: &str, _value: &str) -> CkResult<()> {
        Ok(())
    }

    async fn bind_role_to_user(&self, _actor: AccountId, role_id: RoleId, account_id: AccountId) -> CkResult<()> {
        let mut actor_roles = self.actor_roles.lock();
        let roles = actor_roles.entry(account_id).or_default();
        if !roles.contains(&role_id) {
            roles.push(role_id);
        }
        Ok(())
    }

    async fn bind_role_to_label(&self, _actor: AccountId, _role_id: RoleId, _key: &str, _value: &str) -> CkResult<()> {
        Ok(())
    }

    async fn unbind_rule_from_user(&self, _actor: AccountId, rule_id: RuleId, account_id: AccountId) -> CkResult<()> {
        let mut actor_rules = self.actor_rules.lock();
        if let Some(rules) = actor_rules.get_mut(&account_id) {
            rules.retain(|r| r != &rule_id);
        }
        Ok(())
    }

    async fn unbind_rule_from_label(
        &self,
        _actor: AccountId,
        _rule_id: RuleId,
        _key: &str,
        _value: &str,
    ) -> CkResult<()> {
        Ok(())
    }

    async fn unbind_role_from_user(&self, _actor: AccountId, role_id: RoleId, account_id: AccountId) -> CkResult<()> {
        let mut actor_roles = self.actor_roles.lock();
        if let Some(roles) = actor_roles.get_mut(&account_id) {
            roles.retain(|r| r != &role_id);
        }
        Ok(())
    }

    async fn unbind_role_from_label(
        &self,
        _actor: AccountId,
        _role_id: RoleId,
        _key: &str,
        _value: &str,
    ) -> CkResult<()> {
        Ok(())
    }
}

// ----------------------------------------------------------------------------------------------

pub struct RbacManager {
    store: Arc<dyn RbacStore + Send + Sync>,
    cache: Arc<cache::RbacCache>,
}

impl RbacManager {
    pub fn new(store: Arc<dyn RbacStore + Send + Sync>) -> Self {
        RbacManager {
            store,
            cache: cache::RbacCache::new(cache::DEFAULT_TTL, cache::DEFAULT_MAX_SIZE),
        }
    }

    pub async fn get_bindings_for_account(&self, account_id: AccountId) -> CkResult<AccountBindings> {
        self.store.get_bindings_for_account(account_id).await
    }

    pub async fn list_all_account_ids(&self) -> CkResult<Vec<(AccountId, String)>> {
        self.store.list_all_account_ids().await
    }

    pub async fn is_allowed(&self, request: RbacAllowedRequest) -> CkResult<RbacAllowedResponse> {
        let rules: Vec<Rule> = match self.cache.get(request.subject) {
            Some(cached) => cached,
            None => {
                let rules = self.store.get_rules_for_account(request.subject).await?;
                self.cache.insert(request.subject, rules.clone());
                rules
            }
        };

        trace!(
            account_id = %request.subject,
            permission = %request.permission,
            resource = %request.resource,
            total_rules = rules.len(),
            "rbac eval: fetched rules for account"
        );

        let mut matching: Vec<(&Rule, u32)> = rules
            .iter()
            .filter(|r| r.spec.permission.grants(request.permission))
            .filter(|r| r.spec.target.matches_request(&request.resource))
            .filter(|r| r.spec.condition.as_ref().is_none_or(|c| c.evaluate(&request.resource_labels)))
            .map(|r| (r, r.spec.target.specificity_score()))
            .collect();

        if matching.is_empty() {
            trace!(
                account_id = %request.subject,
                permission = %request.permission,
                resource = %request.resource,
                "rbac eval: no matching rules — denied"
            );
            return Ok(RbacAllowedResponse {
                allowed: false,
                matched_rule: None,
            });
        }

        let best = matching.iter().map(|(_, s)| *s).max().unwrap_or(0);
        matching.retain(|(_, s)| *s == best);

        trace!(
            account_id = %request.subject,
            permission = %request.permission,
            resource = %request.resource,
            candidate_count = matching.len(),
            best_specificity = best,
            "rbac eval: candidates after specificity filter"
        );

        if let Some((r, _)) = matching.iter().find(|(r, _)| r.spec.effect == PolicyEffect::Deny) {
            trace!(
                account_id = %request.subject,
                permission = %request.permission,
                resource = %request.resource,
                winning_rule = %r.id,
                "rbac eval: deny rule wins"
            );
            return Ok(RbacAllowedResponse {
                allowed: false,
                matched_rule: Some(r.id),
            });
        }

        if let Some((r, _)) = matching.iter().find(|(r, _)| r.spec.effect == PolicyEffect::Allow) {
            trace!(
                account_id = %request.subject,
                permission = %request.permission,
                resource = %request.resource,
                winning_rule = %r.id,
                "rbac eval: allow rule wins"
            );
            return Ok(RbacAllowedResponse {
                allowed: true,
                matched_rule: Some(r.id),
            });
        }

        trace!(
            account_id = %request.subject,
            permission = %request.permission,
            resource = %request.resource,
            "rbac eval: no allow or deny at best specificity — denied"
        );
        Ok(RbacAllowedResponse {
            allowed: false,
            matched_rule: None,
        })
    }

    pub async fn explain(&self, request: RbacAllowedRequest, verbose: bool) -> CkResult<RbacExplainResponse> {
        let rules = match self.cache.get(request.subject) {
            Some(cached) => cached,
            None => {
                let rules = self.store.get_rules_for_account(request.subject).await?;
                self.cache.insert(request.subject, rules.clone());
                rules
            }
        };

        let mut near_misses = Vec::new();
        let mut matching: Vec<(&Rule, u32)> = vec![];

        for rule in &rules {
            let perm_match = rule.spec.permission.grants(request.permission);
            let target_match = rule.spec.target.matches_request(&request.resource);
            let cond_match = rule.spec.condition.as_ref().is_none_or(|c| c.evaluate(&request.resource_labels));

            if perm_match && target_match && cond_match {
                matching.push((rule, rule.spec.target.specificity_score()));
            } else if verbose {
                let reason = if !perm_match {
                    NearMissReason::PermissionMismatch
                } else if !target_match {
                    NearMissReason::TargetMismatch
                } else {
                    NearMissReason::ConditionMismatch
                };
                near_misses.push(RbacNearMiss {
                    rule: rule.clone(),
                    reason,
                });
            }
        }

        if matching.is_empty() {
            return Ok(RbacExplainResponse {
                allowed: false,
                matched_rule: None,
                near_misses,
            });
        }

        let best = matching.iter().map(|(_, s)| *s).max().unwrap_or(0);

        if verbose {
            for (r, s) in &matching {
                if *s < best {
                    near_misses.push(RbacNearMiss {
                        rule: (*r).clone(),
                        reason: NearMissReason::LostToHigherSpecificity,
                    });
                }
            }
        }

        let candidates: Vec<_> = matching.iter().filter(|(_, s)| *s == best).collect();

        if let Some((r, _)) = candidates.iter().find(|(r, _)| r.spec.effect == PolicyEffect::Deny) {
            return Ok(RbacExplainResponse {
                allowed: false,
                matched_rule: Some((*r).clone()),
                near_misses,
            });
        }
        if let Some((r, _)) = candidates.iter().find(|(r, _)| r.spec.effect == PolicyEffect::Allow) {
            return Ok(RbacExplainResponse {
                allowed: true,
                matched_rule: Some((*r).clone()),
                near_misses,
            });
        }

        Ok(RbacExplainResponse {
            allowed: false,
            matched_rule: None,
            near_misses,
        })
    }

    // ----------------------------------------------------------------------------------------

    pub async fn resolve_short_rule_id(&self, prefix: &str) -> CkResult<ResolveOne<RuleId>> {
        self.store.resolve_short_rule_id(prefix).await
    }

    // ----------------------------------------------------------------------------------------

    pub async fn role_create(&self, ctx: &CallContext, name: String, metadata: Metadata) -> CkResult<Role> {
        let actor = ctx.actor.require_account_id().copied()?;
        self.store.role_create(actor, name, metadata).await
    }

    pub async fn role_update(
        &self,
        ctx: &CallContext,
        role_id: RoleId,
        name: Option<String>,
        description: Option<String>,
    ) -> CkResult<Role> {
        let actor = ctx.actor.require_account_id().copied()?;
        let patch = RolePatch {
            name,
            description: Some(description),
        };

        self.store.role_update(actor, role_id, patch).await
    }

    pub async fn role_delete(&self, ctx: &CallContext, role_id: RoleId) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.role_delete(actor, role_id).await;
        if result.is_ok() {
            self.cache.invalidate_all();
        }
        result
    }

    pub async fn role_get(&self, role_id: RoleId) -> CkResult<RoleWithRules> {
        self.store.role_get(role_id).await
    }

    pub async fn role_get_by_name(&self, role_name: &str) -> CkResult<RoleWithRules> {
        self.store.role_get_by_name(role_name).await
    }

    pub async fn role_search(&self) -> CkResult<Vec<RoleWithRules>> {
        self.store.role_search().await
    }

    pub async fn role_add_rule(&self, ctx: &CallContext, role_id: RoleId, rule_id: RuleId) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.add_rule_to_role(actor, role_id, rule_id).await;
        if result.is_ok() {
            self.cache.invalidate_all();
        }
        result
    }

    pub async fn role_remove_rule(&self, ctx: &CallContext, role_id: RoleId, rule_id: RuleId) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.delete_rule_from_role(actor, role_id, rule_id).await;
        if result.is_ok() {
            self.cache.invalidate_all();
        }
        result
    }

    // ----------------------------------------------------------------------------------------

    pub async fn rule_create(&self, ctx: &CallContext, spec: RuleSpec, metadata: Metadata) -> CkResult<Rule> {
        let actor = ctx.actor.require_account_id().copied()?;
        self.store.rule_create(actor, spec, metadata).await
    }

    pub async fn rule_delete(&self, ctx: &CallContext, rule_id: RuleId) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.rule_delete(actor, rule_id).await;
        if result.is_ok() {
            self.cache.invalidate_all();
        }
        result
    }

    pub async fn rule_get(&self, rule_id: RuleId) -> CkResult<Rule> {
        self.store.rule_get(rule_id).await
    }

    pub async fn rule_search(&self) -> CkResult<Vec<RuleListItem>> {
        self.store.rule_search().await
    }

    // ----------------------------------------------------------------------------------------

    pub async fn bind_rule_to_user(&self, ctx: &CallContext, rule_id: RuleId, account_id: AccountId) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.bind_rule_to_user(actor, rule_id, account_id).await;
        if result.is_ok() {
            self.cache.invalidate(account_id);
        }
        result
    }

    pub async fn bind_rule_to_label(&self, ctx: &CallContext, rule_id: RuleId, key: &str, value: &str) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.bind_rule_to_label(actor, rule_id, key, value).await;
        if result.is_ok() {
            self.cache.invalidate_all();
        }
        result
    }

    pub async fn bind_role_to_user(&self, ctx: &CallContext, role_id: RoleId, account_id: AccountId) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.bind_role_to_user(actor, role_id, account_id).await;
        if result.is_ok() {
            self.cache.invalidate(account_id);
        }
        result
    }

    pub async fn bind_role_to_label(&self, ctx: &CallContext, role_id: RoleId, key: &str, value: &str) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.bind_role_to_label(actor, role_id, key, value).await;
        if result.is_ok() {
            self.cache.invalidate_all();
        }
        result
    }

    pub async fn unbind_rule_from_user(
        &self,
        ctx: &CallContext,
        rule_id: RuleId,
        account_id: AccountId,
    ) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.unbind_rule_from_user(actor, rule_id, account_id).await;
        if result.is_ok() {
            self.cache.invalidate(account_id);
        }
        result
    }

    pub async fn unbind_rule_from_label(
        &self,
        ctx: &CallContext,
        rule_id: RuleId,
        key: &str,
        value: &str,
    ) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.unbind_rule_from_label(actor, rule_id, key, value).await;
        if result.is_ok() {
            self.cache.invalidate_all();
        }
        result
    }

    pub async fn unbind_role_from_user(
        &self,
        ctx: &CallContext,
        role_id: RoleId,
        account_id: AccountId,
    ) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.unbind_role_from_user(actor, role_id, account_id).await;
        if result.is_ok() {
            self.cache.invalidate(account_id);
        }
        result
    }

    pub async fn unbind_role_from_label(
        &self,
        ctx: &CallContext,
        role_id: RoleId,
        key: &str,
        value: &str,
    ) -> CkResult<()> {
        let actor = ctx.actor.require_account_id().copied()?;
        let result = self.store.unbind_role_from_label(actor, role_id, key, value).await;
        if result.is_ok() {
            self.cache.invalidate_all();
        }
        result
    }
}
