// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::one_line_sql;
use hierarkey_core::CkResult;
use sqlx::PgPool;

pub const MIGRATIONS: &[(&str, &str)] = &[
    ("0000_setup", include_str!("../migrations/0000_setup.sql")),
    ("0010_account", include_str!("../migrations/0010_account.sql")),
    ("0020_masterkey", include_str!("../migrations/0020_masterkey.sql")),
    ("0030_kek", include_str!("../migrations/0030_kek.sql")),
    ("0031_namespace", include_str!("../migrations/0031_namespace.sql")),
    ("0032_namespace_kek", include_str!("../migrations/0032_namespace_kek.sql")),
    ("0040_tokens", include_str!("../migrations/0040_tokens.sql")),
    (
        "0040_token_scope_refresh",
        include_str!("../migrations/0041_token_scope_refresh.sql"),
    ),
    ("0050_secrets", include_str!("../migrations/0050_secrets.sql")),
    ("0051_secret_revisions", include_str!("../migrations/0051_secret_revisions.sql")),
    ("0060_rbac", include_str!("../migrations/0060_rbac.sql")),
    ("0061_rbac_roles", include_str!("../migrations/0061_rbac_roles.sql")),
    ("0062_rbac_rules", include_str!("../migrations/0062_rbac_rules.sql")),
    ("0063_rbac_role_rules", include_str!("../migrations/0063_rbac_role_rules.sql")),
    (
        "0064_rbac_account_rules",
        include_str!("../migrations/0064_rbac_account_rules.sql"),
    ),
    (
        "0065_rbac_account_roles",
        include_str!("../migrations/0065_rbac_account_roles.sql"),
    ),
    ("0066_rbac_population", include_str!("../migrations/0066_rbac_population.sql")),
    (
        "0067_rbac_platform_target",
        include_str!("../migrations/0067_rbac_platform_target.sql"),
    ),
    (
        "0070_brute_force_lockout",
        include_str!("../migrations/0070_brute_force_lockout.sql"),
    ),
    ("0071_rbac_soft_delete", include_str!("../migrations/0071_rbac_soft_delete.sql")),
    ("0072_pat_client_ip", include_str!("../migrations/0072_pat_client_ip.sql")),
    (
        "0073_masterkey_draining",
        include_str!("../migrations/0073_masterkey_draining.sql"),
    ),
    (
        "0074_masterkey_pending",
        include_str!("../migrations/0074_masterkey_pending.sql"),
    ),
    (
        "0075_rename_token_scope_to_purpose",
        include_str!("../migrations/0075_rename_token_scope_to_purpose.sql"),
    ),
    (
        "0076_rename_destroyed_to_deleted",
        include_str!("../migrations/0076_rename_destroyed_to_deleted.sql"),
    ),
    (
        "0077_fix_namespace_unique_index",
        include_str!("../migrations/0077_fix_namespace_unique_index.sql"),
    ),
    ("0078_platform_license", include_str!("../migrations/0078_platform_license.sql")),
    (
        "0079_account_client_cert",
        include_str!("../migrations/0079_account_client_cert.sql"),
    ),
    ("0080_mfa_backup_codes", include_str!("../migrations/0080_mfa_backup_codes.sql")),
    ("0081_audit_events", include_str!("../migrations/0081_audit_events.sql")),
    (
        "0082_secrets_partial_unique",
        include_str!("../migrations/0082_secrets_partial_unique.sql"),
    ),
    (
        "0083_secret_created_updated_by",
        include_str!("../migrations/0083_secret_created_updated_by.sql"),
    ),
    (
        "0084_federated_identities",
        include_str!("../migrations/0084_federated_identities.sql"),
    ),
    (
        "0085_namespace_created_updated_by",
        include_str!("../migrations/0085_namespace_created_updated_by.sql"),
    ),
    ("0086_signing_key", include_str!("../migrations/0086_signing_key.sql")),
    ("0087_row_hmac_columns", include_str!("../migrations/0087_row_hmac_columns.sql")),
    (
        "0088_account_status_tampered",
        include_str!("../migrations/0088_account_status_tampered.sql"),
    ),
    (
        "0089_rbac_role_rules_hmac",
        include_str!("../migrations/0089_rbac_role_rules_hmac.sql"),
    ),
    ("0090_pat_hmac", include_str!("../migrations/0090_pat_hmac.sql")),
    ("0091_auth_nonces", include_str!("../migrations/0091_auth_nonces.sql")),
];

/// Returns true if a migration must run outside a transaction.
/// This is required for `ALTER TYPE ... ADD VALUE` statements, which PostgreSQL
/// does not allow inside a transaction block.
fn needs_no_txn(sql: &str) -> bool {
    sql.lines().any(|l| {
        let l = l.trim().to_ascii_uppercase();
        l.starts_with("ALTER TYPE") && l.contains("ADD VALUE")
    })
}

pub async fn run_migrations(pool: &PgPool) -> CkResult<()> {
    // Create migrations table if not exists
    sqlx::query(&one_line_sql(
        r#"
        CREATE TABLE IF NOT EXISTS _hierarkey_migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    ))
    .execute(pool)
    .await?;

    // Get applied migrations
    let applied: Vec<String> = sqlx::query_scalar("SELECT name FROM _hierarkey_migrations ORDER BY name")
        .fetch_all(pool)
        .await?;

    // Run pending migrations
    for (name, sql) in MIGRATIONS {
        if !applied.contains(&name.to_string()) {
            println!("Applying migration: {name}");

            if needs_no_txn(sql) {
                // Run migration outside a transaction (required for ALTER TYPE ... ADD VALUE).
                sqlx::raw_sql(sql).execute(pool).await?;
                sqlx::query("INSERT INTO _hierarkey_migrations (name) VALUES ($1)")
                    .bind(name)
                    .execute(pool)
                    .await?;
            } else {
                let mut tx = pool.begin().await?;

                // Run migration. We use Raw SQL execution here because we have multiple statements
                // within each SQL script. The scripts are never user-provided, so this is safe.
                sqlx::raw_sql(sql).execute(&mut *tx).await?;

                // Record migration
                sqlx::query("INSERT INTO _hierarkey_migrations (name) VALUES ($1)")
                    .bind(name)
                    .execute(&mut *tx)
                    .await?;

                tx.commit().await?;
            }
        }
    }

    println!("All migrations applied.");

    Ok(())
}

pub async fn check_migrations(pool: &PgPool) -> CkResult<Vec<String>> {
    let applied: Vec<String> = sqlx::query_scalar("SELECT name FROM _hierarkey_migrations ORDER BY name")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let pending: Vec<_> = MIGRATIONS
        .iter()
        .filter(|(name, _)| !applied.contains(&name.to_string()))
        .collect();

    Ok(pending.iter().map(|(name, _)| name.to_string()).collect())
}
