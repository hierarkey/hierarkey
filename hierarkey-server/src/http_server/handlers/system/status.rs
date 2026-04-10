// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::handlers::ApiResult;
use crate::rbac::{Permission, RbacResource};
use axum::extract::State;
use axum::{Extension, Json};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatusDto {
    pub namespaces: NamespaceStats,
    pub secrets: SecretStats,
    pub accounts: AccountStats,
    pub masterkeys: MasterKeyStats,
    pub keks: KekStats,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NamespaceStats {
    pub total: i64,
    pub active: i64,
    pub disabled: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretStats {
    /// Total secrets (not deleted)
    pub total: i64,
    /// Active secrets (status = active, not deleted)
    pub active: i64,
    /// Secrets whose active revision uses a stale KEK (not the namespace's current active KEK)
    pub stale_kek: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountStats {
    pub users: i64,
    pub users_active: i64,
    pub service_accounts: i64,
    pub service_accounts_active: i64,
    pub admins: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MasterKeyStats {
    pub total: i64,
    pub active: i64,
    pub retired: i64,
    pub locked: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KekStats {
    /// Total KEKs (not deleted)
    pub total: i64,
    /// KEKs wrapped by a non-active master key (need re-wrapping)
    pub stale_masterkey: i64,
}

#[axum::debug_handler]
pub async fn system_status(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
) -> ApiResult<Json<ApiResponse<SystemStatusDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SystemStatusFailed,
    };

    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let pool = &state.pool;

    let (ns_total, ns_active, ns_disabled): (i64, i64, i64) = sqlx::query_as(
        "SELECT \
            COUNT(*) FILTER (WHERE deleted_at IS NULL), \
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND status = 'active'), \
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND status = 'disabled') \
         FROM namespaces",
    )
    .fetch_one(pool)
    .await
    .ctx(ctx)?;

    let (secrets_total, secrets_active): (i64, i64) = sqlx::query_as(
        "SELECT \
            COUNT(*) FILTER (WHERE deleted_at IS NULL), \
            COUNT(*) FILTER (WHERE deleted_at IS NULL AND status = 'active') \
         FROM secrets",
    )
    .fetch_one(pool)
    .await
    .ctx(ctx)?;

    let stale_secrets: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT s.id) \
         FROM secrets s \
         JOIN secret_revisions sr \
           ON sr.secret_id = s.id AND sr.revision = s.active_revision \
         JOIN namespace_kek_assignments nka \
           ON nka.namespace_id = s.namespace_id AND nka.is_active = TRUE \
         WHERE s.deleted_at IS NULL \
           AND sr.kek_id != nka.kek_id",
    )
    .fetch_one(pool)
    .await
    .ctx(ctx)?;

    // Get counts per (account_type, status) for user and service accounts
    let account_rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT account_type::text, status::text, COUNT(*) \
         FROM accounts \
         WHERE deleted_at IS NULL \
           AND account_type IN ('user', 'service') \
         GROUP BY account_type, status",
    )
    .fetch_all(pool)
    .await
    .ctx(ctx)?;

    let mut users: i64 = 0;
    let mut users_active: i64 = 0;
    let mut service_accounts: i64 = 0;
    let mut service_accounts_active: i64 = 0;

    for (account_type, status, count) in &account_rows {
        match account_type.as_str() {
            "user" => {
                users += count;
                if status == "active" {
                    users_active += count;
                }
            }
            "service" => {
                service_accounts += count;
                if status == "active" {
                    service_accounts_active += count;
                }
            }
            _ => {}
        }
    }

    let admins: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT ara.account_id) \
         FROM rbac_account_roles ara \
         JOIN rbac_roles r ON r.id = ara.role_id \
         JOIN accounts a ON a.id = ara.account_id \
         WHERE r.name = 'platform:admin' \
           AND a.deleted_at IS NULL \
           AND (ara.valid_from IS NULL OR ara.valid_from <= NOW()) \
           AND (ara.valid_until IS NULL OR ara.valid_until > NOW())",
    )
    .fetch_one(pool)
    .await
    .ctx(ctx)?;

    let (mk_total, mk_active, mk_retired): (i64, i64, i64) = sqlx::query_as(
        "SELECT \
            COUNT(*), \
            COUNT(*) FILTER (WHERE status = 'active'), \
            COUNT(*) FILTER (WHERE status = 'retired') \
         FROM masterkeys",
    )
    .fetch_one(pool)
    .await
    .ctx(ctx)?;

    // Locked count: consult the in-memory keyring
    let master_keys = state.masterkey_service.find_all(&call_ctx).await.ctx(ctx)?;
    let mk_locked = master_keys
        .iter()
        .filter(|mk| state.masterkey_service.is_locked(&call_ctx, mk).unwrap_or(false))
        .count() as i64;

    let (kek_total, kek_stale): (i64, i64) = sqlx::query_as(
        "SELECT \
            COUNT(*), \
            COUNT(*) FILTER (WHERE k.masterkey_id != ( \
                SELECT id FROM masterkeys \
                WHERE usage = 'wrap_kek' AND status = 'active' \
                LIMIT 1 \
            )) \
         FROM keks k \
         WHERE k.deleted_at IS NULL",
    )
    .fetch_one(pool)
    .await
    .ctx(ctx)?;

    let mut warnings: Vec<String> = Vec::new();

    if mk_locked > 0 {
        warnings.push(format!("{mk_locked} master key(s) are locked — secrets cannot be decrypted"));
    }
    if stale_secrets > 0 {
        warnings.push(format!("{stale_secrets} secret(s) use a stale KEK and should be re-wrapped"));
    }
    if kek_stale > 0 {
        warnings.push(format!(
            "{kek_stale} KEK(s) are wrapped by a non-active master key and should be re-wrapped"
        ));
    }
    if admins == 0 {
        warnings.push("No admin accounts found — platform may be unmanageable".to_string());
    }

    let data = SystemStatusDto {
        namespaces: NamespaceStats {
            total: ns_total,
            active: ns_active,
            disabled: ns_disabled,
        },
        secrets: SecretStats {
            total: secrets_total,
            active: secrets_active,
            stale_kek: stale_secrets,
        },
        accounts: AccountStats {
            users,
            users_active,
            service_accounts,
            service_accounts_active,
            admins,
        },
        masterkeys: MasterKeyStats {
            total: mk_total,
            active: mk_active,
            retired: mk_retired,
            locked: mk_locked,
        },
        keks: KekStats {
            total: kek_total,
            stale_masterkey: kek_stale,
        },
        warnings,
    };

    let status = ApiStatus::new(ApiCode::SystemStatusSuccess, "System status retrieved successfully");
    Ok(Json(ApiResponse::ok(status, data)))
}
