// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

//! Audit logging service.

use crate::audit_context::{Actor, CallContext};
use crate::service::LicenseService;
use chrono::{DateTime, Utc};
use hierarkey_core::license::Feature;
use hierarkey_core::{CkError, CkResult};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::error;
use uuid::Uuid;

// ------------------------------------------------------------------------------------------------
// Public event-type constants
// ------------------------------------------------------------------------------------------------

/// String constants for the `event_type` column.
pub mod event_type {
    // Authentication
    pub const AUTH_LOGIN_SUCCESS: &str = "auth.login_success";
    pub const AUTH_LOGIN_FAILURE: &str = "auth.login_failure";
    pub const AUTH_LOGOUT: &str = "auth.logout";
    pub const AUTH_MFA_VERIFY_SUCCESS: &str = "auth.mfa_verify_success";
    pub const AUTH_MFA_VERIFY_FAILURE: &str = "auth.mfa_verify_failure";
    pub const AUTH_BRUTE_FORCE_LOCKOUT: &str = "auth.brute_force_lockout";
    pub const AUTH_SERVICE_ACCOUNT_TOKEN: &str = "auth.service_account_token";
    pub const AUTH_FEDERATED: &str = "auth.federated";

    // Personal Access Tokens
    pub const PAT_ISSUED: &str = "pat.issued";
    pub const PAT_REVOKED: &str = "pat.revoked";

    // Secrets
    pub const SECRET_READ: &str = "secret.read";
    pub const SECRET_CREATE: &str = "secret.create";
    pub const SECRET_UPDATE: &str = "secret.update";
    pub const SECRET_DELETE: &str = "secret.delete";
    pub const SECRET_REVISE: &str = "secret.revise";
    pub const SECRET_STATUS_CHANGE: &str = "secret.status_change";

    // Namespaces
    pub const NAMESPACE_CREATE: &str = "namespace.create";
    pub const NAMESPACE_UPDATE: &str = "namespace.update";
    pub const NAMESPACE_DELETE: &str = "namespace.delete";
    pub const NAMESPACE_STATUS_CHANGE: &str = "namespace.status_change";
    pub const NAMESPACE_KEK_ROTATE: &str = "namespace.kek_rotate";

    // Accounts
    pub const ACCOUNT_CREATE: &str = "account.create";
    pub const ACCOUNT_UPDATE: &str = "account.update";
    pub const ACCOUNT_DELETE: &str = "account.delete";
    pub const ACCOUNT_STATUS_CHANGE: &str = "account.status_change";
    pub const ACCOUNT_PASSWORD_CHANGE: &str = "account.password_change";
    pub const ACCOUNT_MFA_CHANGE: &str = "account.mfa_change";
    pub const ACCOUNT_PROMOTE: &str = "account.promote";
    pub const ACCOUNT_DEMOTE: &str = "account.demote";

    // RBAC
    pub const RBAC_ROLE_CREATE: &str = "rbac.role_create";
    pub const RBAC_ROLE_UPDATE: &str = "rbac.role_update";
    pub const RBAC_ROLE_DELETE: &str = "rbac.role_delete";
    pub const RBAC_RULE_CREATE: &str = "rbac.rule_create";
    pub const RBAC_RULE_DELETE: &str = "rbac.rule_delete";
    pub const RBAC_BIND: &str = "rbac.bind";
    pub const RBAC_UNBIND: &str = "rbac.unbind";

    // Master keys
    pub const MASTERKEY_CREATE: &str = "masterkey.create";
    pub const MASTERKEY_DELETE: &str = "masterkey.delete";
    pub const MASTERKEY_ACTIVATE: &str = "masterkey.activate";
    pub const MASTERKEY_LOCK: &str = "masterkey.lock";
    pub const MASTERKEY_UNLOCK: &str = "masterkey.unlock";
    pub const MASTERKEY_ROTATE: &str = "masterkey.rotate";

    // Platform
    pub const LICENSE_CHANGE: &str = "platform.license_change";
    pub const BREAKGLASS_USED: &str = "platform.breakglass_used";
}

// ------------------------------------------------------------------------------------------------
// AuditOutcome
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

impl AuditOutcome {
    fn as_str(self) -> &'static str {
        match self {
            AuditOutcome::Success => "success",
            AuditOutcome::Failure => "failure",
            AuditOutcome::Denied => "denied",
        }
    }
}

// ------------------------------------------------------------------------------------------------
// AuditEvent
// ------------------------------------------------------------------------------------------------

/// A single audit event to be recorded.  Build one with [`AuditEvent::from_ctx`] and then
/// optionally enrich it with [`with_resource`] / [`with_actor_name`] / [`with_metadata`].
#[derive(Debug)]
pub struct AuditEvent {
    pub event_type: String,
    pub outcome: AuditOutcome,

    pub actor_id: Option<Uuid>,
    pub actor_type: Option<String>,
    pub actor_name: Option<String>,

    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub resource_name: Option<String>,

    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub client_ip: Option<IpAddr>,

    pub metadata: Option<serde_json::Value>,
}

impl AuditEvent {
    /// Create a base event from a [`CallContext`].  Callers should follow up with
    /// [`with_resource`] etc. to add event-specific detail.
    pub fn from_ctx(ctx: &CallContext, event_type: impl Into<String>, outcome: AuditOutcome) -> Self {
        let (actor_id, actor_type) = match &ctx.actor {
            Actor::Account(id) => (Some(id.0), Some("account".to_string())),
            Actor::System => (None, Some("system".to_string())),
        };

        Self {
            event_type: event_type.into(),
            outcome,
            actor_id,
            actor_type,
            actor_name: ctx.actor_name.clone(),
            resource_type: None,
            resource_id: None,
            resource_name: None,
            request_id: Some(ctx.request_id.to_string()),
            trace_id: Some(ctx.trace_id.to_string()),
            client_ip: ctx.client_ip,
            metadata: None,
        }
    }

    pub fn with_resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: Uuid,
        resource_name: impl Into<String>,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id);
        self.resource_name = Some(resource_name.into());
        self
    }

    /// Like `with_resource` but without an ID — for operations where the UUID isn't available
    /// (e.g. reveal-by-ref returns only the secret value, not the full secret record).
    pub fn with_resource_ref(mut self, resource_type: impl Into<String>, resource_name: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_name = Some(resource_name.into());
        self
    }

    pub fn with_actor_name(mut self, name: impl Into<String>) -> Self {
        self.actor_name = Some(name.into());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Override the actor fields — useful for auth endpoints where the CallContext actor
    /// is still `Actor::System` at the time of logging but the authenticated account is known.
    pub fn with_actor(mut self, actor_id: uuid::Uuid, actor_type: &str, actor_name: &str) -> Self {
        self.actor_id = Some(actor_id);
        self.actor_type = Some(actor_type.to_string());
        self.actor_name = Some(actor_name.to_string());
        self
    }
}

// ------------------------------------------------------------------------------------------------
// AuditService
// ------------------------------------------------------------------------------------------------

pub struct AuditService {
    pool: PgPool,
    pub(crate) license_service: Arc<LicenseService>,
    /// Last chain_hash written; serializes concurrent writes and seeds the hash chain.
    /// Initialized from the DB by [`init`]; empty string acts as the genesis value.
    last_chain_hash: Mutex<String>,
}

impl AuditService {
    pub fn new(pool: PgPool, license_service: Arc<LicenseService>) -> Self {
        Self {
            pool,
            license_service,
            last_chain_hash: Mutex::new(String::new()),
        }
    }

    /// Load the most recent chain_hash from the database.
    /// Must be called once during startup before any events are logged.
    pub async fn init(&self) {
        let result: Option<String> =
            sqlx::query_scalar("SELECT chain_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None);

        *self.last_chain_hash.lock().await = result.unwrap_or_default();
    }

    /// Record an audit event.
    ///
    /// If the active license does not include [`Feature::Audit`] this is a no-op,
    /// unless a grace period is active (up to 7 days after license expiry), in which
    /// case writes continue so no audit gap occurs during license renewal.
    /// Any database error is logged but never propagated — audit failures must never
    /// break the operation that triggered them.
    pub async fn log(&self, event: AuditEvent) {
        if !self
            .license_service
            .get_effective_license()
            .has_feature_or_grace(&Feature::Audit)
        {
            return;
        }

        let id = Uuid::now_v7();
        let now = chrono::Utc::now();
        // Postgres timestamptz has microsecond precision; truncate here so the hash
        // computed at write-time matches the hash recomputed from the stored timestamp.
        let now_nanos = now.timestamp_micros() * 1000;

        // Serialize writes: hold the mutex for the duration of the INSERT so the chain
        // never forks even under concurrent requests.
        let mut last_hash = self.last_chain_hash.lock().await;

        let chain_hash = compute_chain_hash(&last_hash, &id, &event.event_type, event.outcome.as_str(), now_nanos);

        let result = sqlx::query(
            r#"
            INSERT INTO audit_events (
                id, event_type, outcome,
                actor_id, actor_type, actor_name,
                resource_type, resource_id, resource_name,
                request_id, trace_id, client_ip,
                metadata, created_at, chain_hash
            ) VALUES (
                $1, $2, $3,
                $4, $5, $6,
                $7, $8, $9,
                $10, $11, $12,
                $13, $14, $15
            )
            "#,
        )
        .bind(id)
        .bind(&event.event_type)
        .bind(event.outcome.as_str())
        .bind(event.actor_id)
        .bind(&event.actor_type)
        .bind(&event.actor_name)
        .bind(&event.resource_type)
        .bind(event.resource_id)
        .bind(&event.resource_name)
        .bind(&event.request_id)
        .bind(&event.trace_id)
        .bind(event.client_ip.map(|ip| ip.to_string()))
        .bind(event.metadata.as_ref().map(sqlx::types::Json))
        .bind(now)
        .bind(&chain_hash)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => *last_hash = chain_hash,
            Err(e) => error!("audit: failed to write event '{}': {e}", event.event_type),
        }
    }

    /// If `result` is `Err`, log a failure audit event and return the error unchanged.
    /// `CkError::Rbac` / `CkError::PermissionDenied` → `Denied`; everything else → `Failure`.
    /// `Ok` values pass through without any logging.
    pub async fn log_err<T>(
        &self,
        result: CkResult<T>,
        event_fn: impl FnOnce(AuditOutcome) -> AuditEvent,
    ) -> CkResult<T> {
        if let Err(ref e) = result {
            let outcome = match e {
                CkError::Rbac(_) | CkError::PermissionDenied => AuditOutcome::Denied,
                _ => AuditOutcome::Failure,
            };
            self.log(event_fn(outcome)).await;
        }
        result
    }
}

// ------------------------------------------------------------------------------------------------
// Query types
// ------------------------------------------------------------------------------------------------

/// Filters for [`AuditService::query`].
#[derive(Debug, Default, serde::Deserialize)]
pub struct AuditFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub actor_id: Option<Uuid>,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub outcome: Option<String>,
    /// 0-based page number (default 0).
    #[serde(default)]
    pub page: u32,
    /// Page size (default 50, max 500).
    #[serde(default)]
    pub limit: u32,
}

/// A single audit event row returned from the database.
#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct AuditEventRow {
    pub seq: i64,
    pub id: Uuid,
    pub event_type: String,
    pub outcome: String,
    pub actor_id: Option<Uuid>,
    pub actor_type: Option<String>,
    pub actor_name: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub resource_name: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub client_ip: Option<String>,
    pub metadata: Option<sqlx::types::Json<serde_json::Value>>,
    pub created_at: DateTime<Utc>,
    pub chain_hash: String,
}

/// Paginated result from [`AuditService::query`].
#[derive(Debug, serde::Serialize)]
pub struct AuditQueryResult {
    pub events: Vec<AuditEventRow>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
}

/// Result of a chain-integrity verification pass.
#[derive(Debug, serde::Serialize)]
pub struct ChainVerifyResult {
    /// `true` if every event in the checked range matches its expected chain hash.
    pub valid: bool,
    /// Number of events checked.
    pub total_checked: i64,
    /// `seq` of the first event whose chain hash does not match, if any.
    pub first_broken_seq: Option<i64>,
}

impl AuditService {
    /// Query audit events with optional filters and pagination.
    pub async fn query(&self, filter: &AuditFilter) -> CkResult<AuditQueryResult> {
        let limit = filter.limit.clamp(1, 500);
        let limit = if limit == 0 { 50 } else { limit };
        let offset = filter.page as i64 * limit as i64;

        // Translate a user-supplied glob pattern (e.g. "masterkey.*") into a SQL LIKE pattern.
        // Only `*` is treated as a wildcard; event type names contain only alphanum and `.`
        // so no escaping of `_` or `%` is needed. Without a wildcard, LIKE behaves as `=`.
        let event_type_pattern = filter.event_type.as_deref().map(|s| s.replace('*', "%"));

        // Count total matching rows.
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM audit_events
            WHERE ($1::timestamptz IS NULL OR created_at >= $1)
              AND ($2::timestamptz IS NULL OR created_at <= $2)
              AND ($3::uuid        IS NULL OR actor_id = $3)
              AND ($4::text        IS NULL OR resource_type = $4)
              AND ($5::uuid        IS NULL OR resource_id = $5)
              AND ($6::text        IS NULL OR event_type LIKE $6)
              AND ($7::text        IS NULL OR outcome = $7)
            "#,
        )
        .bind(filter.from)
        .bind(filter.to)
        .bind(filter.actor_id)
        .bind(&filter.resource_type)
        .bind(filter.resource_id)
        .bind(&event_type_pattern)
        .bind(&filter.outcome)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CkError::Custom(format!("audit query count failed: {e}")))?;

        // Fetch the page.
        let events: Vec<AuditEventRow> = sqlx::query_as(
            r#"
            SELECT seq, id, event_type, outcome,
                   actor_id, actor_type, actor_name,
                   resource_type, resource_id, resource_name,
                   request_id, trace_id, client_ip,
                   metadata, created_at, chain_hash
            FROM audit_events
            WHERE ($1::timestamptz IS NULL OR created_at >= $1)
              AND ($2::timestamptz IS NULL OR created_at <= $2)
              AND ($3::uuid        IS NULL OR actor_id = $3)
              AND ($4::text        IS NULL OR resource_type = $4)
              AND ($5::uuid        IS NULL OR resource_id = $5)
              AND ($6::text        IS NULL OR event_type LIKE $6)
              AND ($7::text        IS NULL OR outcome = $7)
            ORDER BY seq DESC
            LIMIT $8 OFFSET $9
            "#,
        )
        .bind(filter.from)
        .bind(filter.to)
        .bind(filter.actor_id)
        .bind(&filter.resource_type)
        .bind(filter.resource_id)
        .bind(&event_type_pattern)
        .bind(&filter.outcome)
        .bind(limit as i64)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CkError::Custom(format!("audit query failed: {e}")))?;

        Ok(AuditQueryResult {
            events,
            total,
            page: filter.page,
            limit,
        })
    }

    /// Walk the audit log in forward order and verify the SHA-256 chain hash of each event.
    ///
    /// `from_seq` — start at this seq (inclusive); defaults to 1.
    /// `limit`    — maximum number of events to check (default 10 000, max 100 000).
    pub async fn verify_chain(&self, from_seq: Option<i64>, limit: Option<i64>) -> CkResult<ChainVerifyResult> {
        let from_seq = from_seq.unwrap_or(1).max(1);
        let limit = limit.unwrap_or(10_000).clamp(1, 100_000);

        // Determine the previous chain hash (the hash of seq = from_seq - 1, or "" for genesis).
        let prev_hash: String = if from_seq <= 1 {
            String::new()
        } else {
            sqlx::query_scalar("SELECT chain_hash FROM audit_events WHERE seq = $1")
                .bind(from_seq - 1)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| CkError::Custom(format!("audit verify: predecessor fetch failed: {e}")))?
                .unwrap_or_default()
        };

        // Minimal row: only fields needed for hash recomputation.
        #[derive(sqlx::FromRow)]
        struct VerifyRow {
            seq: i64,
            id: Uuid,
            event_type: String,
            outcome: String,
            created_at: DateTime<Utc>,
            chain_hash: String,
        }

        let rows: Vec<VerifyRow> = sqlx::query_as(
            "SELECT seq, id, event_type, outcome, created_at, chain_hash
             FROM audit_events
             WHERE seq >= $1
             ORDER BY seq ASC
             LIMIT $2",
        )
        .bind(from_seq)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CkError::Custom(format!("audit verify: fetch failed: {e}")))?;

        let total_checked = rows.len() as i64;
        let mut running_hash = prev_hash;
        let mut first_broken_seq: Option<i64> = None;

        for row in &rows {
            let nanos = row.created_at.timestamp_micros() * 1000;
            let expected = compute_chain_hash(&running_hash, &row.id, &row.event_type, &row.outcome, nanos);
            if expected != row.chain_hash {
                first_broken_seq = Some(row.seq);
                break;
            }
            running_hash = row.chain_hash.clone();
        }

        Ok(ChainVerifyResult {
            valid: first_broken_seq.is_none(),
            total_checked,
            first_broken_seq,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// Chain hash
// ------------------------------------------------------------------------------------------------

/// Compute a SHA-256 chain hash over the identifying fields of the new event.
///
/// Input (`:` separated): prev_hash | id | event_type | outcome | created_at_nanos
fn compute_chain_hash(prev_hash: &str, id: &Uuid, event_type: &str, outcome: &str, created_at_nanos: i64) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b":");
    h.update(id.as_bytes());
    h.update(b":");
    h.update(event_type.as_bytes());
    h.update(b":");
    h.update(outcome.as_bytes());
    h.update(b":");
    h.update(created_at_nanos.to_string().as_bytes());
    hex::encode(h.finalize())
}
