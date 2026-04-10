// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::manager::masterkey::MasterKeyStatus;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LockedKeyInfo {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub usage: String,
    pub status: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReadyzResponse {
    pub status: String,
    pub vault: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locked_keys: Vec<LockedKeyInfo>,
}

pub async fn readyz(State(state): State<AppState>, Extension(call_ctx): Extension<CallContext>) -> impl IntoResponse {
    let master_keys = match state.masterkey_service.find_all(&call_ctx).await {
        Ok(keys) => keys,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyzResponse {
                    status: "not_ready".into(),
                    vault: "error".into(),
                    reason: Some("failed_to_load_master_keys".into()),
                    locked_keys: vec![],
                }),
            );
        }
    };

    // Find active master key
    let active_mk = master_keys.iter().find(|k| k.status == MasterKeyStatus::Active);

    // Check if active key exists and is unlocked
    let active_locked = match active_mk {
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyzResponse {
                    status: "not_ready".into(),
                    vault: "locked".into(),
                    reason: Some("no_active_master_key".into()),
                    locked_keys: vec![],
                }),
            );
        }
        Some(mk) => state.masterkey_service.is_locked(&call_ctx, mk).unwrap_or(true),
    };

    // Collect all locked keys (only Active and Draining — Retired and Pending are excluded:
    // Retired are not in the keyring; Pending don't wrap any KEKs yet so being locked is harmless)
    let keyring = state.masterkey_service.keyring();
    let locked_keys: Vec<LockedKeyInfo> = master_keys
        .iter()
        .filter(|mk| mk.status != MasterKeyStatus::Retired && mk.status != MasterKeyStatus::Pending)
        .filter(|mk| state.masterkey_service.is_locked(&call_ctx, mk).unwrap_or(true))
        .map(|mk| {
            let provider = keyring
                .provider_for(mk)
                .map(|p| p.to_string())
                .unwrap_or_else(|_| "unknown".into());
            LockedKeyInfo {
                id: mk.short_id.to_string(),
                name: mk.name.clone(),
                provider,
                usage: mk.usage.to_string(),
                status: mk.status.to_string(),
            }
        })
        .collect();

    if active_locked {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyzResponse {
                status: "not_ready".into(),
                vault: "locked".into(),
                reason: Some("active_master_key_locked".into()),
                locked_keys,
            }),
        );
    }

    // Active key is unlocked, but draining keys that are locked mean some secrets are
    // temporarily unreadable (their KEKs cannot be decrypted until the key is unlocked).
    let has_locked_draining = locked_keys
        .iter()
        .any(|k| k.status == MasterKeyStatus::Draining.to_string());

    if has_locked_draining {
        return (
            StatusCode::OK,
            Json(ReadyzResponse {
                status: "degraded".into(),
                vault: "unlocked".into(),
                reason: Some("draining_keys_locked".into()),
                locked_keys,
            }),
        );
    }

    (
        StatusCode::OK,
        Json(ReadyzResponse {
            status: "ready".into(),
            vault: "unlocked".into(),
            reason: None,
            locked_keys: vec![],
        }),
    )
}
