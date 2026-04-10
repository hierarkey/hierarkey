// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::http_server::AppState;
use crate::http_server::handlers::ApiResult;
use axum::Json;
use axum::extract::State;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FederatedProviderEntry {
    pub id: String,
    pub provider: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
}

/// `GET /v1/auth/federated`
///
/// Returns the list of federated authentication providers configured on this server.
/// Does not require authentication — callers need this list to know which provider
/// ID to use before they have a token.
#[axum::debug_handler]
pub(crate) async fn list_providers(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<Vec<FederatedProviderEntry>>>> {
    let providers: Vec<FederatedProviderEntry> = state
        .federated_providers
        .iter()
        .map(|p| FederatedProviderEntry {
            id: p.provider_id().to_string(),
            provider: p.provider_type().to_string(),
            issuer: p.issuer().to_string(),
            audience: p.audience().map(str::to_string),
            jwks_url: p.jwks_url().map(str::to_string),
        })
        .collect();

    let status = ApiStatus::new(ApiCode::AuthTokenListSucceeded, "Federated providers retrieved");
    Ok(Json(ApiResponse::ok(status, providers)))
}
