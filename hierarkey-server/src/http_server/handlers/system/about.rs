// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::audit_context::CallContext;
use crate::http_server::AppState;
use crate::http_server::api_error::{ApiErrorCtx, WithCtx};
use crate::http_server::auth_user::AuthUser;
use crate::http_server::handlers::ApiResult;
use crate::preview::{preview_enabled, preview_expiry_date};
use crate::rbac::{Permission, RbacResource};
use axum::Extension;
use axum::Json;
use axum::extract::State;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiStatus};
use hierarkey_core::license::Tier;
use serde::{Deserialize, Serialize};

// ---- Public shape (no auth) -----------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct AboutPublicDto {
    pub product: &'static str,
    pub server_time_utc: String,
    pub version: VersionPublicDto,
    pub api: ApiInfoDto,
    pub license: LicensePublicDto,
    pub support: SupportDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionPublicDto {
    pub semver: &'static str,
    pub release_stage: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_expires_at: Option<String>,
}

// ---- Authenticated (admin) shape -------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct AboutAdminDto {
    pub product: &'static str,
    pub server_time_utc: String,
    pub version: VersionAdminDto,
    pub api: ApiInfoDto,
    pub license: LicenseAdminDto,
    pub support: SupportDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionAdminDto {
    pub semver: &'static str,
    pub git_commit: &'static str,
    pub git_dirty: bool,
    pub build_date_utc: Option<String>,
    pub release_stage: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_expires_at: Option<String>,
}

// ---- Shared sub-types -------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiInfoDto {
    pub version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LicensePublicDto {
    pub tier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LicenseAdminDto {
    pub tier: String,
    pub license_subject: Option<String>,
    pub license_id: Option<String>,
    pub features: LicenseFeaturesDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LicenseFeaturesDto {
    pub advanced_rbac: bool,
    pub msp_mode: bool,
    pub audit_export: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SupportDto {
    pub vendor: &'static str,
    pub support_url: &'static str,
}

// ---- Helpers ----------------------------------------------------------------

fn build_time_str() -> Option<String> {
    let secs: u64 = env!("BUILD_TIME_UNIX").parse().unwrap_or(0);
    if secs == 0 {
        return None;
    }
    chrono::DateTime::from_timestamp(secs as i64, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn release_stage_and_expiry() -> (&'static str, Option<String>) {
    if preview_enabled() {
        let expires = preview_expiry_date().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        ("preview", Some(expires))
    } else {
        ("stable", None)
    }
}

fn git_dirty() -> bool {
    env!("GIT_DIRTY").parse().unwrap_or(false)
}

fn features_for_tier(tier: &Tier) -> LicenseFeaturesDto {
    match tier {
        Tier::Community => LicenseFeaturesDto {
            advanced_rbac: false,
            msp_mode: false,
            audit_export: false,
        },
        Tier::Commercial => LicenseFeaturesDto {
            advanced_rbac: true,
            msp_mode: true,
            audit_export: true,
        },
    }
}

// ---- Public handler ---------------------------------------------------------

#[axum::debug_handler]
pub async fn about_public(State(state): State<AppState>) -> ApiResult<Json<ApiResponse<AboutPublicDto>>> {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let (release_stage, preview_expires_at) = release_stage_and_expiry();
    let effective = state.license_service.get_effective_license();

    let data = AboutPublicDto {
        product: "Hierarkey Server",
        server_time_utc: now,
        version: VersionPublicDto {
            semver: env!("CARGO_PKG_VERSION"),
            release_stage,
            preview_expires_at,
        },
        api: ApiInfoDto {
            version: "v1",
            base_url: None,
            docs_url: None,
        },
        license: LicensePublicDto {
            tier: effective.tier.to_string(),
        },
        support: SupportDto {
            vendor: "Hierarkey",
            support_url: "https://hierarkey.com/support",
        },
    };

    let status = ApiStatus::new(ApiCode::AboutFetched, "OK");
    Ok(Json(ApiResponse::ok(status, data)))
}

// ---- Admin handler ----------------------------------------------------------

#[axum::debug_handler]
pub async fn about_admin(
    State(state): State<AppState>,
    _auth: AuthUser,
    Extension(call_ctx): Extension<CallContext>,
) -> ApiResult<Json<ApiResponse<AboutAdminDto>>> {
    let ctx = ApiErrorCtx {
        fail_code: ApiCode::SystemStatusFailed,
    };
    state
        .rbac_service
        .require_permission(&call_ctx, Permission::PlatformAdmin, RbacResource::Platform)
        .await
        .ctx(ctx)?;

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let (release_stage, preview_expires_at) = release_stage_and_expiry();
    let effective = state.license_service.get_effective_license();

    let data = AboutAdminDto {
        product: "Hierarkey Server",
        server_time_utc: now,
        version: VersionAdminDto {
            semver: env!("CARGO_PKG_VERSION"),
            git_commit: env!("GIT_COMMIT"),
            git_dirty: git_dirty(),
            build_date_utc: build_time_str(),
            release_stage,
            preview_expires_at,
        },
        api: ApiInfoDto {
            version: "v1",
            base_url: None,
            docs_url: None,
        },
        license: LicenseAdminDto {
            tier: effective.tier.to_string(),
            license_subject: effective.licensee.clone(),
            license_id: effective.license_id.clone(),
            features: features_for_tier(&effective.tier),
        },
        support: SupportDto {
            vendor: "Hierarkey",
            support_url: "https://hierarkey.com/support",
        },
    };

    let status = ApiStatus::new(ApiCode::AboutFetched, "OK");
    Ok(Json(ApiResponse::ok(status, data)))
}
