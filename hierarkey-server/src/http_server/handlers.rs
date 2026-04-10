// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub(crate) mod account;
pub mod audit;
pub mod auth;
mod common;
pub(crate) mod healthz;
pub(crate) mod index;
pub(crate) mod masterkey;
pub(crate) mod namespace;
pub(crate) mod pat;
pub(crate) mod secret;
pub mod system;

pub mod account_response;
pub mod auth_response;
pub mod masterkey_response;
pub mod namespace_response;
pub mod pat_response;
pub mod rbac;
pub mod readyz;
pub mod secret_response;

pub use healthz::healthz;
pub use index::index;
pub use readyz::readyz;

use crate::http_server::api_error::HttpError;

pub type ApiResult<T> = Result<T, HttpError>;
