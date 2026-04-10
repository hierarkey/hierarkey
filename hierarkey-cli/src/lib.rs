// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#![forbid(unsafe_code)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::dbg_macro)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![cfg_attr(not(test), deny(warnings))]

pub mod cli;
pub mod commands;
pub mod config;
pub mod error;
mod http;
pub mod utils;
mod values;

pub use http::ApiClient;
