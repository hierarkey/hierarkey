// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#[axum::debug_handler]
pub async fn index() -> &'static str {
    "Hierarkey server is operational"
}
