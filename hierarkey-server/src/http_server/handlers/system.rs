// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

mod about;
mod status;

pub use about::{about_admin, about_public};
pub use status::SystemStatusDto;
pub use status::system_status;
