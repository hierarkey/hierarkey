// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

#[derive(Debug, Copy, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "rbac_target_kind", rename_all = "lowercase")]
pub enum TargetKind {
    All,
    Platform,
    Namespace,
    Secret,
    Account,
}
