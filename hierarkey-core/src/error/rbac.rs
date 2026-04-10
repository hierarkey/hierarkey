// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::CkError;

#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("not found: {0}")]
    NotFound(&'static str),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("storage error: {0}")]
    Store(#[from] StoreError),
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("db error: {0}")]
    Db(String),
}

impl From<RbacError> for CkError {
    fn from(e: RbacError) -> Self {
        CkError::Rbac(e)
    }
}
