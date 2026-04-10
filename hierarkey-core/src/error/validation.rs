// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::CkError;
use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("{field} does not match")]
    Mismatch { field: &'static str },

    #[error("rule syntax error: {0}")]
    Rule(String),

    #[error("{field} is too short (min {min})")]
    TooShort { field: &'static str, min: usize },

    #[error("{field} is too long (max {max})")]
    TooLong { field: &'static str, max: usize },

    #[error("{field} is too small (min {min})")]
    TooSmall { field: &'static str, min: i64 },

    #[error("{field} is too large (max {max})")]
    TooLarge { field: &'static str, max: i64 },

    #[error("{field} contains invalid characters. Allowed: {allowed}")]
    InvalidChars { field: &'static str, allowed: &'static str },

    #[error("validation failed for {field}: {code}")]
    Field {
        field: &'static str,
        code: &'static str,
        message: Cow<'static, str>,
    },

    #[error("validation failed for {field}: {code}")]
    FieldWithParams {
        field: &'static str,
        code: &'static str,
        message: &'static str,
        params: Vec<(&'static str, String)>,
    },

    #[error("{field} already exists: {message}")]
    AlreadyExists { field: &'static str, message: String },

    #[error("invalid ID format: {id}")]
    InvalidId { id: String },

    #[error("general validation error: {0}")]
    Custom(String),

    #[error("missing required field: {field}")]
    MissingField { field: &'static str },

    #[error("invalid operation: {message}")]
    InvalidOperation { message: String },

    #[error("invalid value for {field}: {value}")]
    InvalidValue { field: &'static str, value: String },
}

impl From<ValidationError> for CkError {
    fn from(e: ValidationError) -> Self {
        CkError::Validation(e)
    }
}
