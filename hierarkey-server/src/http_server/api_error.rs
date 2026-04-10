// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::service::masterkey::{MasterKeyActivateError, MasterKeyLockError, MasterKeyUnlockError};
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hierarkey_core::CkError;
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::api::status::{ApiCode, ApiErrorCode, ApiStatus};
use hierarkey_core::error::auth::AuthError;
use hierarkey_core::error::rbac::RbacError;
use tracing::error;
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct ApiErrorCtx {
    pub fail_code: ApiCode,
}

pub trait WithCtx<T> {
    fn ctx(self, ctx: ApiErrorCtx) -> Result<T, HttpError>;
}

impl<T> WithCtx<T> for Result<T, CkError> {
    fn ctx(self, ctx: ApiErrorCtx) -> Result<T, HttpError> {
        self.map_err(|e| HttpError::from_ck(e, ctx))
    }
}

impl<T> WithCtx<T> for Result<T, sqlx::Error> {
    fn ctx(self, ctx: ApiErrorCtx) -> Result<T, HttpError> {
        self.map_err(|_| HttpError {
            http: StatusCode::INTERNAL_SERVER_ERROR,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::DbError,
            message: "Database error".to_string(),
            details: None,
        })
    }
}

impl<T> WithCtx<T> for Result<T, serde_json::Error> {
    fn ctx(self, ctx: ApiErrorCtx) -> Result<T, HttpError> {
        self.map_err(|e| HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::SerializationError,
            message: e.to_string(),
            details: None,
        })
    }
}

// #[derive(Debug, Serialize)]
// pub struct ErrorResponse {
//     pub error: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub message: Option<String>,
// }

#[derive(Debug)]
pub struct HttpError {
    pub http: StatusCode,
    pub fail_code: ApiCode,   // e.g. NamespaceCreateFailed
    pub reason: ApiErrorCode, // e.g. AlreadyExists / ValidationFailed
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = ApiStatus::new(self.fail_code, self.message.clone());

        let error_body = hierarkey_core::api::status::ApiErrorBody {
            code: self.reason,
            message: self.message,
            details: self.details,
        };

        let response_body = ApiResponse::<()> {
            status,
            error: Some(error_body),
            data: None,
        };

        (self.http, Json(response_body)).into_response()
    }
}

impl HttpError {
    #[inline]
    pub fn simple(http: StatusCode, fail_code: ApiCode, reason: ApiErrorCode, message: impl Into<String>) -> Self {
        Self {
            http,
            fail_code,
            reason,
            message: message.into(),
            details: None,
        }
    }

    #[inline]
    pub fn simple_details(
        http: StatusCode,
        fail_code: ApiCode,
        reason: ApiErrorCode,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            http,
            fail_code,
            reason,
            message: message.into(),
            details: Some(details),
        }
    }

    pub fn from_activate_error(err: MasterKeyActivateError, ctx: ApiErrorCtx) -> Self {
        error!("Activate Error: {}", err.to_string());
        match err {
            MasterKeyActivateError::CkError(ck_err) => Self::from_ck(ck_err, ctx),
            MasterKeyActivateError::NotLoaded => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: "Masterkey is not loaded".to_string(),
                details: None,
            },
            MasterKeyActivateError::Locked => Self {
                http: StatusCode::FORBIDDEN,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::Forbidden,
                message: "Masterkey is locked and cannot be activated".to_string(),
                details: None,
            },
        }
    }

    pub fn from_lock_error(err: MasterKeyLockError, ctx: ApiErrorCtx) -> Self {
        error!("Lock Error: {}", err.to_string());
        match err {
            MasterKeyLockError::CkError(ck_err) => Self::from_ck(ck_err, ctx),
            MasterKeyLockError::NotLoaded => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: "Masterkey is not loaded".to_string(),
                details: None,
            },
        }
    }

    pub fn from_unlock_error(err: MasterKeyUnlockError, ctx: ApiErrorCtx) -> Self {
        error!("Unlock Error: {}", err.to_string());
        match err {
            MasterKeyUnlockError::InvalidUnlockData => Self {
                http: StatusCode::BAD_REQUEST,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::ValidationFailed,
                message: "Invalid unlock data provided".to_string(),
                details: None,
            },
            MasterKeyUnlockError::CkError(ck_err) => Self::from_ck(ck_err, ctx),
            MasterKeyUnlockError::AuthenticationFailed => Self {
                http: StatusCode::BAD_REQUEST,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::Unauthorized,
                message: "Incorrect credentials to unlock master key".to_string(),
                details: None,
            },
            MasterKeyUnlockError::NotLoaded => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: "Master key is not loaded".to_string(),
                details: None,
            },
        }
    }

    pub fn from_ck(err: CkError, ctx: ApiErrorCtx) -> Self {
        error!("Error: {}", err.to_string());
        match err {
            CkError::PermissionDenied => Self {
                http: StatusCode::FORBIDDEN,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::Unauthorized,
                message: "Permission denied".to_string(),
                details: None,
            },
            CkError::Auth(auth_error) => match auth_error {
                AuthError::Unauthenticated { reason } => Self {
                    http: StatusCode::UNAUTHORIZED,
                    fail_code: ctx.fail_code,
                    reason: ApiErrorCode::Unauthorized,
                    message: reason.to_string(),
                    details: None,
                },
                AuthError::Forbidden { reason } => Self {
                    http: StatusCode::FORBIDDEN,
                    fail_code: ctx.fail_code,
                    reason: ApiErrorCode::Forbidden,
                    message: reason.to_string(),
                    details: None,
                },
            },
            CkError::Validation(e) => Self {
                http: StatusCode::BAD_REQUEST,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::ValidationFailed,
                message: e.to_string(),
                details: None,
            },
            CkError::ResourceExists { .. } => Self {
                http: StatusCode::CONFLICT,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::AlreadyExists,
                message: err.to_string(),
                details: None,
            },
            CkError::ResourceNotFound { .. } => Self {
                http: StatusCode::NOT_FOUND,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::NotFound,
                message: err.to_string(),
                details: None,
            },
            CkError::Conflict { what } => Self {
                http: StatusCode::CONFLICT,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::Conflict,
                message: what,
                details: None,
            },
            CkError::RevisionMismatch => Self {
                http: StatusCode::CONFLICT,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::Conflict,
                message: "Revision mismatch".to_string(),
                details: None,
            },
            CkError::Rbac(rbac_error) => match rbac_error {
                RbacError::NotFound(_) => Self {
                    http: StatusCode::NOT_FOUND,
                    fail_code: ctx.fail_code,
                    reason: ApiErrorCode::NotFound,
                    message: rbac_error.to_string(),
                    details: None,
                },
                _ => Self {
                    http: StatusCode::INTERNAL_SERVER_ERROR,
                    fail_code: ctx.fail_code,
                    reason: ApiErrorCode::InternalError,
                    message: rbac_error.to_string(),
                    details: None,
                },
            },
            CkError::Crypto(_) => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: "Cryptographic operation failed".to_string(),
                details: None,
            },
            CkError::Sqlx(_) => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: "Database error".to_string(),
                details: None,
            },
            CkError::Io(_) => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: "IO error".to_string(),
                details: None,
            },
            CkError::Serde(_) => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: "Serialization error".to_string(),
                details: None,
            },
            CkError::Config(_) => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: "Configuration error".to_string(),
                details: None,
            },
            CkError::MasterKey(msg) => Self {
                http: StatusCode::SERVICE_UNAVAILABLE,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::InternalError,
                message: msg,
                details: None,
            },
            CkError::InvalidCredentials => Self {
                http: StatusCode::UNAUTHORIZED,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::Unauthorized,
                message: "Invalid credentials".to_string(),
                details: None,
            },
            _ => Self {
                http: StatusCode::INTERNAL_SERVER_ERROR,
                fail_code: ctx.fail_code,
                reason: ApiErrorCode::CryptoError,
                message: "Internal error".to_string(),
                details: None,
            },
        }
    }

    pub fn unauthorized(ctx: ApiErrorCtx, message: impl Into<String>) -> Self {
        Self {
            http: StatusCode::UNAUTHORIZED,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Unauthorized,
            message: message.into(),
            details: None,
        }
    }

    pub fn forbidden(ctx: ApiErrorCtx, message: impl Into<String>) -> Self {
        Self {
            http: StatusCode::FORBIDDEN,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::Forbidden,
            message: message.into(),
            details: None,
        }
    }

    pub fn not_found(ctx: ApiErrorCtx, message: impl Into<String>) -> Self {
        Self {
            http: StatusCode::NOT_FOUND,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::NotFound,
            message: message.into(),
            details: None,
        }
    }

    pub fn bad_request(ctx: ApiErrorCtx, message: impl Into<String>) -> Self {
        Self {
            http: StatusCode::BAD_REQUEST,
            fail_code: ctx.fail_code,
            reason: ApiErrorCode::PreconditionFailed,
            message: message.into(),
            details: None,
        }
    }
}
