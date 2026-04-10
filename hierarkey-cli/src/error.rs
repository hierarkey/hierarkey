// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use hierarkey_core::CkError;
use hierarkey_core::api::status::ApiErrorCode;
use hierarkey_core::error::validation::ValidationError;
use std::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    /// Input validation error from the command line
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Authentication error given back from the server
    #[error("Authentication error: {0}")]
    Unauthenticated(String),

    /// HTTP or network error before connecting to the server
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// API returned an error status
    #[error("API error: code={code:?}, message={message}, details={details:?}")]
    ApiError {
        code: ApiErrorCode,
        message: String,
        details: Option<serde_json::Value>,
    },

    /// Other errors
    #[error("Other error: {0}")]
    Other(String),

    /// Error parsing server response
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Request failed
    #[error("Request failed: {0}")]
    RequestFailed(String),

    /// Serde JSON error
    #[error("(De)Serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    /// IO Error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Config error
    #[error("Config error: {0}")]
    ConfigError(String),

    // CkError
    #[error("Core error: {0}")]
    CkError(#[from] CkError),

    // ValidationError
    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationError),
}

impl CliError {
    /// Check if error is likely a TLS/certificate issue
    pub fn is_tls_error(&self) -> bool {
        match self {
            CliError::Http(e) => {
                let mut source = e.source();
                while let Some(err) = source {
                    // Actual rustls error — definitely TLS
                    if err.downcast_ref::<rustls::Error>().is_some() {
                        return true;
                    }
                    source = err.source();
                }

                // Fallback: TLS-specific terms in the error string, but exclude
                // plain connection errors (connection refused, etc.)
                if e.is_connect() {
                    return false;
                }
                let msg = e.to_string().to_lowercase();
                msg.contains("certificate") || msg.contains("ssl") || msg.contains("tls")
            }
            _ => false,
        }
    }

    /// Get user-friendly error message with helpful hints
    pub fn user_message(&self) -> String {
        match self {
            CliError::Http(e) if self.is_tls_error() => {
                format!(
                    "TLS certificate verification failed.\n\
                    This is likely a self-signed certificate.\n\
                    Use the -k or --self-signed flag to accept self-signed certificates:\n\
                    Example: hkey -k namespace list\n\n\
                    Original error: {e}"
                )
            }
            CliError::Http(e) if e.is_connect() => {
                let url_hint = e
                    .url()
                    .map(|u| format!(" at {}", u.origin().ascii_serialization()))
                    .unwrap_or_default();
                format!(
                    "Cannot reach the server{url_hint}.\n\
                    Is the server running? Check your --server / HKEY_SERVER_URL configuration.\n\n\
                    Original error: {e}"
                )
            }
            CliError::Http(e) if e.is_timeout() => {
                format!(
                    "Request timed out.\n\
                    The server took too long to respond. Check your network connection.\n\n\
                    Original error: {e}"
                )
            }
            CliError::Http(e) => format!("Network error: {e}"),
            CliError::ApiError { message, details, .. } => {
                if let Some(details) = details {
                    format!("Error: {message}\nDetails: {details}")
                } else {
                    format!("Error: {message}")
                }
            }
            CliError::Unauthenticated(msg) => format!("Authentication failed: {msg}"),
            CliError::InvalidInput(msg) => format!("Invalid input: {msg}"),
            CliError::ConfigError(msg) => format!("Configuration error: {msg}"),
            CliError::RequestFailed(msg) => format!("Request failed: {msg}"),
            CliError::ValidationError(e) => format!("Validation error: {e}"),
            CliError::IoError(e) => format!("IO error: {e}"),
            CliError::SerdeError(e) => format!("Failed to parse server response: {e}"),
            CliError::ParseError(msg) => format!("Failed to parse server response: {msg}"),
            CliError::CkError(e) => format!("Error: {e}"),
            CliError::Other(msg) => format!("Error: {msg}"),
        }
    }
}

impl CliError {
    /// Map error to appropriate exit code
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Other(_) => 1,
            CliError::ParseError(_) => 1,
            CliError::SerdeError(_) => 1,
            CliError::IoError(_) => 1,
            CliError::ValidationError(_) => 1,
            CliError::InvalidInput(_) => 2,
            CliError::CkError(_) => 2,
            CliError::Unauthenticated(_) => 3,
            CliError::ConfigError(_) => 6,
            CliError::Http(_) => 11,
            CliError::ApiError { .. } => 12,
            CliError::RequestFailed(_) => 12,
        }
    }
}

pub type CliResult<T> = Result<T, CliError>;
