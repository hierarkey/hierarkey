// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::api::status::{ApiErrorBody, ApiStatus, Outcome};
use serde::{Deserialize, Serialize};

// Generic API response wrapper that includes status, optional error, and optional data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Always return the API status, even on success, to provide consistent metadata about the response.
    pub status: ApiStatus,

    /// On failure, include the error details. On success, this will be None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiErrorBody>,

    /// On success, include the response data. On failure, this will be None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    /// Create a success response with the given status and data. The error field will be None.
    pub fn ok(status: ApiStatus, data: T) -> Self {
        debug_assert!(matches!(status.outcome, Outcome::Success));
        Self {
            status,
            error: None,
            data: Some(data),
        }
    }

    /// Create a success response with the given status but no data. The error field will be None.
    pub fn ok_no_data(status: ApiStatus) -> Self {
        debug_assert!(matches!(status.outcome, Outcome::Success));
        Self {
            status,
            error: None,
            data: None,
        }
    }

    /// Create a failure response with the given status and error details. The data field will be None.
    pub fn fail(status: ApiStatus, error: ApiErrorBody) -> Self {
        debug_assert!(matches!(status.outcome, Outcome::Failure));
        Self {
            status,
            error: Some(error),
            data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::status::{ApiCode, ApiErrorCode};

    fn success_status() -> ApiStatus {
        ApiStatus::new(ApiCode::SecretCreated, "created")
    }

    fn failure_status() -> ApiStatus {
        ApiStatus::new(ApiCode::SecretCreateFailed, "failed")
    }

    fn error_body() -> ApiErrorBody {
        ApiErrorBody {
            code: ApiErrorCode::ValidationFailed,
            message: "bad input".to_string(),
            details: None,
        }
    }

    // --- ok ---

    #[test]
    fn ok_sets_data_and_clears_error() {
        let resp: ApiResponse<u32> = ApiResponse::ok(success_status(), 42);
        assert_eq!(resp.data, Some(42));
        assert!(resp.error.is_none());
        assert!(matches!(resp.status.outcome, Outcome::Success));
    }

    // --- ok_no_data ---

    #[test]
    fn ok_no_data_has_no_data_or_error() {
        let resp: ApiResponse<u32> = ApiResponse::ok_no_data(success_status());
        assert!(resp.data.is_none());
        assert!(resp.error.is_none());
        assert!(matches!(resp.status.outcome, Outcome::Success));
    }

    // --- fail ---

    #[test]
    fn fail_sets_error_and_clears_data() {
        let resp: ApiResponse<u32> = ApiResponse::fail(failure_status(), error_body());
        assert!(resp.data.is_none());
        assert!(resp.error.is_some());
        assert!(matches!(resp.status.outcome, Outcome::Failure));
    }

    // --- serde: skip_serializing_if = "Option::is_none" ---

    #[test]
    fn ok_serializes_without_error_field() {
        let resp: ApiResponse<u32> = ApiResponse::ok(success_status(), 1);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("\"error\""), "error field should be absent: {json}");
        assert!(json.contains("\"data\""));
    }

    #[test]
    fn ok_no_data_serializes_without_data_or_error_fields() {
        let resp: ApiResponse<u32> = ApiResponse::ok_no_data(success_status());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("\"error\""), "error field should be absent: {json}");
        assert!(!json.contains("\"data\""), "data field should be absent: {json}");
    }

    #[test]
    fn fail_serializes_without_data_field() {
        let resp: ApiResponse<u32> = ApiResponse::fail(failure_status(), error_body());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\""));
        assert!(!json.contains("\"data\""), "data field should be absent: {json}");
    }

    // --- serde round-trip ---

    #[test]
    fn serde_roundtrip_ok() {
        let original: ApiResponse<String> = ApiResponse::ok(success_status(), "hello".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let restored: ApiResponse<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.data, Some("hello".to_string()));
        assert!(restored.error.is_none());
        assert!(matches!(restored.status.outcome, Outcome::Success));
    }

    #[test]
    fn serde_roundtrip_fail() {
        let original: ApiResponse<String> = ApiResponse::fail(failure_status(), error_body());
        let json = serde_json::to_string(&original).unwrap();
        let restored: ApiResponse<String> = serde_json::from_str(&json).unwrap();
        assert!(restored.data.is_none());
        assert!(restored.error.is_some());
        assert_eq!(restored.error.unwrap().message, "bad input");
        assert!(matches!(restored.status.outcome, Outcome::Failure));
    }
}
