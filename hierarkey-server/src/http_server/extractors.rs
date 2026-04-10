// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::http_server::api_error::HttpError;
use axum::extract::rejection::BytesRejection::FailedToBufferBody;
use axum::http::StatusCode;
use axum::{
    body::Body,
    extract::rejection::JsonRejection,
    extract::{FromRequest, Json},
    http::Request,
};
use hierarkey_core::api::status::{ApiCode, ApiErrorCode};
// ----------------------------------------------------------------------------------------

// ApiJson is a wrapper around axum's JSON extractor that maps rejections to HttpError.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = HttpError;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await.map_err(map_json_rejection)?;
        Ok(ApiJson(value))
    }
}

fn map_json_rejection(rej: JsonRejection) -> HttpError {
    use axum::extract::rejection::FailedToBufferBody::LengthLimitError;
    use axum::extract::rejection::FailedToBufferBody::UnknownBodyError;
    use axum::extract::rejection::JsonRejection::*;

    match rej {
        MissingJsonContentType(e) => HttpError {
            // 415 is a better signal than 400 for “wrong/missing Content-Type”
            http: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            fail_code: ApiCode::InvalidContentType, // pick/add a code that fits your enum
            reason: ApiErrorCode::ValidationFailed,
            message: "Content-Type must be application/json".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
        JsonSyntaxError(e) => HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::InvalidJson, // pick/add
            reason: ApiErrorCode::SerializationError,
            message: "Malformed JSON body".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
        JsonDataError(e) => HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::InvalidJson, // or ApiCode::InvalidRequestBody
            reason: ApiErrorCode::ValidationFailed,
            message: "JSON does not match the expected schema".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
        // Includes body read failures, too-large payloads, etc.
        BytesRejection(FailedToBufferBody(LengthLimitError(e))) => HttpError {
            http: StatusCode::PAYLOAD_TOO_LARGE,
            fail_code: ApiCode::RequestBodyTooLarge,
            reason: ApiErrorCode::ValidationFailed,
            message: format!("Request body exceeds limit ({HTTP_MAX_BODY_SIZE} bytes)"),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
        BytesRejection(FailedToBufferBody(UnknownBodyError(e))) => HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::InvalidRequest,
            reason: ApiErrorCode::InvalidRequest,
            message: "Failed to buffer request body".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
        e => {
            HttpError {
                http: StatusCode::BAD_REQUEST,
                fail_code: ApiCode::InvalidRequest, // generic
                reason: ApiErrorCode::InvalidRequest,
                message: "Failed to parse JSON body".to_string(),
                details: Some(serde_json::json!({"error": e.to_string()})),
            }
        }
    }
}

// ----------------------------------------------------------------------------------------

pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(value) = Query::<T>::from_request_parts(parts, state)
            .await
            .map_err(map_query_rejection)?;
        Ok(ApiQuery(value))
    }
}

fn map_query_rejection(rej: QueryRejection) -> HttpError {
    match rej {
        QueryRejection::FailedToDeserializeQueryString(e) => HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::InvalidQuery,
            reason: ApiErrorCode::ValidationFailed,
            message: "Failed to deserialize query string".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
        e => HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::InvalidQuery,
            reason: ApiErrorCode::InvalidRequest,
            message: "Failed to parse query parameters".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
    }
}

// ----------------------------------------------------------------------------------------

use crate::global::HTTP_MAX_BODY_SIZE;
use axum::extract::Query;
use axum::extract::rejection::QueryRejection;
use axum::{
    extract::rejection::PathRejection,
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use serde::de::DeserializeOwned;

pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(value) = Path::<T>::from_request_parts(parts, state)
            .await
            .map_err(map_path_rejection)?;
        Ok(ApiPath(value))
    }
}

// ----------------------------------------------------------------------------------------

fn map_path_rejection(rej: PathRejection) -> HttpError {
    match rej {
        PathRejection::FailedToDeserializePathParams(e) => HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::InvalidPath,
            reason: ApiErrorCode::ValidationFailed,
            message: "Failed to deserialize path parameters".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
        PathRejection::MissingPathParams(e) => HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::InvalidPath,
            reason: ApiErrorCode::ValidationFailed,
            message: "Missing path parameters".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
        e => HttpError {
            http: StatusCode::BAD_REQUEST,
            fail_code: ApiCode::InvalidPath,
            reason: ApiErrorCode::InvalidRequest,
            message: "Failed to parse path parameters".to_string(),
            details: Some(serde_json::json!({"error": e.to_string()})),
        },
    }
}
