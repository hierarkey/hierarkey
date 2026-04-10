// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::error::{CliError, CliResult};
use hierarkey_core::api::response::ApiResponse;
use hierarkey_core::resources::AccountName;
use hierarkey_server::http_server::handlers::auth_response::{AuthRequest, AuthResponse, AuthScope};
use std::time::Duration;
use zeroize::Zeroizing;

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// A simple API client for making requests to the Hierarkey server. It handles authentication,
/// error handling, and response parsing.
#[derive(Debug, Clone)]
pub struct ApiClient {
    client: reqwest::blocking::Client,
    pub base_url: String,
}

impl ApiClient {
    pub fn new(base_url: String, accept_self_signed: bool) -> CliResult<Self> {
        if accept_self_signed {
            tracing::warn!(
                "Accepting self-signed certificates. This is insecure and should only be used for development."
            );
        }

        // Setup the HTTP client with appropriate timeouts and TLS settings
        let client = reqwest::blocking::ClientBuilder::new()
            .use_rustls_tls()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .danger_accept_invalid_certs(accept_self_signed)
            .user_agent(format!("hierarkey-cli/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(CliError::Http)?;

        let base_url = base_url.trim_end_matches('/').to_string();

        if !base_url.starts_with("https://") && accept_self_signed {
            tracing::warn!(
                "Using HTTPS URL with --self-signed flag. This is insecure and should only be used for development."
            );
        }

        Ok(Self { client, base_url })
    }

    pub fn post(&self, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("POST {}", url);
        self.client.post(&url)
    }

    pub fn patch(&self, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("PATCH {}", url);
        self.client.patch(&url)
    }

    pub fn put(&self, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("PUT {}", url);
        self.client.put(&url)
    }

    pub fn get(&self, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("GET {}", url);
        self.client.get(&url)
    }

    pub fn delete(&self, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("DELETE {}", url);
        self.client.delete(&url)
    }

    /// Parse a JSON API response body, giving a helpful error when the body is empty.
    fn parse_response<T: serde::de::DeserializeOwned>(
        status: reqwest::StatusCode,
        text: &str,
    ) -> CliResult<ApiResponse<T>> {
        if text.trim().is_empty() {
            let msg = match status.as_u16() {
                404 => "This endpoint is not available on this server. It may require the Commercial Edition or a configuration change.".to_string(),
                501 => "This operation is not implemented on this server.".to_string(),
                _ => format!("Server returned HTTP {status} with an empty response body."),
            };
            return Err(CliError::RequestFailed(msg));
        }
        serde_json::from_str(text).map_err(|e| CliError::ParseError(format!("Failed to parse server response: {e}")))
    }

    /// Handle a full API response, returning the entire ApiResponse object.
    pub fn handle_full_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::blocking::Response,
    ) -> CliResult<ApiResponse<T>> {
        let status = response.status();
        let text = response
            .text()
            .map_err(|e| CliError::RequestFailed(format!("Failed to read response: {e}")))?;

        let api_response: ApiResponse<T> = Self::parse_response(status, &text)?;

        if let Some(error) = &api_response.error {
            return Err(CliError::ApiError {
                code: error.code,
                message: error.message.clone(),
                details: error.details.clone(),
            });
        }

        Ok(api_response)
    }

    /// Handle a full API response, returning just the data field or an error if present.
    pub fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::blocking::Response,
    ) -> CliResult<T> {
        let status = response.status();
        let text = response.text().unwrap_or_else(|_| String::new());

        let api_response: ApiResponse<T> = Self::parse_response(status, &text)?;

        if let Some(error) = api_response.error {
            return Err(CliError::ApiError {
                code: error.code,
                message: error.message,
                details: error.details,
            });
        }

        api_response
            .data
            .ok_or_else(|| CliError::Other("No data in successful response".to_string()))
    }

    /// Handle an API response that is expected to have no data (i.e. just success or error).
    pub fn handle_response_unit(&self, response: reqwest::blocking::Response) -> CliResult<ApiResponse<()>> {
        let status = response.status();
        let text = response
            .text()
            .map_err(|e| CliError::RequestFailed(format!("Failed to read response: {e}")))?;

        let api_response: ApiResponse<()> = Self::parse_response(status, &text)?;

        if let Some(error) = api_response.error {
            return Err(CliError::ApiError {
                code: error.code,
                message: error.message,
                details: error.details,
            });
        }

        Ok(api_response)
    }

    /// Get an authentication token for the given account name and password. The token will have
    /// the specified scope and TTL.
    pub fn get_auth_token(
        &self,
        account_name: &AccountName,
        password: &str,
        scope: AuthScope,
        description: &str,
        ttl_minutes: u32,
    ) -> CliResult<AuthResponse> {
        let body = AuthRequest {
            account_name: account_name.clone(),
            password: Zeroizing::new(password.to_string()),
            description: description.to_string(),
            ttl_minutes,
            scope,
        };

        let resp = self.post("/v1/auth/login").json(&body).send()?;
        let body = self.handle_full_response::<AuthResponse>(resp)?;

        let Some(data) = body.data else {
            return Err(CliError::Other("No data received from server".into()));
        };

        Ok(data)
    }

    /// Complete an MFA challenge, returning a full auth token on success.
    pub fn mfa_verify(&self, challenge_token: &str, code: &str, ttl_minutes: Option<u32>) -> CliResult<AuthResponse> {
        let body = serde_json::json!({
            "challenge_token": challenge_token,
            "code": code,
            "ttl_minutes": ttl_minutes,
        });

        let resp = self.post("/v1/auth/mfa/verify").json(&body).send()?;
        let api_response = self.handle_full_response::<AuthResponse>(resp)?;
        api_response
            .data
            .ok_or_else(|| CliError::Other("No data in MFA verify response".to_string()))
    }
}
