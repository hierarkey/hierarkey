// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretReviseArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::values::{ValueSource, open_editor, resolve_value};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_standard;
use hierarkey_core::MAX_SECRET_SIZE;
use hierarkey_core::api::status::Outcome;
use hierarkey_core::resources::SecretRef;
use hierarkey_server::http_server::handlers::secret_response::SecretResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct ApiRequest {
    sec_ref: String,
    value_b64: String,
    note: Option<String>,
    activate: bool,
}

#[derive(Deserialize)]
struct SecretRevealResponse {
    value_b64: String,
}

fn try_reveal_current_value(client: &ApiClient, token: &str, sec_ref: &str) -> String {
    let result: Result<String, _> = (|| {
        let resp = client
            .post("/v1/secrets/reveal")
            .json(&serde_json::json!({ "sec_ref": sec_ref }))
            .bearer_auth(token)
            .send()
            .map_err(|e| e.to_string())?;

        let body = client
            .handle_response::<SecretRevealResponse>(resp)
            .map_err(|e| e.to_string())?;

        let value_bytes = base64_standard.decode(&body.value_b64).map_err(|e| e.to_string())?;

        String::from_utf8(value_bytes).map_err(|e| e.to_string())
    })();

    result.unwrap_or_default()
}

pub fn secret_revise(client: &ApiClient, cli_args: &CliArgs, args: &SecretReviseArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let payload = create_request_from_args(args, client, token.as_str())?;

    // Build the URL path for the revise endpoint
    let url_param = if args.id.is_some() {
        // Short ID — send directly in URL
        args.sec_ref_value().to_string()
    } else {
        // Use the sec_ref value (already validated) stripped of leading slash and URL-encoded
        let stripped = payload.sec_ref.trim_start_matches('/');
        urlencoding::encode(stripped).into_owned()
    };

    let resp = client
        .post(&format!("/v1/secrets/{url_param}/revise"))
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<SecretResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else if resp_body.status.outcome == Outcome::Failure {
        println!("Failed to revise secret: {}", resp_body.status.message);
    } else {
        println!("Secret '{}' revised successfully.", payload.sec_ref);
        println!();
        println!("You can describe the secret with the 'describe' command to see the details:");
        println!("  hkey secret describe --ref {}", payload.sec_ref);
        println!();
        println!("You can reveal the secret with the 'reveal' command to see its contents:");
        println!("  hkey secret reveal --ref {}", payload.sec_ref);
    }

    Ok(())
}

fn create_request_from_args(args: &SecretReviseArgs, client: &ApiClient, token: &str) -> CliResult<ApiRequest> {
    // Determine the sec_ref value to send in the body
    let sec_ref_str = if args.id.is_some() {
        // Short ID — pass directly to server which will resolve it
        args.sec_ref_value().to_string()
    } else {
        let sec_ref =
            SecretRef::from_string(args.sec_ref_value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        if sec_ref.revision.is_some() {
            return Err(CliError::InvalidInput(
                "Secret reference must not include a revision when creating a secret".into(),
            ));
        }
        sec_ref.to_string()
    };

    let value_bytes = if args.use_editor {
        let initial_content = try_reveal_current_value(client, token, &sec_ref_str);
        let text = open_editor(&initial_content)?;
        text.into_bytes()
    } else {
        let value_source = ValueSource::try_from(args).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        let value_bytes = resolve_value(value_source)?;
        let Some(value_bytes) = value_bytes else {
            return Err(CliError::InvalidInput(
                "Secret value must be provided via --value, --value-hex, --value-base64, --from-file, --stdin or --use-editor".into(),
            ));
        };
        value_bytes
    };

    if value_bytes.len() > MAX_SECRET_SIZE {
        return Err(CliError::InvalidInput(format!(
            "Secret value exceeds maximum allowed size of {} MiB",
            (MAX_SECRET_SIZE / (1024 * 1024))
        )));
    }

    Ok(ApiRequest {
        sec_ref: sec_ref_str,
        value_b64: base64_standard.encode(value_bytes),
        note: args.note.clone(),
        activate: args.activate,
    })
}
