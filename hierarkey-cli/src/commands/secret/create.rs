// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretCreateArgs;
use crate::commands::secret::describe::print_secret_describe;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::values::{ValueSource, resolve_value};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_standard;
use hierarkey_core::api::search::query::SecretType;
use hierarkey_core::api::status::Outcome;
use hierarkey_core::resources::SecretRef;
use hierarkey_core::{Labels, MAX_SECRET_SIZE, parse_labels, validate_labels};
use hierarkey_server::http_server::handlers::secret_response::SecretResponse;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ApiRequest {
    sec_ref: String,
    value_b64: String,
    secret_type: SecretType,
    description: Option<String>,
    labels: Labels,
}

pub fn secret_create(client: &ApiClient, cli_args: &CliArgs, args: &SecretCreateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let payload = create_request_from_args(args)?;

    let resp = client
        .post("/v1/secrets")
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<SecretResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else if resp_body.status.outcome == Outcome::Failure {
        println!("Failed to create secret: {}", resp_body.status.message);
    } else {
        println!("Secret '{}' created successfully.", payload.sec_ref);
        println!();
        if let Some(data) = &resp_body.data {
            print_secret_describe(data);
            println!();
        }
        println!("Next steps:");
        println!("  hkey secret describe --ref {}", payload.sec_ref);
        println!("  hkey secret reveal --ref {}", payload.sec_ref);
    }

    Ok(())
}

fn create_request_from_args(args: &SecretCreateArgs) -> CliResult<ApiRequest> {
    let sec_ref = SecretRef::from_string(&args.sec_ref).map_err(|e| CliError::InvalidInput(e.to_string()))?;
    if sec_ref.revision.is_some() {
        return Err(CliError::InvalidInput(
            "Secret reference must not include a revision when creating a secret".into(),
        ));
    }

    validate_labels(&args.labels).map_err(|e| CliError::InvalidInput(e.to_string()))?;

    let value_source = ValueSource::try_from(args).map_err(|e| CliError::InvalidInput(e.to_string()))?;
    let value_bytes = resolve_value(value_source)?;
    let Some(value_bytes) = value_bytes else {
        return Err(CliError::InvalidInput(
            "Secret value must be provided via --value, --value-hex, --value-base64, --from-file, --stdin or --use-editor".into(),
        ));
    };

    if value_bytes.len() > MAX_SECRET_SIZE {
        return Err(CliError::InvalidInput(format!(
            "Secret value exceeds maximum allowed size of {} MiB",
            MAX_SECRET_SIZE / (1024 * 1024)
        )));
    }

    Ok(ApiRequest {
        sec_ref: sec_ref.to_string(),
        value_b64: base64_standard.encode(value_bytes),
        secret_type: args.sec_type.unwrap_or(SecretType::Opaque),
        description: args.description.clone(),
        labels: parse_labels(&args.labels),
    })
}
