// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::{OutputFormat, SecretRevealArgs};
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use base64::Engine;
use hierarkey_core::resources::SecretRef;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize, Serialize)]
struct SecretRevealResponse {
    sec_ref: String,
    value_b64: String,
}

pub fn secret_reveal(client: &ApiClient, cli_args: &CliArgs, args: &SecretRevealArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let sec_ref = SecretRef::from_string(&args.sec_ref).map_err(|e| CliError::InvalidInput(e.to_string()))?;

    let resp = client
        .post("/v1/secrets/reveal")
        .json(&json!({
            "sec_ref": sec_ref.to_string(),
        }))
        .bearer_auth(token.as_str())
        .send()?;

    let body = client.handle_response::<SecretRevealResponse>(resp)?;

    let want_hex = args.hex || args.output == Some(OutputFormat::Hex);
    let want_b64 = args.base64 || args.output == Some(OutputFormat::Base64);

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else if want_hex {
        let value_bytes = base64::engine::general_purpose::STANDARD
            .decode(&body.value_b64)
            .map_err(|e| CliError::InvalidInput(format!("Failed to decode secret value from base64: {e}")))?;
        println!("0x{}", hex::encode(value_bytes).to_uppercase());
    } else if want_b64 {
        println!("{}", body.value_b64);
    } else {
        let value_bytes = base64::engine::general_purpose::STANDARD
            .decode(&body.value_b64)
            .map_err(|e| CliError::InvalidInput(format!("Failed to decode secret value from base64: {e}")))?;
        let value_str = String::from_utf8(value_bytes).map_err(|_| {
            CliError::InvalidInput("Secret might be binary. Try --hex or --base64 instead.".to_string())
        })?;
        print!("{value_str}");
    }

    Ok(())
}
