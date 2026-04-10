// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretActivateArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::api::status::Outcome;
use hierarkey_core::resources::SecretRef;
use hierarkey_server::http_server::handlers::secret_response::SecretResponse;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ApiRequest {
    reason: Option<String>,
}

pub fn secret_activate(client: &ApiClient, cli_args: &CliArgs, args: &SecretActivateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.id.is_some() {
        // Short ID — send directly (no revision needed for short-id)
        args.sec_ref_value().to_string()
    } else {
        let sec_ref =
            SecretRef::from_string(args.sec_ref_value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        if sec_ref.revision.is_none() {
            return Err(CliError::InvalidInput(
                "Secret reference must include a revision when activating a revision".into(),
            ));
        }
        urlencoding::encode(&sec_ref.to_string()[1..]).into_owned()
    };

    let payload = ApiRequest {
        reason: args.reason.clone(),
    };

    let resp = client
        .post(&format!("/v1/secrets/{param}/activate"))
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<SecretResponse>(resp)?;

    // Display ref for human-readable output
    let display_ref = args.sec_ref_value();

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body.status)?);
    } else if resp_body.status.outcome == Outcome::Failure {
        println!("Failed to activate secret revision: {}", resp_body.status.message);
    } else {
        println!("Secret revision '{display_ref}' activated successfully.");
        println!();
        println!("You can describe the secret with the 'describe' command to see the details:");
        println!("  hkey secret describe --ref {display_ref}");
        println!();
        println!("You can reveal the secret with the 'reveal' command to see its contents:");
        println!("  hkey secret reveal --ref {display_ref}");
    }

    Ok(())
}
