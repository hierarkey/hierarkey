// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretUpdateArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::api::status::Outcome;
use hierarkey_core::resources::SecretRef;
use hierarkey_core::{Labels, parse_labels, validate_labels};
use hierarkey_server::http_server::handlers::secret_response::SecretResponse;
use serde::Serialize;

#[derive(Serialize, Debug)]
struct ApiRequest {
    description: Option<String>,
    updated_labels: Labels,
    remove_labels: Vec<String>,
    clear_description: bool,
    clear_labels: bool,
}

pub fn secret_update(client: &ApiClient, cli_args: &CliArgs, args: &SecretUpdateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.id.is_some() {
        // Short ID — send directly
        args.sec_ref_value().to_string()
    } else {
        let sec_ref =
            SecretRef::from_string(args.sec_ref_value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        if sec_ref.revision.is_some() {
            return Err(CliError::InvalidInput("Cannot specify revision when updating a secret".into()));
        }
        urlencoding::encode(&sec_ref.to_string()[1..]).into_owned()
    };

    // Parse labels
    validate_labels(&args.labels).map_err(|e| CliError::InvalidInput(e.to_string()))?;
    let updated_labels = parse_labels(&args.labels);

    // Can't clear and update description
    if args.clear_description && args.description.is_some() {
        return Err(CliError::InvalidInput(
            "Cannot clear description while also setting a new description".into(),
        ));
    }
    // Check if any of the updated labels are also part of the remove list
    for key in args.remove_labels.iter() {
        if updated_labels.contains_key(key) {
            return Err(CliError::InvalidInput(format!(
                "Cannot both update and remove the same label '{key}'",
            )));
        }
    }

    let payload = ApiRequest {
        description: args.description.clone(),
        updated_labels,
        clear_labels: args.clear_labels,
        clear_description: args.clear_description,
        remove_labels: args.remove_labels.clone(),
    };

    let resp = client
        .patch(&format!("/v1/secrets/{param}"))
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<SecretResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else if resp_body.status.outcome == Outcome::Failure {
        println!("Failed to update secret: {}", resp_body.status.message);
    } else {
        println!("Secret '{}' updated successfully.", args.sec_ref_value());
        println!();
        println!("You can describe the secret with the 'describe' command to see the details:");
        println!("  hkey secret describe --ref {}", args.sec_ref_value());
    }

    Ok(())
}
