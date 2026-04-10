// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::namespace::NamespaceUpdateArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::api::status::Outcome;
use hierarkey_core::resources::NamespaceString;
use hierarkey_core::{Labels, parse_labels, validate_labels};
use hierarkey_server::http_server::handlers::namespace_response::NamespaceResponse;
use serde::Serialize;
use std::str::FromStr;

#[derive(Serialize)]
struct ApiRequest {
    namespace: String,
    description: Option<String>,
    updated_labels: Labels,
    remove_labels: Vec<String>,
    clear_description: bool,
    clear_labels: bool,
}

pub fn namespace_update(client: &ApiClient, cli_args: &CliArgs, args: &NamespaceUpdateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.selector.is_short_id() {
        args.selector.value().to_string()
    } else {
        // Parse and validate namespace
        let ns = NamespaceString::from_str(args.selector.value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        if ns.is_reserved() {
            return Err(CliError::InvalidInput(
                "Cannot create namespaces starting with a $ (reserved)".into(),
            ));
        }
        urlencoding::encode(&ns.to_string()[1..]).into_owned()
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
    for key in &args.remove_labels {
        if updated_labels.contains_key(key) {
            return Err(CliError::InvalidInput(format!(
                "Cannot both update and remove the same label '{key}'"
            )));
        }
    }

    let payload = ApiRequest {
        namespace: args.selector.value().to_string(),
        description: args.description.clone(),
        updated_labels,
        clear_labels: args.clear_labels,
        clear_description: args.clear_description,
        remove_labels: args.remove_labels.clone(),
    };

    let resp = client
        .patch(&format!("/v1/namespaces/{param}"))
        .bearer_auth(token)
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<NamespaceResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else if resp_body.status.outcome == Outcome::Failure {
        println!("Failed to update namespace: {}", resp_body.status.message);
    } else {
        println!("Namespace '{}' updated successfully.", args.selector.value());
        println!();
        println!("You can describe the namespace with the 'describe' command to see the details:");
        println!("  hkey namespace describe --namespace {}", args.selector.value());
    }

    Ok(())
}
