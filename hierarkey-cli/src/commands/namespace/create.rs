// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::namespace::NamespaceCreateArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::api::status::Outcome;
use hierarkey_core::resources::NamespaceString;
use hierarkey_core::{Labels, parse_labels, validate_labels};
use hierarkey_server::http_server::handlers::namespace_response::NamespaceResponse;
use serde::Serialize;
use std::str::FromStr;

#[derive(Serialize, Debug)]
struct ApiRequest {
    namespace: String,
    description: Option<String>,
    labels: Labels,
}

pub fn namespace_create(client: &ApiClient, cli_args: &CliArgs, args: &NamespaceCreateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    // Parse and validate namespace
    let ns = NamespaceString::from_str(&args.namespace).map_err(|e| CliError::InvalidInput(e.to_string()))?;
    if ns.is_reserved() {
        return Err(CliError::InvalidInput(
            "Cannot create reserved namespaces starting with a $".into(),
        ));
    }

    // Parse labels
    validate_labels(&args.labels).map_err(|e| CliError::InvalidInput(e.to_string()))?;

    let payload = ApiRequest {
        namespace: ns.to_string(),
        description: args.description.clone(),
        labels: parse_labels(&args.labels),
    };

    let resp = client.post("/v1/namespaces").bearer_auth(token).json(&payload).send()?;
    let resp_body = client.handle_full_response::<NamespaceResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else if resp_body.status.outcome == Outcome::Failure {
        println!("Failed to create namespace: {}", resp_body.status.message);
    } else {
        println!("Namespace '{}' created successfully.", args.namespace);
        println!();
        if let Some(ns_data) = resp_body.data {
            super::print_describe_namespace(ns_data);
            println!();
        }
        println!("Next steps:");
        println!("  hkey namespace describe --namespace {}", args.namespace);
        println!("  hkey secret create --ref {}:my-secret --value 'secret_value'", args.namespace);
    }

    Ok(())
}
