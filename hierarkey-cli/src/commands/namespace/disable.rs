// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::namespace::NamespaceDisableArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::resources::NamespaceString;
use std::str::FromStr;

pub fn namespace_disable(client: &ApiClient, cli_args: &CliArgs, args: &NamespaceDisableArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.selector.is_short_id() {
        args.selector.value().to_string()
    } else {
        // Parse and validate namespace
        let ns = NamespaceString::from_str(args.selector.value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        if ns.is_reserved() {
            return Err(CliError::InvalidInput(
                "Cannot create reserved namespaces starting with a $".into(),
            ));
        }
        urlencoding::encode(&ns.to_string()[1..]).into_owned()
    };

    let resp = client
        .post(&format!("/v1/namespaces/{param}/disable"))
        .bearer_auth(token.as_str())
        .send()?;
    let resp_body = client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else {
        println!("Namespace '{}' disabled successfully.", args.selector.value());
        println!();
        println!("You can re-enable the namespace with the 'enable' command:");
        println!("  hkey namespace enable --namespace {}", args.selector.value());
    }

    Ok(())
}
