// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::namespace::NamespaceDeleteArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::resources::NamespaceString;
use std::str::FromStr;

pub fn namespace_delete(client: &ApiClient, cli_args: &CliArgs, args: &NamespaceDeleteArgs) -> CliResult<()> {
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

    if !args.confirm && !cli_args.output_json {
        use std::io::{self, Write};
        println!(
            "WARNING: you are about to DELETE namespace '{}' including its secrets. This option cannot be undone!",
            args.selector.value()
        );
        print!("Please type 'i agree' to confirm: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim() != "i agree" {
            println!("Aborted deleting namespace '{}'", args.selector.value());
            return Ok(());
        }
    }

    let url = if args.delete_secrets {
        format!("/v1/namespaces/{param}?delete_secrets=true")
    } else {
        format!("/v1/namespaces/{param}")
    };

    let resp = client.delete(&url).bearer_auth(token.as_str()).send()?;
    let resp_body = client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else {
        println!("Namespace '{}' deleted.", args.selector.value());
    }

    Ok(())
}
