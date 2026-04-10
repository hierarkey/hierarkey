// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretDeleteArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::resources::SecretRef;

pub fn secret_delete(client: &ApiClient, cli_args: &CliArgs, args: &SecretDeleteArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.id.is_some() {
        // Short ID — send directly

        // Short IDs can't have revisions
        args.sec_ref_value().to_string()
    } else {
        let sec_ref =
            SecretRef::from_string(args.sec_ref_value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        if sec_ref.revision.is_some() {
            return Err(CliError::InvalidInput(
                "Cannot specify a revision when deleting a secret".into(),
            ));
        }
        urlencoding::encode(&sec_ref.to_string()[1..]).into_owned()
    };

    if !args.confirm && !cli_args.output_json {
        use std::io::{self, Write};
        print!("Are you sure you want to delete '{}'? (y/N): ", args.sec_ref_value());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted");
            return Ok(());
        }
    }

    let resp = client
        .delete(&format!("/v1/secrets/{param}"))
        .bearer_auth(token.as_str())
        .send()?;

    client.handle_response_unit(resp)?;

    if cli_args.output_json {
        let success = serde_json::json!({ "deleted": true, "ref": args.sec_ref_value() });
        println!("{}", serde_json::to_string_pretty(&success)?);
    } else {
        println!("Secret '{}' deleted.", args.sec_ref_value());
    }

    Ok(())
}
