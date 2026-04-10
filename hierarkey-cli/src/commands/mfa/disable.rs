// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::error::CliResult;
use crate::http::ApiClient;

pub fn mfa_disable(client: &ApiClient, cli_args: &CliArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    if !cli_args.output_json {
        use std::io::{self, Write};
        print!("Are you sure you want to disable MFA for your account? (y/N): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let resp = client.delete("/v1/auth/mfa").bearer_auth(token.as_str()).send()?;
    client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "disabled": true }))?);
    } else {
        println!("MFA has been disabled.");
    }

    Ok(())
}
