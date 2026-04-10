// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::pat::PatRevokeArgs;
use crate::error::CliResult;
use crate::http::ApiClient;

pub fn pat_revoke(client: &ApiClient, cli_args: &CliArgs, args: &PatRevokeArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    if !cli_args.output_json {
        use std::io::{self, Write};
        print!("Are you sure you want to revoke token '{}'? (y/N): ", args.id);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted");
            return Ok(());
        }
    }

    let resp = client
        .delete(&format!("/v1/pat/{}", urlencoding::encode(&args.id)))
        .bearer_auth(token.as_str())
        .send()?;

    client.handle_response_unit(resp)?;

    if cli_args.output_json {
        let success = serde_json::json!({
            "revoked": true,
            "id": args.id,
        });
        println!("{}", serde_json::to_string_pretty(&success)?);
    } else {
        println!("PAT '{}' revoked.", args.id);
    }

    Ok(())
}
