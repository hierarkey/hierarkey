// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijussen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretRestoreArgs;
use crate::error::CliResult;
use crate::http::ApiClient;

pub fn secret_restore(client: &ApiClient, cli_args: &CliArgs, args: &SecretRestoreArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .post(&format!("/v1/secrets/{}/restore", args.id))
        .bearer_auth(token.as_str())
        .send()?;
    client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::json!({ "restored": true, "id": args.id }));
    } else {
        println!("Secret '{}' restored successfully.", args.id);
    }

    Ok(())
}
