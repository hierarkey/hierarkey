// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::account::AccountDeleteArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use hierarkey_core::api::status::Outcome;

pub fn account_delete(client: &ApiClient, cli_args: &CliArgs, args: &AccountDeleteArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let account = args.account.value();
    let resp = client
        .delete(&format!("/v1/accounts/{account}"))
        .bearer_auth(token)
        .send()?;
    let resp_body = client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body)?);
    } else if resp_body.status.outcome == Outcome::Failure {
        println!("Account '{account}' could not be deleted.");
    } else {
        println!("Account '{account}' deleted successfully.");
    }

    Ok(())
}
