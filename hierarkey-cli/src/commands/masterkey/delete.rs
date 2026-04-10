// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::masterkey::MasterkeyDeleteArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use hierarkey_core::api::status::Outcome;

pub fn masterkey_delete(client: &ApiClient, cli_args: &CliArgs, args: &MasterkeyDeleteArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .delete(&format!("/v1/masterkeys/{}", args.selector.value()))
        .bearer_auth(token)
        .send()?;
    let resp_body = client.handle_response_unit(resp)?;

    if resp_body.status.outcome != Outcome::Success {
        println!(
            "Failed to delete master key '{}': {}",
            args.selector.value(),
            resp_body.status.message
        );
        return Ok(());
    }

    println!("Master key '{}' deleted successfully.", args.selector.value());
    Ok(())
}
