// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::masterkey::MasterkeyActivateArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use hierarkey_core::api::status::{ApiCode, Outcome};

pub fn masterkey_activate(client: &ApiClient, cli_args: &CliArgs, args: &MasterkeyActivateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .post(&format!("/v1/masterkeys/{}/activate", args.selector.value()))
        .bearer_auth(token)
        .send()?;
    let resp_body = client.handle_response_unit(resp)?;

    if resp_body.status.outcome != Outcome::Success {
        println!(
            "Failed to lock master key '{}': {}",
            args.selector.value(),
            resp_body.status.message
        );
        return Ok(());
    }

    if resp_body.status.code == ApiCode::MasterKeyAlreadyActivated {
        println!("Masterkey '{}' is already activated.", args.selector.value());
        return Ok(());
    }

    println!("Masterkey '{}' activated successfully.", args.selector.value());
    println!();
    println!("The previous active master key is now draining. Rewrap its KEKs to use the new master key:");
    println!("  hkey rewrap kek --from <previous-key-name>");
    Ok(())
}
