// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::masterkey::MasterkeyLockArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use hierarkey_core::api::status::{ApiCode, Outcome};
use serde::Serialize;

#[derive(Serialize)]
pub struct ApiRequest {
    reason: Option<String>,
}

pub fn masterkey_lock(client: &ApiClient, cli_args: &CliArgs, args: &MasterkeyLockArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let data = ApiRequest {
        reason: args.reason.clone(),
    };

    let resp = client
        .post(&format!("/v1/masterkeys/{}/lock", args.selector.value()))
        .bearer_auth(token)
        .json(&data)
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

    if resp_body.status.code == ApiCode::MasterKeyAlreadyLocked {
        println!("Master key '{}' is already locked.", args.selector.value());
        return Ok(());
    }

    println!("Master key '{}' locked successfully.", args.selector.value());
    Ok(())
}
