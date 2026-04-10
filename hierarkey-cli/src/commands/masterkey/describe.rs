// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::masterkey::{MasterkeyDescribeArgs, print_describe_masterkey};
use crate::error::CliResult;
use crate::http::ApiClient;
use hierarkey_server::http_server::handlers::masterkey_response::MasterKeyStatusResponse;

pub fn masterkey_describe(client: &ApiClient, cli_args: &CliArgs, args: &MasterkeyDescribeArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .get(&format!("/v1/masterkeys/{}", args.selector.value()))
        .bearer_auth(token)
        .send()?;
    let data: MasterKeyStatusResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        print_describe_masterkey(data);
    }

    Ok(())
}
