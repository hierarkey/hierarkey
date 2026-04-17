// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretDisableArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::resources::SecretRef;

pub fn secret_disable(client: &ApiClient, cli_args: &CliArgs, args: &SecretDisableArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.id.is_some() {
        args.sec_ref_value().to_string()
    } else {
        let sec_ref =
            SecretRef::from_string(args.sec_ref_value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        urlencoding::encode(&sec_ref.to_string()[1..]).into_owned()
    };

    let resp = client
        .post(&format!("/v1/secrets/{param}/disable"))
        .bearer_auth(token.as_str())
        .send()?;
    client.handle_response_unit(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::json!({ "disabled": true, "ref": args.sec_ref_value() }));
    } else {
        println!("Secret '{}' disabled successfully.", args.sec_ref_value());
    }

    Ok(())
}
