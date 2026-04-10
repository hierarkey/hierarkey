// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::masterkey::MasterkeyPkcs11TokensArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use hierarkey_server::service::masterkey::MasterKeyPkcs11TokenInfo as Pkcs11TokenInfo;

pub fn masterkey_pkcs11_tokens(
    client: &ApiClient,
    cli_args: &CliArgs,
    _args: &MasterkeyPkcs11TokensArgs,
) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client.get("/v1/masterkeys/pkcs11/tokens").bearer_auth(token).send()?;

    let tokens: Vec<Pkcs11TokenInfo> = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&tokens)?);
        return Ok(());
    }

    if tokens.is_empty() {
        println!("No PKCS#11 tokens found.");
        return Ok(());
    }

    println!(
        "{:<12} {:<33} {:<33} {:<17} SERIAL",
        "SLOT ID", "LABEL", "MANUFACTURER", "MODEL"
    );
    for t in &tokens {
        println!(
            "{:<12} {:<33} {:<33} {:<17} {}",
            t.slot_id, t.label, t.manufacturer, t.model, t.serial
        );
    }

    Ok(())
}
