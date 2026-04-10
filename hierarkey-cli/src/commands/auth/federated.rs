// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::auth::{AuthFederatedArgs, PrintField};
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::utils::formatting::parse_ttl;
use hierarkey_server::http_server::handlers::auth_response::AuthResponse;

pub fn auth_federated(client: &ApiClient, cli_args: &CliArgs, args: &AuthFederatedArgs) -> CliResult<()> {
    let ttl_minutes = args
        .ttl
        .as_deref()
        .map(|t| parse_ttl(t).map_err(CliError::InvalidInput))
        .transpose()?;

    // Read credential from file or flag
    let credential = if let Some(path) = &args.credential_file {
        std::fs::read_to_string(path)
            .map_err(|e| CliError::InvalidInput(format!("failed to read credential file '{}': {e}", path.display())))?
            .trim()
            .to_string()
    } else if let Some(c) = &args.credential {
        c.clone()
    } else {
        return Err(CliError::InvalidInput(
            "provide --credential-file <path> or --credential <token>".into(),
        ));
    };

    let mut body = serde_json::json!({ "credential": credential });
    if let Some(ttl) = ttl_minutes {
        body["ttl_minutes"] = serde_json::json!(ttl);
    }

    let resp = client
        .post(&format!("/v1/auth/federated/{}", args.provider_id))
        .json(&body)
        .send()?;
    let data = client.handle_response::<AuthResponse>(resp)?;

    if args.env {
        println!("export HKEY_ACCESS_TOKEN={}", data.access_token.as_str());
        return Ok(());
    }

    if let Some(field) = args.print {
        match field {
            PrintField::AccessToken => println!("{}", data.access_token.as_str()),
            PrintField::RefreshToken => println!("{}", data.refresh_token.as_str()),
            PrintField::ExpiresIn => println!("{}", data.expires_at),
        }
        return Ok(());
    }

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        println!("Provider    : {}", args.provider_id);
        println!("Account     : {}", data.account_name);
        println!("Scope       : {}", data.scope);
        println!("Expires at  : {}", data.expires_at);
        println!("Access Token: {}", data.access_token.as_str());
    }

    Ok(())
}
