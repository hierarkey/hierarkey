// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::account::{
    AccountDescribeFederatedIdentityArgs, AccountLinkFederatedIdentityArgs, AccountUnlinkFederatedIdentityArgs,
};
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::fmt_date;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct FederatedIdentityResponse {
    pub provider_id: String,
    pub external_issuer: String,
    pub external_subject: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub fn account_link_federated_identity(
    client: &ApiClient,
    cli_args: &CliArgs,
    args: &AccountLinkFederatedIdentityArgs,
) -> CliResult<()> {
    let token = cli_args.require_token()?;
    let account = args.account.value();

    let resp = client
        .post(&format!("/v1/accounts/{account}/federated-identity"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "provider_id":       args.provider_id,
            "external_issuer":   args.external_issuer,
            "external_subject":  args.external_subject,
        }))
        .send()?;
    client.handle_response::<FederatedIdentityResponse>(resp)?;

    println!("Federated identity linked to account '{account}'.");
    Ok(())
}

pub fn account_describe_federated_identity(
    client: &ApiClient,
    cli_args: &CliArgs,
    args: &AccountDescribeFederatedIdentityArgs,
) -> CliResult<()> {
    let token = cli_args.require_token()?;
    let account = args.account.value();

    let resp = client
        .get(&format!("/v1/accounts/{account}/federated-identity"))
        .bearer_auth(token)
        .send()?;
    let data = client.handle_response::<FederatedIdentityResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        println!("  {:<20} {}", "Provider ID:", data.provider_id);
        println!("  {:<20} {}", "Issuer:", data.external_issuer);
        println!("  {:<20} {}", "Subject:", data.external_subject);
        println!("  {:<20} {}", "Linked at:", fmt_date(data.created_at));
    }

    Ok(())
}

pub fn account_unlink_federated_identity(
    client: &ApiClient,
    cli_args: &CliArgs,
    args: &AccountUnlinkFederatedIdentityArgs,
) -> CliResult<()> {
    let token = cli_args.require_token()?;
    let account = args.account.value();

    let resp = client
        .delete(&format!("/v1/accounts/{account}/federated-identity"))
        .bearer_auth(token)
        .send()?;
    client.handle_response_unit(resp)?;

    println!("Federated identity unlinked from account '{account}'.");
    Ok(())
}
