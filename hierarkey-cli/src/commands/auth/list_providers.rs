// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::clip;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct FederatedProviderEntry {
    pub id: String,
    pub provider: String,
    #[serde(default)]
    pub issuer: String,
    pub audience: Option<String>,
    pub jwks_url: Option<String>,
}

pub fn auth_list_providers(client: &ApiClient, cli_args: &CliArgs) -> CliResult<()> {
    let resp = client.get("/v1/auth/federated").send()?;
    let providers = client.handle_response::<Vec<FederatedProviderEntry>>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&providers)?);
    } else if providers.is_empty() {
        println!("No federated authentication providers configured.");
    } else {
        println!("{:<16} {:<18} {:<52} AUDIENCE", "ID", "TYPE", "ISSUER / JWKS URL");
        println!("{}", "-".repeat(100));
        for p in &providers {
            let url = if !p.issuer.is_empty() {
                p.issuer.as_str()
            } else {
                p.jwks_url.as_deref().unwrap_or("-")
            };
            println!(
                "{:<16} {:<18} {:<52} {}",
                clip(&p.id, 16),
                clip(&p.provider, 18),
                clip(url, 52),
                p.audience.as_deref().unwrap_or("-"),
            );
        }
    }

    Ok(())
}
