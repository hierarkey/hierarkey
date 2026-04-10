// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use clap::Subcommand;
use hierarkey_server::service::license::LicenseStatusDto;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum LicenseCommand {
    /// Show license tier, features, and expiry
    Status,

    /// Install or replace the active license
    Set {
        /// Path to the license JSON file produced by hkey-license create
        #[arg(long = "from-file", value_name = "FILE")]
        from_file: PathBuf,
    },

    /// Remove the active license (reverts to Community tier)
    Remove,
}

pub fn license_status(client: &ApiClient, cli_args: &CliArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client.get("/v1/system/license").bearer_auth(token).send()?;
    let data = client.handle_response::<LicenseStatusDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    println!("LICENSE");
    println!("  {:<20} {}", "Tier:", data.tier);
    println!("  {:<20} {}", "Licensee:", data.licensee.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "License ID:", data.license_id.as_deref().unwrap_or("-"));
    println!(
        "  {:<20} {}",
        "Expires:",
        data.expires_at
            .map(|d| d.to_string())
            .unwrap_or_else(|| "never".to_string())
    );
    if data.is_expired {
        println!("  {:<20} YES", "EXPIRED:");
    }
    if data.is_community_fallback {
        println!();
        println!("Note: Running without a license (Community tier).");
    }
    println!();

    Ok(())
}

pub fn license_set(client: &ApiClient, cli_args: &CliArgs, from_file: &PathBuf) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let json = std::fs::read_to_string(from_file)
        .map_err(|e| crate::error::CliError::Other(format!("cannot read {}: {e}", from_file.display())))?;

    // Parse to validate JSON, then send as the request body
    let license: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| crate::error::CliError::Other(format!("invalid license JSON: {e}")))?;

    let resp = client
        .put("/v1/system/license")
        .bearer_auth(token)
        .json(&license)
        .send()?;
    let data = client.handle_response::<LicenseStatusDto>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    println!("License installed successfully.");
    println!("  {:<20} {}", "Tier:", data.tier);
    println!("  {:<20} {}", "Licensee:", data.licensee.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "License ID:", data.license_id.as_deref().unwrap_or("-"));
    println!(
        "  {:<20} {}",
        "Expires:",
        data.expires_at
            .map(|d| d.to_string())
            .unwrap_or_else(|| "never".to_string())
    );
    println!();

    Ok(())
}

pub fn license_remove(client: &ApiClient, cli_args: &CliArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client.delete("/v1/system/license").bearer_auth(token).send()?;
    client.handle_response::<()>(resp)?;

    println!("License removed. Server reverted to Community tier.");
    println!();

    Ok(())
}
