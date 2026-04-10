// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::account::AccountDescribeArgs;
use crate::commands::account::federated_identity::FederatedIdentityResponse;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::utils::formatting::{fmt_bool, fmt_date, fmt_labels, fmt_opt_date};
use hierarkey_server::http_server::handlers::account_response::AccountSearchResponse;
use hierarkey_server::service::account::{AccountSearchQuery, AccountType};
use hierarkey_server::{AccountDto, AccountRef};

pub fn account_describe(client: &ApiClient, cli_args: &CliArgs, args: &AccountDescribeArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    // When --id is given, resolve via prefix search first.
    let identifier = if let Some(id) = args.account.id.as_deref() {
        let q = AccountSearchQuery {
            id_prefix: Some(id.to_string()),
            limit: Some(11), // enough to detect ambiguity
            ..Default::default()
        };

        let resp = client
            .post("/v1/accounts/search")
            .bearer_auth(token.as_str())
            .json(&serde_json::json!(q))
            .send()?;
        let data = client.handle_response::<AccountSearchResponse>(resp)?;

        match data.entries.len() {
            0 => {
                return Err(CliError::InvalidInput(format!("No account found with ID matching '{id}'")));
            }
            1 => data
                .entries
                .into_iter()
                .next()
                .ok_or_else(|| CliError::InvalidInput("Unexpected empty result".to_string()))?
                .account_name
                .to_string(),
            n => {
                let shown: Vec<String> = data
                    .entries
                    .iter()
                    .take(10)
                    .map(|a| format!("  {} ({})", a.account_name, a.id))
                    .collect();
                let suffix = if n > 10 {
                    format!("\n  ... and {} more", n - 10)
                } else {
                    String::new()
                };
                return Err(CliError::InvalidInput(format!(
                    "{n} accounts match '{id}':\n{}{}",
                    shown.join("\n"),
                    suffix
                )));
            }
        }
    } else {
        args.account.value().to_string()
    };

    let resp = client
        .get(&format!("/v1/accounts/{identifier}"))
        .bearer_auth(&token)
        .send()?;
    let data = client.handle_response::<AccountDto>(resp)?;

    let fed_identity: Option<FederatedIdentityResponse> = if data.account_type == AccountType::Service {
        let resp = client
            .get(&format!("/v1/accounts/{identifier}/federated-identity"))
            .bearer_auth(&token)
            .send()?;
        if resp.status().as_u16() == 404 {
            None
        } else {
            Some(client.handle_response::<FederatedIdentityResponse>(resp)?)
        }
    } else {
        None
    };

    if cli_args.output_json {
        let mut json = serde_json::to_value(&data)?;
        if let Some(fi) = &fed_identity {
            json["federated_identity"] = serde_json::to_value(fi)?;
        }
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        print_account_describe(&data);
        if let Some(fi) = &fed_identity {
            println!();
            println!("FEDERATED IDENTITY:");
            println!("  {:<20} {}", "Provider ID:", fi.provider_id);
            println!("  {:<20} {}", "Issuer:", fi.external_issuer);
            println!("  {:<20} {}", "Subject:", fi.external_subject);
            println!("  {:<20} {}", "Linked at:", fmt_date(fi.created_at));
        }
    }

    Ok(())
}

pub fn print_account_describe(account: &AccountDto) {
    println!("  {:<20} {}", "Identifier:", account.id);
    println!("  {:<20} {}", "Name:", account.account_name);
    println!("  {:<20} {}", "Full Name:", account.full_name.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "Email:", account.email.as_deref().unwrap_or("-"));

    let reason = match &account.status_reason {
        Some(reason) => format!("({reason})"),
        None => "".to_string(),
    };
    println!(
        "  {:<20} {}",
        "Status:",
        format!("{} {}", account.status.to_string().to_uppercase(), reason).trim()
    );
    println!("  {:<20} {}", "Type:", account.account_type);
    println!("  {:<20} {}", "MFA enabled:", fmt_bool(account.mfa_enabled, "YES", "NO"));

    println!();
    println!("SECURITY:");
    println!(
        "  {:<20} {}",
        "Must change pw:",
        fmt_bool(account.must_change_password, "YES", "NO")
    );
    println!(
        "  {:<20} {}",
        "Password changed:",
        fmt_opt_date(account.password_changed_at, "-")
    );
    println!("  {:<20} {}", "Last login at:", fmt_opt_date(account.last_login_at, "Never"));
    println!("  {:<20} {}", "Failed logins:", account.failed_login_attempts);
    if let Some(locked_until) = account.locked_until {
        println!("  {:<20} {}", "Locked until:", fmt_date(locked_until));
    }

    println!();
    println!("METADATA:");
    let description = account.metadata.description();
    println!("  {:<20} {}", "Description:", description.as_deref().unwrap_or("-"));
    let labels = account.metadata.labels();
    println!("  {:<20} {}", "Labels:", fmt_labels(&labels));
    println!("  {:<20} {}", "Created at:", fmt_date(account.created_at));
    println!("  {:<20} {}", "Created by:", fmt_account_ref(account.created_by.as_ref()));
    println!("  {:<20} {}", "Updated at:", fmt_opt_date(account.updated_at, "-"));
    if account.updated_by.is_some() {
        println!("  {:<20} {}", "Updated by:", fmt_account_ref(account.updated_by.as_ref()));
    } else {
        println!("  {:<20} -", "Updated by:");
    }
    println!("  {:<20} {}", "Deleted at:", fmt_opt_date(account.deleted_at, "-"));
    if account.deleted_by.is_some() {
        println!("  {:<20} {}", "Deleted by:", fmt_account_ref(account.deleted_by.as_ref()));
    }
}

fn fmt_account_ref(r: Option<&AccountRef>) -> String {
    match r {
        Some(r) => format!("{} ({})", r.name, r.id),
        None => "-".to_string(),
    }
}
