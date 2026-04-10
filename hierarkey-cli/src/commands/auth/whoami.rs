// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::{fmt_bool, fmt_date, fmt_opt_date};
use hierarkey_server::http_server::handlers::auth_response::WhoamiResponse;
use hierarkey_server::service::account::AccountType;

fn fmt_opt_str(v: Option<String>, none: &str) -> String {
    v.unwrap_or_else(|| none.to_string())
}

fn print_kv(label: &str, value: impl AsRef<str>) {
    let key = format!("{label}:");
    println!("  {:<20} {}", key, value.as_ref());
}

pub fn auth_whoami(client: &ApiClient, cli_args: &CliArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client.get("/v1/auth/whoami").bearer_auth(token.as_str()).send()?;
    let data: WhoamiResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data.account)?);
        return Ok(());
    }

    print_kv("User Name", &data.account.account_name);
    print_kv("User ID", data.account.id.to_string());

    let account_type = match data.account.account_type {
        AccountType::Service => "service",
        AccountType::User => "user",
        AccountType::System => "system",
    };
    print_kv("Type", account_type);

    print_kv("Status", data.account.status.to_string().to_uppercase());
    print_kv("MFA enabled", fmt_bool(data.account.mfa_enabled, "YES", "NO"));

    match data.account.locked_until {
        Some(until) => print_kv("Locked", format!("yes (until {})", fmt_date(until))),
        None => print_kv("Locked", "no"),
    }

    print_kv("Full name", fmt_opt_str(data.account.full_name, "-"));
    print_kv("Email", fmt_opt_str(data.account.email, "-"));
    print_kv("Created", fmt_date(data.account.created_at));
    print_kv("Updated", fmt_opt_date(data.account.updated_at, "-"));

    println!();
    println!("TOKEN (PAT):");
    print_kv("Token ID", data.token.short_id.clone());
    print_kv("Description", data.token.description);
    print_kv("Created", fmt_date(data.token.created_at));
    print_kv("Last used", fmt_opt_date(data.token.last_used_at, "Never"));
    print_kv("Expires", fmt_date(data.token.expires_at));

    Ok(())
}
