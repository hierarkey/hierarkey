// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::ApiClient;
use crate::cli::CliArgs;
use crate::error::CliResult;
use crate::utils::formatting::clip;
use hierarkey_server::http_server::handlers::readyz::ReadyzResponse;
use hierarkey_server::http_server::handlers::system::SystemStatusDto;

pub fn status(client: &ApiClient, cli_args: &CliArgs) -> CliResult<()> {
    let resp = client.get("/readyz").send()?;
    let readyz: ReadyzResponse = resp.json()?;

    println!("VAULT");
    println!("  {:<20} {} (vault={})", "Status:", readyz.status, readyz.vault);
    if let Some(reason) = &readyz.reason {
        println!("  {:<20} {}", "Reason:", reason);
    }
    if readyz.locked_keys.is_empty() {
        println!("  {:<20} none", "Locked keys:");
    } else {
        println!("  {:<20} {}", "Locked keys:", readyz.locked_keys.len());
        println!();
        println!("  {:<12}  {:<20}  {:<10}  {:<10}", "ID", "NAME", "PROVIDER", "STATUS");
        for k in &readyz.locked_keys {
            println!(
                "  {:<12}  {:<20}  {:<10}  {:<10}",
                clip(&k.id, 12),
                clip(&k.name, 20),
                clip(&k.provider, 10),
                clip(&k.status, 10),
            );
        }
    }

    let token = match &cli_args.token {
        Some(t) => t.clone(),
        None => {
            println!();
            println!("Tip: Log in to see full system statistics.");
            return Ok(());
        }
    };

    let resp = client.get("/v1/system/status").bearer_auth(token.as_str()).send()?;

    let sys: SystemStatusDto = match client.handle_response(resp) {
        Ok(data) => data,
        Err(_) => {
            println!();
            println!("Tip: Platform admin role required for system statistics.");
            return Ok(());
        }
    };

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&sys)?);
        return Ok(());
    }

    if !sys.warnings.is_empty() {
        println!();
        println!("WARNINGS ({}):", sys.warnings.len());
        for w in &sys.warnings {
            println!("  ! {w}");
        }
    }

    println!();
    println!("NAMESPACES");
    println!(
        "  {:<20} {}  ({} disabled)",
        "Total:", sys.namespaces.total, sys.namespaces.disabled
    );

    println!();
    println!("SECRETS");
    println!("  {:<20} {}", "Total:", sys.secrets.total);
    println!("  {:<20} {}", "Active:", sys.secrets.active);
    if sys.secrets.stale_kek > 0 {
        println!("  {:<20} {} (need re-wrap)", "Stale KEK:", sys.secrets.stale_kek);
    } else {
        println!("  {:<20} none", "Stale KEK:");
    }

    println!();
    println!("ACCOUNTS");
    println!(
        "  {:<20} {}  ({} active)",
        "Users:", sys.accounts.users, sys.accounts.users_active
    );
    println!(
        "  {:<20} {}  ({} active)",
        "Service accounts:", sys.accounts.service_accounts, sys.accounts.service_accounts_active
    );
    println!("  {:<20} {}", "Admins:", sys.accounts.admins);

    println!();
    println!("MASTER KEYS");
    println!(
        "  {:<20} {}  ({} active, {} retired, {} locked)",
        "Total:", sys.masterkeys.total, sys.masterkeys.active, sys.masterkeys.retired, sys.masterkeys.locked,
    );

    println!();
    println!("KEY ENCRYPTION KEYS (KEKs)");
    println!("  {:<20} {}", "Total:", sys.keks.total);
    if sys.keks.stale_masterkey > 0 {
        println!("  {:<20} {} (need re-wrap)", "Stale master key:", sys.keks.stale_masterkey);
    } else {
        println!("  {:<20} none", "Stale master key:");
    }

    println!();

    Ok(())
}
