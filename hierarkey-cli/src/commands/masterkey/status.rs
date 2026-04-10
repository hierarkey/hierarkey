// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::masterkey::MasterkeyStatusArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::{clip, fmt_bool, fmt_date};
use crate::utils::tabled::display_labels;
use crate::utils::tabled::display_opt_date;
use crate::utils::tabled::display_option;
use hierarkey_core::Labels;
use hierarkey_server::http_server::handlers::masterkey_response::{
    MasterKeyStatusListResponse, MasterKeyStatusResponse,
};
use hierarkey_server::service::account::AccountId;
use hierarkey_server::{MasterKeyStatus, MasterkeyId};
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Tabled)]
#[tabled(rename_all = "PascalCase")]
pub struct MasterKeyTableEntry {
    pub id: MasterkeyId,
    pub name: String,
    pub usage: String,
    pub status: String,
    pub backend: String,
    #[tabled(rename = "KEKs")]
    pub kek_count: String,
    #[tabled(display = "display_option")]
    pub description: Option<String>,
    #[tabled(display = "display_labels")]
    pub labels: Labels,
    #[tabled(rename = "Created At")]
    pub created_at: String,
    #[tabled(display = "display_opt_date")]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[tabled(display = "display_opt_date")]
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,

    pub locked: String,
    #[tabled(display = "display_opt_date")]
    pub unlocked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[tabled(skip)]
    pub unlocked_by_id: Option<AccountId>,
    #[tabled(display = "display_option")]
    pub unlocked_by_name: Option<String>,
    #[tabled(display = "display_opt_date")]
    pub locked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[tabled(skip)]
    pub locked_by_id: Option<AccountId>,
    #[tabled(display = "display_option")]
    pub locked_by_name: Option<String>,
    #[tabled(display = "display_option")]
    pub locked_reason: Option<String>,
}

impl From<MasterKeyStatusResponse> for MasterKeyTableEntry {
    fn from(mks: MasterKeyStatusResponse) -> Self {
        Self {
            id: mks.master_key.id,
            name: mks.master_key.name,
            usage: mks.master_key.usage.to_string(),
            status: mks.master_key.status.to_string(),
            backend: mks.keyring.provider.to_string(),
            kek_count: mks.kek_count.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string()),
            description: mks.master_key.description,
            labels: mks.master_key.labels,
            created_at: fmt_date(mks.master_key.created_at),
            updated_at: mks.master_key.updated_at,
            retired_at: mks.master_key.retired_at,
            locked: if mks.keyring.locked {
                "locked".to_string()
            } else {
                "unlocked".to_string()
            },
            unlocked_at: mks.keyring.unlocked_at,
            unlocked_by_id: mks.keyring.unlocked_by_id,
            unlocked_by_name: mks.keyring.unlocked_by_name,
            locked_at: mks.keyring.locked_at,
            locked_by_id: mks.keyring.locked_by_id,
            locked_by_name: mks.keyring.locked_by_name,
            locked_reason: mks.keyring.locked_reason,
        }
    }
}

pub fn masterkey_status(client: &ApiClient, cli_args: &CliArgs, _args: &MasterkeyStatusArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client.get("/v1/masterkeys").bearer_auth(token).send()?;
    let data = client.handle_response::<MasterKeyStatusListResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else if cli_args.output_table {
        let entries = data
            .entries
            .into_iter()
            .map(MasterKeyTableEntry::from)
            .collect::<Vec<_>>();

        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
    } else {
        if data.entries.is_empty() {
            println!("No master keys found matching the criteria.");
        } else {
            println!("{:<16}  {:<22}  {:<9}  {:<8}  {:<5}", "ID", "NAME", "STATUS", "LOCK", "KEKs",);

            for entry in data.entries {
                let mk = entry.master_key;
                let kr = entry.keyring;
                let kek_col = match entry.kek_count {
                    Some(n) => n.to_string(),
                    None => "-".to_string(),
                };
                let active_marker = if mk.status == MasterKeyStatus::Active { "*" } else { " " };

                println!(
                    "{:<16}  {}{:<21}  {:<9}  {:<8}  {:<5}",
                    &mk.short_id,
                    active_marker,
                    clip(&mk.name, 21),
                    clip(&mk.status.to_string(), 9),
                    fmt_bool(kr.locked, "locked", "unlocked"),
                    kek_col,
                );
            }

            println!();
        }
        println!("Tip: Use `--table` for more columns, or:");
        println!("  hkey masterkey describe --id <mk_...>");
    }

    Ok(())
}
