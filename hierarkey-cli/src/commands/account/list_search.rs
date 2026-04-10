// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::account::{AccountListArgs, AccountSearchArgs, AccountSortBy};
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use crate::utils::formatting::{clip, fmt_age, fmt_date, fmt_labels, fmt_opt_date};
use hierarkey_server::http_server::handlers::account_response::AccountSearchResponse;
use hierarkey_server::service::account::{AccountSearchQuery, QueryOrder};
use hierarkey_server::{AccountDto, AccountStatus, AccountType};
use std::collections::HashMap;
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Tabled)]
struct AccountTableEntry {
    #[tabled(rename = "ID")]
    pub id: String,

    #[tabled(rename = "NAME")]
    pub name: String,

    #[tabled(rename = "FULL NAME")]
    pub full_name: String,

    #[tabled(rename = "TYPE")]
    pub type_: String,

    #[tabled(rename = "STATUS")]
    pub status: String,

    #[tabled(rename = "FLAGS")]
    pub flags: String,

    #[tabled(rename = "LAST LOGIN")]
    pub last_login: String,

    #[tabled(rename = "Created At")]
    pub created: String,

    #[tabled(rename = "LABELS")]
    pub labels: String,
}

impl From<&AccountDto> for AccountTableEntry {
    fn from(account: &AccountDto) -> Self {
        AccountTableEntry {
            id: account.id.to_string(),
            name: account.account_name.to_string(),
            full_name: account.full_name.clone().unwrap_or_else(|| "-".to_string()),
            type_: account.account_type.to_string(),
            status: account.status.to_string(),
            flags: get_flags(account),
            last_login: fmt_opt_date(account.last_login_at, "-"),
            created: fmt_date(account.created_at),
            labels: fmt_labels(&account.metadata.labels()),
        }
    }
}

pub fn account_search(client: &ApiClient, cli_args: &CliArgs, args: &AccountSearchArgs) -> CliResult<()> {
    let q = search_to_query(args)?;
    search_impl(client, q, cli_args)
}

pub fn account_list(client: &ApiClient, cli_args: &CliArgs, args: &AccountListArgs) -> CliResult<()> {
    let q = list_to_query(args);
    search_impl(client, q, cli_args)
}

fn search_impl(client: &ApiClient, q: AccountSearchQuery, cli_args: &CliArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let resp = client
        .post("/v1/accounts/search")
        .bearer_auth(token.as_str())
        .json(&serde_json::json!(q))
        .send()?;

    let data = client.handle_response::<AccountSearchResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else if cli_args.output_table {
        // Table output
        let entries = data
            .entries
            .into_iter()
            .map(|e| AccountTableEntry::from(&e))
            .collect::<Vec<_>>();

        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
    } else {
        if data.entries.is_empty() {
            println!("No accounts found matching the criteria.");
        } else {
            println!(
                "{:<16}  {:<18}  {:<7}  {:<8}  {:<14}  AGE",
                "ID", "NAME", "TYPE", "STATUS", "FLAGS"
            );

            for account in data.entries {
                println!(
                    "{:<16}  {:<18}  {:<7}  {:<8}  {:<14}  {}",
                    clip(&account.id.to_string(), 16),
                    clip(account.account_name.as_ref(), 18),
                    clip(&account.account_type.to_string(), 7),
                    clip(&account.status.to_string(), 8),
                    clip(&get_flags(&account), 14),
                    fmt_age(account.created_at),
                );
            }

            println!();
        }
        println!("Tip: Use `--table` for more columns, or:");
        println!("  hkey account describe --name <name>");
    }

    Ok(())
}

fn get_flags(account: &AccountDto) -> String {
    let mut flags = Vec::new();
    if account.mfa_enabled {
        flags.push("mfa");
    }
    if account.locked_until.is_some() {
        flags.push("locked");
    }
    if account.must_change_password {
        flags.push("must_change_pw");
    }
    flags.join(", ")
}

fn search_to_query(args: &AccountSearchArgs) -> CliResult<AccountSearchQuery> {
    let now = chrono::Utc::now();

    let account_type = if args.all {
        vec![]
    } else if args.account_type.is_empty() {
        vec![AccountType::User]
    } else {
        args.account_type.iter().copied().map(Into::into).collect()
    };

    let status = if args.all {
        vec![]
    } else if args.status.is_empty() {
        vec![AccountStatus::Active]
    } else {
        args.status.iter().copied().map(Into::into).collect()
    };

    let label_pairs = split_labels(&args.label).map_err(|e| CliError::InvalidInput(e.to_string()))?;

    let mut label_key = label_pairs.label_keys;
    label_key.extend(args.has_label.clone());

    Ok(AccountSearchQuery {
        account_type,
        status,
        q: args.query.clone(),
        prefix: None,
        id_prefix: None,
        order: if args.desc { QueryOrder::Desc } else { QueryOrder::Asc },
        label: label_pairs.labels,
        label_key,
        limit: args.limit,
        offset: args.offset,
        created_after: args.created_after.as_ref().map(|t| t.resolve(now)),
        created_before: args.created_before.as_ref().map(|t| t.resolve(now)),
        sort_by: args.sort_by.clone(),
    })
}

fn list_to_query(args: &AccountListArgs) -> AccountSearchQuery {
    let account_type = if args.all {
        vec![]
    } else if args.account_type.is_empty() {
        vec![AccountType::User]
    } else {
        args.account_type.iter().copied().map(Into::into).collect()
    };

    let status = if args.all {
        vec![]
    } else if args.status.is_empty() {
        vec![AccountStatus::Active]
    } else {
        args.status.iter().copied().map(Into::into).collect()
    };

    AccountSearchQuery {
        account_type,
        status,
        q: None,
        prefix: args.prefix.clone(),
        id_prefix: None,
        order: QueryOrder::Asc,
        label: HashMap::new(),
        label_key: vec![],
        created_before: None,
        created_after: None,
        limit: args.limit,
        offset: args.offset,
        sort_by: AccountSortBy::Name,
    }
}

struct LabelPairs {
    label_keys: Vec<String>,
    labels: HashMap<String, String>,
}

fn split_labels(raw: &[String]) -> Result<LabelPairs, String> {
    let mut labels: HashMap<String, String> = HashMap::new(); // key + value
    let mut label_keys: Vec<String> = Vec::new(); // key only

    for s in raw {
        let raw = s.trim();
        if raw.is_empty() {
            return Err("invalid --label: empty value".to_string());
        }

        match raw.split_once('=') {
            None => {
                // --label foo  => label_key
                let key = raw.trim();
                if key.is_empty() {
                    return Err(format!("invalid --label {s:?}: empty key"));
                }
                label_keys.push(key.to_string());
            }
            Some((k, v)) => {
                // --label foo=bar  => label
                let key = k.trim();
                let val = v.trim();

                if key.is_empty() {
                    return Err(format!("invalid --label {s:?}: empty key"));
                }
                if val.is_empty() {
                    // choose behavior:
                    // A) treat as error:
                    return Err(format!("invalid --label {s:?}: empty value (use --label KEY)"));
                    // B) or treat as key-only:
                    // label_key.push(key.to_string());
                }

                labels.insert(key.to_string(), val.to_string());
            }
        }
    }

    Ok(LabelPairs { label_keys, labels })
}
