// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::utils::formatting::{fmt_bool, fmt_date, fmt_labels, fmt_opt_date};
use clap::{Args, Parser, Subcommand};
use hierarkey_server::MasterKeyUsage;
use hierarkey_server::http_server::handlers::masterkey_response::MasterKeyStatusResponse;
use hierarkey_server::service::masterkey::MasterKeyProviderType;

pub mod activate;
pub mod create;
pub mod delete;
pub mod describe;
pub mod lock;
pub mod pkcs11_tokens;
pub mod status;
pub mod unlock;

#[derive(Subcommand)]
pub enum MasterkeyCommand {
    /// Show status of the master keys
    Status(MasterkeyStatusArgs),
    /// Lock a master key (or all keys)
    Lock(MasterkeyLockArgs),
    /// Unlock a master key
    Unlock(MasterkeyUnlockArgs),
    /// Describe a master key and its versions
    Describe(MasterkeyDescribeArgs),
    /// Create a new master key
    Create(MasterkeyCreateArgs),
    /// Activate a master key (and retire the previous one)
    Activate(MasterkeyActivateArgs),
    /// Delete a retired master key
    Delete(MasterkeyDeleteArgs),
    /// List available PKCS#11 token slots on the server's configured HSM module
    Pkcs11Tokens(MasterkeyPkcs11TokensArgs),
}

#[derive(Parser, Debug)]
pub struct MasterkeyPkcs11TokensArgs {}

#[derive(Args, Debug)]
pub struct MasterkeySelector {
    #[clap(long, conflicts_with = "id", required_unless_present = "id")]
    pub name: Option<String>,
    #[clap(long, conflicts_with = "name", required_unless_present = "name")]
    pub id: Option<String>,
}

impl MasterkeySelector {
    pub fn value(&self) -> &str {
        self.name
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --name or --id"))
    }
}

#[derive(Parser, Debug)]
pub struct MasterkeyDescribeArgs {
    #[command(flatten)]
    pub selector: MasterkeySelector,
}

#[derive(Parser, Debug)]
pub struct MasterkeyStatusArgs {}

#[derive(Parser, Debug)]
pub struct MasterkeyCreateArgs {
    /// Name of the master key to create
    #[clap(long)]
    pub name: String,

    /// Description of the master key
    #[clap(long)]
    pub description: Option<String>,

    /// Labels to assign to the master key (key=value)
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,

    /// Type of master key: 'wrap_kek'
    #[arg(long = "usage", value_enum)]
    key_usage: MasterKeyUsage,

    /// Provider of master key: 'insecure' or 'passphrase', 'pkcs11'
    #[arg(long = "provider", value_enum)]
    provider: MasterKeyProviderType,

    /// Passphrase for encrypted key (if applicable, will prompt if not provided)
    #[arg(
        long = "insecure-passphrase",
        requires_if("passphrase", "provider"),
        conflicts_with = "generate_passphrase"
    )]
    passphrase: Option<String>,

    /// Generate a random passphrase
    #[arg(long, conflicts_with = "passphrase")]
    generate_passphrase: bool,

    /// Key label for PKCS#11 provider (required when --provider pkcs11)
    #[arg(long = "pkcs11-key-label")]
    pub pkcs11_key_label: Option<String>,

    /// Slot number for PKCS#11 provider
    #[arg(long = "pkcs11-slot")]
    pub pkcs11_slot: Option<u64>,

    /// Token label for PKCS#11 provider
    #[arg(long = "pkcs11-token-label")]
    pub pkcs11_token_label: Option<String>,
}

#[derive(Parser, Debug)]
pub struct MasterkeyLockArgs {
    #[command(flatten)]
    pub selector: MasterkeySelector,

    /// Reason for locking the master key
    #[clap(long)]
    pub reason: Option<String>,

    /// Lock all keys
    #[clap(long)]
    pub all: Option<bool>,
}

#[derive(Parser, Debug)]
pub struct MasterkeyActivateArgs {
    #[command(flatten)]
    pub selector: MasterkeySelector,
}

#[derive(Parser, Debug)]
pub struct MasterkeyDeleteArgs {
    #[command(flatten)]
    pub selector: MasterkeySelector,
}

#[derive(Parser, Debug)]
pub struct MasterkeyUnlockArgs {
    #[command(flatten)]
    pub selector: MasterkeySelector,

    /// Passphrase for the master key (if applicable, will prompt if not provided)
    #[arg(long = "insecure-passphrase")]
    pub passphrase: Option<String>,

    /// Passphrase will be provided via standard input
    #[arg(long = "passphrase-stdin")]
    pub passphrase_stdin: bool,
}

fn fmt_name_or_id(name: Option<&str>, id: Option<&str>) -> String {
    name.filter(|s| !s.is_empty()).or(id).unwrap_or("-").to_string()
}

pub(crate) fn print_describe_masterkey(data: MasterKeyStatusResponse) {
    let mk = &data.master_key;

    // Identity section (no header)
    println!("  {:<20} {}", "Identifier:", mk.short_id);
    println!("  {:<20} {}", "Name:", mk.name);
    println!("  {:<20} {}", "Usage:", mk.usage);
    println!("  {:<20} {}", "Status:", mk.status.to_string().to_uppercase());

    println!();
    println!("METADATA:");
    println!("  {:<20} {}", "Description:", mk.description.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "Labels:", fmt_labels(&mk.labels));
    println!("  {:<20} {}", "Created at:", fmt_date(mk.created_at));
    let created_by_id_str = mk.created_by_id.map(|id| id.to_string());
    println!(
        "  {:<20} {}",
        "Created by:",
        fmt_name_or_id(mk.created_by_name.as_deref(), created_by_id_str.as_deref())
    );
    println!("  {:<20} {}", "Updated at:", fmt_opt_date(mk.updated_at, "-"));
    let updated_by_id_str = mk.updated_by_id.map(|id| id.to_string());
    println!(
        "  {:<20} {}",
        "Updated by:",
        fmt_name_or_id(mk.updated_by_name.as_deref(), updated_by_id_str.as_deref())
    );

    let kr = &data.keyring;

    println!();
    println!("MASTERKEY STATUS:");
    if let Some(count) = data.kek_count {
        let label = match mk.status {
            hierarkey_server::MasterKeyStatus::Draining => "KEKs remaining:",
            _ => "KEKs wrapped:",
        };
        println!("  {label:<20} {count}");
    }
    println!("  {:<20} {}", "Locked:", fmt_bool(kr.locked, "LOCKED", "UNLOCKED"));
    if kr.locked {
        if let Some(t) = kr.locked_at {
            println!("  {:<20} {}", "Locked at:", fmt_date(t));
        }
        if let Some(name) = &kr.locked_by_name {
            println!("  {:<20} {}", "Locked by:", name);
        }
        println!("  {:<20} {}", "Lock reason:", kr.locked_reason.as_deref().unwrap_or("-"));
    } else {
        if let Some(t) = kr.unlocked_at {
            println!("  {:<20} {}", "Unlocked at:", fmt_date(t));
        }
        if let Some(name) = &kr.unlocked_by_name {
            println!("  {:<20} {}", "Unlocked by:", name);
        }
    }
}
