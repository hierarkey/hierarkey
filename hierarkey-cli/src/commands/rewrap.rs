// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub mod dek;
pub mod kek;

use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub enum RewrapCommand {
    /// Rewrap the Key Encryption Key (KEK) under a new Masterkey version
    Kek(RewrapKekArgs),
    /// Rewrap Data Encryption Keys (DEKs) under a new Key Encryption Key (KEK)
    Dek(RewrapDekArgs),
}

#[derive(Parser, Debug)]
pub struct RewrapKekArgs {
    /// Source (draining) master key to rewrap KEKs away from (name or mk_ short-id)
    #[arg(
        long,
        help = "Source (draining) master key to rewrap KEKs away from (name or mk_ short-id)"
    )]
    pub from: Option<String>,

    /// Rewrap all KEKs (dangerous; requires --yes unless --dry-run)
    #[arg(long, help = "Rewrap all KEKs (dangerous; requires --yes unless --dry-run)")]
    pub all: bool,

    /// Rewrap all KEKs for a namespace (/prod)
    #[arg(long, help = "Rewrap all KEKs for a namespace (/prod)")]
    pub namespace: Option<String>,

    /// Rewrap one specific KEK by id (kek_...)
    #[arg(long, help = "Rewrap one specific KEK by id (kek_...)")]
    pub kek_id: Option<String>,

    /// Target MasterKey version to wrap KEKs with (defaults to active MasterKey)
    #[arg(
        long,
        help = "Target MasterKey version to wrap KEKs with (defaults to active MasterKey)"
    )]
    pub to_masterkey: Option<String>,

    /// Include inactive/disabled KEK revisions
    #[arg(long, help = "Include inactive/disabled KEK revisions")]
    pub include_inactive: bool,

    /// Show what would change without applying
    #[arg(long, help = "Show what would change without applying")]
    pub dry_run: bool,

    /// Process items in batches (default: 500)
    #[arg(long, default_value_t = 500, help = "Process items in batches (default: 500)")]
    pub batch_size: usize,

    /// Optional audit note
    #[arg(long, help = "Optional audit note")]
    pub note: Option<String>,

    /// Skip interactive confirmation (required for large scopes unless --dry-run)
    #[arg(
        long,
        help = "Skip interactive confirmation (required for large scopes unless --dry-run)"
    )]
    pub yes: bool,
}

#[derive(Parser, Debug)]
pub struct RewrapDekArgs {
    /// Rewrap all DEKs for a namespace (/prod)
    #[arg(long, help = "Rewrap all DEKs for a namespace (/prod)")]
    pub namespace: Option<String>,

    /// Rewrap DEKs for a specific secret (/namespace:path)
    #[arg(long = "ref", help = "Rewrap DEKs for a specific secret (/namespace:path)")]
    pub sec_ref: Option<String>,

    /// Rewrap all DEKs (dangerous; requires --yes unless --dry-run)
    #[arg(long, help = "Rewrap all DEKs (dangerous; requires --yes unless --dry-run)")]
    pub all: bool,

    /// Target KEK to wrap DEKs with (defaults to active KEK of the namespace)
    #[arg(
        long,
        help = "Target KEK to wrap DEKs with (defaults to active KEK of the namespace)"
    )]
    pub to_kek: Option<String>, // accept kek_id / revision / "active" / "latest"

    /// Include inactive/old secret revisions
    #[arg(long, help = "Include inactive/old secret revisions")]
    pub include_inactive_revisions: bool,

    /// Show what would change without applying
    #[arg(long, help = "Show what would change without applying")]
    pub dry_run: bool,

    /// Process items in batches (default: 200)
    #[arg(long, default_value_t = 200, help = "Process items in batches (default: 200)")]
    pub batch_size: usize,

    /// Optional audit note
    #[arg(long, help = "Optional audit note")]
    pub note: Option<String>,

    /// Skip interactive confirmation (required for large scopes unless --dry-run)
    #[arg(
        long,
        help = "Skip interactive confirmation (required for large scopes unless --dry-run)"
    )]
    pub yes: bool,
}
