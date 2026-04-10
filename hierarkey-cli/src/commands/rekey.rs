// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub mod kek;

use clap::ArgAction;
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub enum RekeyCommand {
    /// Create a new KEK revision and optionally migrate DEKs
    Kek(RekeyKekArgs),
}

#[derive(Parser, Debug)]
pub struct RekeyKekArgs {
    /// Namespace to create a new KEK revision for (/prod)
    #[arg(long, help = "Namespace to create a new KEK revision for (/prod)")]
    pub namespace: String,

    /// Wrap the new KEK using this MasterKey version (defaults to active MasterKey)
    #[arg(
        long,
        help = "Wrap the new KEK using this MasterKey version (defaults to active MasterKey)"
    )]
    pub masterkey: Option<String>,

    /// Activate the newly created KEK for this namespace (default behavior)
    #[arg(long, help = "Activate the newly created KEK for this namespace (default behavior)", action = ArgAction::SetTrue)]
    pub activate: bool,

    /// Do not activate the newly created KEK
    #[arg(long = "no-activate", help = "Do not activate the newly created KEK", conflicts_with = "activate", action = ArgAction::SetTrue)]
    pub no_activate: bool,

    /// After creating the new KEK, migrate (rewrap) all DEKs in the namespace to it
    #[arg(
        long,
        help = "After creating the new KEK, migrate (rewrap) all DEKs in the namespace to it"
    )]
    pub migrate_deks: bool,

    /// Include inactive/old secret revisions during migration
    #[arg(
        long,
        help = "Include inactive/old secret revisions during migration",
        requires = "migrate_deks"
    )]
    pub include_inactive_revisions: bool,

    /// Show what would change without applying
    #[arg(long, help = "Show what would change without applying")]
    pub dry_run: bool,

    /// Process migration in batches (default: 200)
    #[arg(
        long,
        default_value_t = 200,
        help = "Process migration in batches (default: 200)",
        requires = "migrate_deks"
    )]
    pub batch_size: usize,

    /// Optional audit note (defaults to \"New KEK revision\" in your handler if omitted)
    #[arg(
        long,
        help = "Optional audit note (defaults to \"New KEK revision\" in your handler if omitted)"
    )]
    pub note: Option<String>,

    /// Skip interactive confirmation (required for migration unless --dry-run)
    #[arg(
        long,
        help = "Skip interactive confirmation (required for migration unless --dry-run)"
    )]
    pub yes: bool,
}
