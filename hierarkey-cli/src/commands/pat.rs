// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{Parser, Subcommand};
pub mod create;
pub mod list;
pub mod revoke;
pub mod show;

#[derive(Subcommand)]
pub enum PatCommand {
    /// Create a new personal access token
    Create(PatCreateArgs),
    /// Show details of a specific personal access token
    Describe(PatDescribeArgs),
    /// List all personal access tokens
    List(PatListArgs),
    /// Revoke a personal access token
    Revoke(PatRevokeArgs),
}

#[derive(Parser, Debug)]
pub struct PatCreateArgs {
    /// Description for the PAT
    #[arg(short = 'd', long)]
    pub description: String,

    /// Labels to attach to the PAT (key=value)
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,

    /// Time-to-live for the PAT (e.g. 60s, 30m, 2h, 7d)
    #[arg(long, default_value = "1h")]
    pub ttl: String,
}

#[derive(Parser, Debug)]
pub struct PatListArgs {}

#[derive(Parser, Debug)]
pub struct PatDescribeArgs {
    /// ID of the PAT to show
    #[arg(long)]
    pub id: String,
}

#[derive(Parser, Debug)]
pub struct PatRevokeArgs {
    /// ID of the PAT to revoke
    #[arg(long)]
    pub id: String,
}
