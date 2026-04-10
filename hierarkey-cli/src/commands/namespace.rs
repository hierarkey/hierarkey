// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::utils::formatting::{fmt_date, fmt_labels, fmt_opt_date};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hierarkey_server::http_server::handlers::namespace_response::NamespaceResponse;
use serde::Serialize;

pub mod create;
pub mod delete;
pub mod describe;
pub mod disable;
pub mod enable;
pub mod list;
pub mod search;
pub mod update;

#[derive(Subcommand)]
pub enum NamespaceCommand {
    /// Create a new namespace
    Create(NamespaceCreateArgs),
    /// Show namespace details and metadata
    Describe(NamespaceDescribeArgs),
    /// Update namespace metadata
    Update(NamespaceUpdateArgs),
    /// Permanently delete a namespace and all its secrets
    Delete(NamespaceDeleteArgs),
    /// Disable a namespace (soft delete, can be restored)
    Disable(NamespaceDisableArgs),
    /// Enable a disabled namespace
    Enable(NamespaceEnableArgs),
    /// List all namespaces
    List(NamespaceListArgs),
    /// Search namespaces by path prefix or query
    Search(NamespaceSearchArgs),
}

#[derive(Parser, Debug)]
pub struct NamespaceCreateArgs {
    /// The namespace to create (starts with /)
    #[arg(short = 'n', long)]
    pub namespace: String,

    /// Labels to attach to the namespace (key=value)
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,

    /// Description for the namespace
    #[arg(short = 'd', long)]
    pub description: Option<String>,
}

#[derive(Args, Debug)]
pub struct NamespaceSelector {
    #[arg(short = 'n', long, conflicts_with = "id", required_unless_present = "id")]
    pub namespace: Option<String>,
    #[arg(long, conflicts_with = "namespace", required_unless_present = "namespace")]
    pub id: Option<String>,
}

impl NamespaceSelector {
    pub fn value(&self) -> &str {
        self.namespace
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --namespace or --id"))
    }

    pub fn is_short_id(&self) -> bool {
        self.id.is_some()
    }
}

#[derive(Parser, Debug)]
pub struct NamespaceDescribeArgs {
    #[command(flatten)]
    pub selector: NamespaceSelector,

    /// Specific revision to display
    #[arg(long, help = "Specific revision to describe")]
    pub revision: Option<u32>,
}

#[derive(Parser, Debug)]
pub struct NamespaceDeleteArgs {
    #[command(flatten)]
    pub selector: NamespaceSelector,

    /// Confirm deletion without prompt
    #[arg(long, help = "Confirm deletion without prompt")]
    pub confirm: bool,

    /// Also delete all secrets in the namespace (required if secrets exist)
    #[arg(long, help = "Delete all secrets in the namespace along with it")]
    pub delete_secrets: bool,
}

#[derive(Parser, Debug)]
pub struct NamespaceDisableArgs {
    #[command(flatten)]
    pub selector: NamespaceSelector,
}

#[derive(Parser, Debug)]
pub struct NamespaceEnableArgs {
    #[command(flatten)]
    pub selector: NamespaceSelector,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NamespaceStatusArg {
    Active,
    Disabled,
    Deleted,
}

impl std::fmt::Display for NamespaceStatusArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NamespaceStatusArg::Active => "active",
            NamespaceStatusArg::Disabled => "disabled",
            NamespaceStatusArg::Deleted => "deleted",
        };
        write!(f, "{s}")
    }
}

#[derive(Parser, Debug)]
pub struct NamespaceListArgs {
    /// Optional namespace prefix to filter by
    #[arg(short = 'p', long)]
    pub prefix: Option<String>,

    /// Include all namespaces (active + disabled + deleted)
    ///
    /// Ignored if --status / --disabled / --deleted is provided.
    #[arg(long, conflicts_with_all = ["status"])]
    pub all: bool,

    /// Filter by one or more statuses (repeatable)
    ///
    /// Example: --status active --status disabled
    #[arg(long, value_enum, action = clap::ArgAction::Append)]
    pub status: Vec<NamespaceStatusArg>,

    /// Limit the number of results
    #[arg(short = 'l', long)]
    pub limit: Option<usize>,

    #[arg(short = 'o', long)]
    /// Offset for the results
    pub offset: Option<usize>,
}

impl NamespaceListArgs {
    /// Resolve the effective status filter for the API.
    /// - default => [Active]
    /// - --all => [Active, Disabled, Deleted]
    /// - --status / --disabled / --deleted => exactly those
    pub fn effective_statuses(&self) -> Vec<String> {
        if self.all {
            return vec![
                NamespaceStatusArg::Active.to_string(),
                NamespaceStatusArg::Disabled.to_string(),
                NamespaceStatusArg::Deleted.to_string(),
            ];
        }

        if self.status.is_empty() {
            return vec![NamespaceStatusArg::Active.to_string()];
        }

        self.status.iter().map(|s| s.to_string()).collect()
    }
}

#[derive(Parser, Debug)]
pub struct NamespaceSearchArgs {
    /// Search query string (filters by namespace path prefix)
    #[arg(short = 'q', long)]
    pub query: Option<String>,

    /// Limit the number of results
    #[arg(short = 'l', long)]
    pub limit: Option<usize>,

    /// Offset for pagination
    #[arg(short = 'o', long)]
    pub offset: Option<usize>,
}

#[derive(Parser, Debug)]
pub struct NamespaceUpdateArgs {
    #[command(flatten)]
    pub selector: NamespaceSelector,

    /// New description (set / replace)
    #[arg(long, conflicts_with = "clear_description")]
    pub description: Option<String>,

    /// Clear the description (set to null/empty)
    #[arg(long)]
    pub clear_description: bool,

    /// Upsert labels in the form key=value
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,

    /// Remove labels by key
    #[arg(long = "remove-label")]
    pub remove_labels: Vec<String>,

    /// Remove all labels from this namespace
    #[arg(long = "clear-labels")]
    pub clear_labels: bool,
}

pub(crate) fn print_describe_namespace(data: NamespaceResponse) {
    // Identity section (no header)
    println!("  {:<20} {}", "Identifier:", data.short_id);
    println!("  {:<20} {}", "Namespace:", data.namespace);
    println!("  {:<20} {}", "Status:", data.status.to_uppercase());

    println!();
    println!("METADATA:");
    println!("  {:<20} {}", "Description:", data.description.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "Labels:", fmt_labels(&data.labels));
    println!("  {:<20} {}", "Created at:", fmt_date(data.created_at));
    println!("  {:<20} {}", "Created by:", data.created_by.as_deref().unwrap_or("-"));
    println!("  {:<20} {}", "Updated at:", fmt_opt_date(data.updated_at, "-"));
    println!("  {:<20} {}", "Updated by:", data.updated_by.as_deref().unwrap_or("-"));

    // Active KEK section
    if let Some(active_rev) = data.active_kek_revision
        && let Some(active_kek) = data.keks.iter().find(|k| k.revision == active_rev)
    {
        println!();
        println!("KEK (ACTIVE):");
        println!("  {:<20} {}", "Revision:", active_kek.revision);
        println!("  {:<20} {}", "KEK ID:", active_kek.kek_short_id);
        println!("  {:<20} {}", "Created:", fmt_date(active_kek.created_at));
        println!("  {:<20} {}", "Master key:", active_kek.masterkey_short_id);
        if let Some(note) = &active_kek.description {
            println!("  {:<20} {}", "Note:", note);
        } else {
            println!("  {:<20} Active key used to wrap DEKs for new/rotated secrets", "Note:");
        }
    }

    // KEK history
    if !data.keks.is_empty() {
        println!();
        println!("KEK HISTORY:");
        println!("  rev  created_at               kek_id");

        let mut sorted_keks = data.keks.clone();
        sorted_keks.sort_by_key(|k| std::cmp::Reverse(k.revision)); // newest first

        for kek in sorted_keks {
            let star = if Some(kek.revision) == data.active_kek_revision {
                "*"
            } else {
                " "
            };
            println!(
                "  {:>3}{} {:<23.23} {}",
                kek.revision,
                star,
                fmt_date(kek.created_at),
                kek.kek_short_id
            );
        }
    }

    // Secrets summary
    if let Some(summary) = &data.secret_summary {
        println!();
        println!("SECRETS SUMMARY:");
        println!("  {:<20} {}", "Total:", summary.total);
        println!("  {:<20} {}", "Latest enabled:", summary.latest_enabled);
        println!("  {:<20} {}", "Disabled:", summary.disabled);
    }
}
