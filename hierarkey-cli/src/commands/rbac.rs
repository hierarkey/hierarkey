// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{ArgGroup, Args, Parser, Subcommand};
use hierarkey_core::resources::AccountName;
use hierarkey_server::rbac::Permission;
use hierarkey_server::rbac::spec::RuleSpec;
use std::str::FromStr;

pub mod bind;
pub mod bindings;
pub mod explain;
pub mod role;
pub mod rule;
pub mod unbind;

#[derive(Debug, Subcommand)]
pub enum RbacCommand {
    /// Manage roles (containers of rules)
    Role(RoleCmd),
    /// Manage rules inside roles
    Rule(RuleCmd),
    /// Bind a subject (account/label selector) to a role
    Bind(BindCmd),
    /// Remove a binding between subject and role
    Unbind(UnbindCmd),
    /// Explain why a request would be allowed/denied
    Explain(ExplainCmd),
    /// Show all RBAC bindings for an account (default: current user)
    Bindings(BindingsCmd),
}

#[derive(Debug, Args)]
pub struct BindingsCmd {
    /// Account name (defaults to current user)
    #[arg(long, conflicts_with = "all")]
    pub account: Option<String>,

    /// Show bindings for all accounts (admin only)
    #[arg(long, conflicts_with = "account")]
    pub all: bool,
}

// ------------------------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct RoleCmd {
    #[command(subcommand)]
    pub cmd: RoleSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RoleSubcommand {
    /// Create a role
    Create(RoleCreateArgs),

    /// Update role metadata
    Update(RoleUpdateArgs),

    /// Delete a role
    Delete(RoleDeleteArgs),

    /// List roles
    List(RoleListArgs),

    /// Describe a single role (+ rules, + bindings optionally)
    Describe(RoleDescribeArgs),

    /// Add a rule to a role
    Add(RoleAddArgs),
}

#[derive(Debug, Args)]
pub struct RoleCreateArgs {
    /// Role name (e.g. "prod-editor")
    #[arg(long)]
    pub name: String,

    /// Optional description
    #[arg(long)]
    pub description: Option<String>,
}

#[derive(Debug, Args)]
pub struct RoleAddArgs {
    /// Existing role name
    #[arg(long)]
    pub name: String,

    /// Rule line, e.g.:
    ///   "allow secret:revise namespace /app1/** where env=prod"
    ///
    /// NOTE: wrap in quotes in the shell.
    #[arg(long = "rule", value_parser = parse_rule_spec, conflicts_with = "rule_id")]
    pub spec: Option<RuleSpec>,

    #[arg(long, conflicts_with = "spec")]
    pub rule_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct RoleUpdateArgs {
    /// Existing role name
    #[arg(long)]
    pub name: String,

    /// Rename role
    #[arg(long)]
    pub new_name: Option<String>,

    /// Set description (pass empty string if you really want empty)
    #[arg(long)]
    pub description: Option<String>,

    /// Clear description
    #[arg(long, default_value_t = false)]
    pub clear_description: bool,
}

#[derive(Debug, Args)]
pub struct RoleDeleteArgs {
    #[arg(long)]
    pub name: String,

    /// Delete even if bindings exist (server should still enforce invariants)
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RoleListArgs {}

#[derive(Debug, Args)]
pub struct RoleDescribeArgs {
    #[arg(long)]
    pub name: String,

    /// Include rules in output
    #[arg(long, default_value_t = true)]
    pub with_rules: bool,

    /// Include bindings in output
    #[arg(long, default_value_t = false)]
    pub with_bindings: bool,
}

// =============================================================================
// RULE
// =============================================================================

#[derive(Debug, Parser)]
pub struct RuleCmd {
    #[command(subcommand)]
    pub cmd: RuleSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RuleSubcommand {
    /// Create a new unbound rule
    Create(RuleCreateArgs),

    /// Remove a rule by id
    Delete(RuleDeleteArgs),

    /// List rules
    List(RuleListArgs),

    /// Describe a rule
    Describe(RuleDescribeArgs),
}

fn parse_rule_spec(s: &str) -> Result<RuleSpec, String> {
    RuleSpec::try_from(s).map_err(|e| format!("invalid rule spec: {e}"))
}

fn parse_permission_token(s: &str) -> Result<Permission, String> {
    Permission::from_str(s).map_err(|e| format!("invalid permission token: {e}"))
}

#[derive(Debug, Args)]
pub struct RuleCreateArgs {
    /// Rule line, e.g.:
    ///   "allow secret:revise namespace /app1/** where env=prod"
    ///
    /// NOTE: wrap in quotes in the shell.
    #[arg(long = "rule", value_parser = parse_rule_spec)]
    pub spec: RuleSpec,
}

#[derive(Debug, Args)]
pub struct RuleDeleteArgs {
    /// Rule id (as printed by list/show)
    #[arg(long)]
    pub id: String,
}

#[derive(Debug, Args)]
pub struct RuleListArgs {
    // We add filters later
}

#[derive(Debug, Args)]
pub struct RuleDescribeArgs {
    /// Rule id (as printed by list/show)
    #[arg(long)]
    pub id: String,
}

// =============================================================================
// BIND / UNBIND
// =============================================================================

#[derive(Debug, Parser)]
#[command(
    group = ArgGroup::new("subject")
        .args(["account_label", "name"])
        .required(true)
        .multiple(false),
    group = ArgGroup::new("binding")
        .args(["role", "rule_id", "rule"])
        .required(true)
        .multiple(false),
)]
pub struct BindCmd {
    #[arg(long)]
    pub account_label: Option<String>,

    #[arg(long)]
    pub name: Option<AccountName>,

    /// Role name to bind
    #[arg(long)]
    pub role: Option<String>,

    #[arg(long)]
    pub rule_id: Option<String>,

    /// Inline rule spec — creates the rule and binds it in one step.
    /// e.g. "allow secret:reveal to secret /prod:*"
    #[arg(long)]
    pub rule: Option<String>,
}

#[derive(Debug, Parser)]
pub struct UnbindCmd {
    #[arg(long, conflicts_with = "name")]
    pub label: Option<String>,

    #[arg(long, conflicts_with = "label")]
    pub name: Option<AccountName>,

    /// Role name to bind
    #[arg(long, conflicts_with = "rule_id")]
    pub role: Option<String>,

    #[arg(long, conflicts_with = "role")]
    pub rule_id: Option<String>,
}

// Optional convenience listing command (if you add it later):
// hkey rbac bind list [--role <role>] [--subject "<subject>"]

// =============================================================================
// EXPLAIN
// =============================================================================

#[derive(Debug, Parser)]
pub struct ExplainCmd {
    /// Account name or id (you can also accept "account:..." if you like)
    #[arg(long)]
    pub account: String,

    /// Permission token, e.g. secret:read
    #[arg(long, value_parser = parse_permission_token)]
    pub permission: Permission,

    /// Explain against a concrete secret reference (preferred)
    #[arg(long, conflicts_with = "namespace")]
    pub secret: Option<String>,

    /// Explain against a namespace path
    #[arg(long, conflicts_with = "secret")]
    pub namespace: Option<String>,

    /// Include near-misses in output
    #[arg(long = "near-misses", default_value_t = false)]
    pub near_misses: bool,
}

// -------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectSelector {
    Account(AccountName),
    LabelEq { key: String, value: String },
}
