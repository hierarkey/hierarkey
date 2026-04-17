// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{ArgGroup, Parser, Subcommand};
use hierarkey_core::api::search::label::LabelExpr;
use hierarkey_core::api::search::query::{ResourceStatus, RotationPolicy, SecretSortKey, SecretType};
use hierarkey_core::api::search::time::TimeExpr;
use hierarkey_core::api::search::time::parse_duration_with_days;
use std::time::Duration;

pub mod activate;
pub mod annotate;
pub mod create;
pub mod delete;
pub mod describe;
pub mod disable;
pub mod enable;
pub mod list;
pub mod restore;
pub mod reveal;
pub mod revise;
pub mod search;
pub mod update;

#[derive(Subcommand)]
pub enum SecretCommand {
    /// Create a new secret with initial value and metadata
    Create(SecretCreateArgs),
    /// Show secret details, metadata, and revision history
    Describe(SecretDescribeArgs),
    /// Update secret-level metadata (does not create a new revision)
    Update(SecretUpdateArgs),
    /// Delete a secret and all its revisions
    Delete(SecretDeleteArgs),
    /// Create a new revision with updated value (metadata unchanged)
    Revise(SecretReviseArgs),
    /// Update metadata for a specific revision (no new revision created)
    Annotate(SecretAnnotateArgs),
    /// List all secrets in a namespace
    List(SecretListArgs),
    /// Search for secrets by filters and keywords
    Search(SecretSearchArgs),
    /// Decrypt and display secret value for a specific revision
    Reveal(SecretRevealArgs),
    /// Activate a specific secret revision
    Activate(SecretActivateArgs),
    /// Enable a secret (make it accessible again after being disabled)
    Enable(SecretEnableArgs),
    /// Disable a secret (block access without deleting it)
    Disable(SecretDisableArgs),
    /// Restore a previously deleted secret by its ID
    Restore(SecretRestoreArgs),
}

#[derive(Parser, Debug)]
#[command(
    group(
        ArgGroup::new("value_source")
            .args([
                "value",
                "value_hex",
                "value_base64",
                "from_file",
                "stdin",
                "use_editor",
            ])
            .required(true)  // exactly one required for create
            .multiple(false) // at most one
    ),
    after_long_help = r#"Usage examples:

    # Create a secret with a direct value
    hkey secret create --ref /prod:foo/bar --value 'secret value' --label type=api-key --label env=prod

    # Create a secret from a file
    hkey secret create --ref /prod:foo/bar --value-from secret.dat
    "#
)]
pub struct SecretCreateArgs {
    /// Fully qualified path for the secret (/namespace:path)
    #[arg(long = "ref", help = "Fully qualified path for the secret (/namespace:path)")]
    pub sec_ref: String,

    /// Description for the secret (secret-level metadata)
    #[arg(short = 'd', long)]
    pub description: Option<String>,

    /// Labels to attach to the secret (secret-level metadata) in the form key=value
    #[arg(short = 'l', long = "label")]
    pub labels: Vec<String>,

    /// Note/description for the initial revision (revision-level metadata)
    #[arg(long)]
    pub note: Option<String>,

    /// Type of the secret (allows hierarkey to parse/validate values)
    #[arg(long = "type")]
    pub sec_type: Option<SecretType>,

    /// Value for the secret (UTF-8 text)
    #[arg(long)]
    pub value: Option<String>,

    /// Value for the secret in hex
    #[arg(long)]
    pub value_hex: Option<String>,

    /// Value for the secret in base64
    #[arg(long)]
    pub value_base64: Option<String>,

    /// Read the secret value from a file (binary)
    #[arg(long)]
    pub from_file: Option<String>,

    /// Read the secret value from stdin (binary)
    ///
    /// Example:
    ///   openssl rand 32 | hkey secret create --ref /prod:foo/bar --stdin
    #[arg(long)]
    pub stdin: bool,

    /// Open the editor to input the secret value (UTF-8 text only)
    #[arg(long)]
    pub use_editor: bool,
}

#[derive(Parser, Debug)]
#[command(
    group(
        ArgGroup::new("value_source")
            .args([
                "value",
                "value_hex",
                "value_base64",
                "from_file",
                "stdin",
                "use_editor",
            ])
            .required(true)  // exactly one required for revise
            .multiple(false) // at most one
    )
)]
pub struct SecretReviseArgs {
    /// Fully qualified path for the secret (/namespace:path)
    #[arg(
        long = "ref",
        help = "Fully qualified path for the secret (/namespace:path)",
        conflicts_with = "id",
        required_unless_present = "id"
    )]
    pub sec_ref: Option<String>,
    /// Short ID of the secret (e.g. sec_abc123)
    #[arg(long, conflicts_with = "sec_ref", required_unless_present = "sec_ref")]
    pub id: Option<String>,

    /// Note/description for this new revision (revision-level metadata)
    #[arg(long)]
    pub note: Option<String>,

    /// Value for the secret (UTF-8 text)
    #[arg(long)]
    pub value: Option<String>,

    /// Value for the secret in hex
    #[arg(long)]
    pub value_hex: Option<String>,

    /// Value for the secret in base64
    #[arg(long)]
    pub value_base64: Option<String>,

    /// Read the secret value from a file (binary)
    #[arg(long)]
    pub from_file: Option<String>,

    /// Read the secret value from stdin (binary)
    ///
    /// Example:
    ///   openssl rand 32 | hkey secret revise --ref /prod:foo/bar --stdin --note "Rotated"
    #[arg(long)]
    pub stdin: bool,

    /// Open the editor to input the secret value (UTF-8 text only)
    #[arg(long)]
    pub use_editor: bool,

    /// Activate the new revision immediately
    #[arg(long, help = "Activate the new revision immediately")]
    pub activate: bool,
}

impl SecretReviseArgs {
    pub fn sec_ref_value(&self) -> &str {
        self.sec_ref
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --ref or --id"))
    }
}

#[derive(Parser, Debug)]
#[command(
    group(
        ArgGroup::new("note_op")
            .args(["note", "clear_note"])
            .required(true)
            .multiple(false)
    )
)]
pub struct SecretAnnotateArgs {
    /// Fully qualified path for the secret (/namespace:path)
    #[arg(
        long = "ref",
        help = "Fully qualified path for the secret (/namespace:path)",
        conflicts_with = "id",
        required_unless_present = "id"
    )]
    pub sec_ref: Option<String>,
    /// Short ID of the secret (e.g. sec_abc123)
    #[arg(long, conflicts_with = "sec_ref", required_unless_present = "sec_ref")]
    pub id: Option<String>,

    /// Set/replace the note for this revision
    #[arg(long)]
    pub note: Option<String>,

    /// Clear the note for this revision
    #[arg(long)]
    pub clear_note: bool,
}

impl SecretAnnotateArgs {
    pub fn sec_ref_value(&self) -> &str {
        self.sec_ref
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --ref or --id"))
    }
}

#[derive(clap::ValueEnum, Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Base64,
    Hex,
    Text,
}

#[derive(Parser, Debug)]
pub struct SecretRevealArgs {
    /// Fully qualified path for the secret (/namespace:path)
    #[arg(long = "ref", help = "Fully qualified path for the secret (/namespace:path)")]
    pub sec_ref: String,

    /// Output the secret value in hex format
    #[arg(
        long = "as-hex",
        help = "Output the secret value in hex format",
        conflicts_with = "base64",
        conflicts_with = "output"
    )]
    pub hex: bool,

    /// Output the secret value in base64 format
    #[arg(
        long = "as-base64",
        help = "Output the secret value in base64 format",
        conflicts_with = "hex",
        conflicts_with = "output"
    )]
    pub base64: bool,

    /// Output format: base64, hex, or text (default)
    #[arg(
        long = "output",
        value_enum,
        help = "Output format: base64, hex, or text",
        conflicts_with = "hex",
        conflicts_with = "base64"
    )]
    pub output: Option<OutputFormat>,
}

#[derive(Parser, Debug)]
pub struct SecretDeleteArgs {
    /// Fully qualified path for the secret (/namespace:path)
    #[arg(
        long = "ref",
        help = "Fully qualified path for the secret (/namespace:path)",
        conflicts_with = "id",
        required_unless_present = "id"
    )]
    pub sec_ref: Option<String>,
    /// Short ID of the secret (e.g. sec_abc123)
    #[arg(long, conflicts_with = "sec_ref", required_unless_present = "sec_ref")]
    pub id: Option<String>,

    /// Confirm deletion without prompt
    #[arg(long, help = "Confirm deletion without prompt")]
    pub confirm: bool,
}

impl SecretDeleteArgs {
    pub fn sec_ref_value(&self) -> &str {
        self.sec_ref
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --ref or --id"))
    }
}

#[derive(Parser, Debug)]
pub struct SecretListArgs {
    /// Namespace to list secrets from
    #[arg(short = 'n', long)]
    pub namespace: Option<String>,

    /// Key prefix to filter secrets
    #[arg(short = 'p', long)]
    pub prefix: Option<String>,

    /// Limit the number of results
    #[arg(short = 'l', long)]
    pub limit: Option<usize>,

    #[arg(short = 'o', long)]
    /// Offset for the results
    pub offset: Option<usize>,
}

#[derive(Parser, Debug)]
pub struct SecretDescribeArgs {
    /// Fully qualified path for the secret (/namespace:path@rev)
    #[arg(
        long = "ref",
        help = "Fully qualified path for the secret (/namespace:path[@rev])",
        conflicts_with = "id",
        required_unless_present = "id"
    )]
    pub sec_ref: Option<String>,
    /// Short ID of the secret (e.g. sec_abc123)
    #[arg(long, conflicts_with = "sec_ref", required_unless_present = "sec_ref")]
    pub id: Option<String>,
}

impl SecretDescribeArgs {
    pub fn sec_ref_value(&self) -> &str {
        self.sec_ref
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --ref or --id"))
    }
}

#[derive(Parser, Debug)]
pub struct SecretSearchArgs {
    /// Exact namespace match. Repeatable (OR).
    #[arg(
        long,
        value_name = "NAMESPACE",
        conflicts_with_all = ["namespace_prefix", "all_namespaces"]
    )]
    pub namespace: Vec<String>,

    /// Namespace prefix match (e.g. "prod/"). Repeatable (OR).
    #[arg(
        long,
        value_name = "PREFIX",
        conflicts_with_all = ["namespace", "all_namespaces"]
    )]
    pub namespace_prefix: Vec<String>,

    /// Search across all namespaces.
    #[arg(long, conflicts_with_all = ["namespace", "namespace_prefix"])]
    pub all_namespaces: bool,

    // --- Identity ------------------------------------------------------------
    /// Key name match
    #[arg(long, value_name = "PATTERN")]
    pub name: Option<String>,

    /// Exact ID prefix
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,

    // --- Labels --------------------------------------------------------------
    /// Include labels. Repeatable. Supports "k=v" and "k".
    #[arg(long, value_name = "LABEL")]
    pub label: Vec<LabelExpr>,

    /// Exclude labels. Repeatable. Supports "k=v" and "k".
    #[arg(long, value_name = "LABEL")]
    pub label_not: Vec<LabelExpr>,

    // --- Time filters --------------------------------------------------------
    /// Created before (RFC3339 or duration like 7d/12h)
    #[arg(long, value_name = "TIME")]
    pub created_before: Option<TimeExpr>,

    /// Created after (RFC3339 or duration like 7d/12h)
    #[arg(long, value_name = "TIME")]
    pub created_after: Option<TimeExpr>,

    /// Updated before (RFC3339 or duration like 7d/12h)
    #[arg(long, value_name = "TIME")]
    pub updated_before: Option<TimeExpr>,

    /// Updated after (RFC3339 or duration like 7d/12h)
    #[arg(long, value_name = "TIME")]
    pub updated_after: Option<TimeExpr>,

    // --- State / hygiene -----------------------------------------------------
    /// Search by resource status
    #[arg(long)]
    pub status: Option<ResourceStatus>,

    /// Search for secrets that need rotation
    #[arg(long)]
    pub needs_rotation: bool,

    /// Rotation policy
    #[arg(long, value_enum)]
    pub rotation_policy: Option<RotationPolicy>,

    /// "Not updated in this duration" (e.g. 90d).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration_with_days)]
    pub stale: Option<Duration>,

    // --- Access signals ------------------------------------------------------
    /// Accessed before (RFC3339 or duration)
    #[arg(long, value_name = "TIME")]
    pub accessed_before: Option<TimeExpr>,

    /// Accessed after (RFC3339 or duration)
    #[arg(long, value_name = "TIME")]
    pub accessed_after: Option<TimeExpr>,

    /// Only secrets that have never been accessed
    #[arg(long)]
    pub never_accessed: bool,

    // --- Type / free text ----------------------------------------------------
    /// Search for secret type
    #[arg(long, value_enum)]
    pub secret_type: Option<SecretType>,

    /// Free-text search across name/description/labels
    #[arg(short = 'q', long = "query")]
    pub q: Option<String>,

    // --- Output controls -----------------------------------------------------
    /// Sort secrets by this key
    #[arg(long, value_enum)]
    pub sort: Option<SecretSortKey>,

    /// Sort in descending order
    #[arg(long)]
    pub desc: bool,

    /// Offset for the results
    #[arg(long)]
    pub offset: Option<usize>,

    /// Limit the number of results (default: 50)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Parser, Debug)]
pub struct SecretUpdateArgs {
    /// Fully qualified path for the secret (/namespace:path)
    #[arg(
        long = "ref",
        help = "Fully qualified path for the secret (/namespace:path)",
        conflicts_with = "id",
        required_unless_present = "id"
    )]
    pub sec_ref: Option<String>,
    /// Short ID of the secret (e.g. sec_abc123)
    #[arg(long, conflicts_with = "sec_ref", required_unless_present = "sec_ref")]
    pub id: Option<String>,

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

    /// Remove all labels from this secret
    #[arg(long = "clear-labels")]
    pub clear_labels: bool,
}

impl SecretUpdateArgs {
    pub fn sec_ref_value(&self) -> &str {
        self.sec_ref
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --ref or --id"))
    }
}

#[derive(Parser, Debug)]
#[command()]
pub struct SecretActivateArgs {
    /// Fully qualified path for the secret revision (/namespace:path@rev)
    #[arg(
        long = "ref",
        help = "Fully qualified path for the secret revision (/namespace:path@rev)",
        conflicts_with = "id",
        required_unless_present = "id"
    )]
    pub sec_ref: Option<String>,
    /// Short ID of the secret (e.g. sec_abc123)
    #[arg(long, conflicts_with = "sec_ref", required_unless_present = "sec_ref")]
    pub id: Option<String>,

    /// Reason for activating this revision
    #[arg(long)]
    pub reason: Option<String>,
}

impl SecretActivateArgs {
    pub fn sec_ref_value(&self) -> &str {
        self.sec_ref
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --ref or --id"))
    }
}

#[derive(Parser, Debug)]
pub struct SecretEnableArgs {
    /// Fully qualified path for the secret (/namespace:path)
    #[arg(
        long = "ref",
        help = "Fully qualified path for the secret (/namespace:path)",
        conflicts_with = "id",
        required_unless_present = "id"
    )]
    pub sec_ref: Option<String>,
    /// Short ID of the secret (e.g. sec_abc123)
    #[arg(long, conflicts_with = "sec_ref", required_unless_present = "sec_ref")]
    pub id: Option<String>,
}

impl SecretEnableArgs {
    pub fn sec_ref_value(&self) -> &str {
        self.sec_ref
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --ref or --id"))
    }
}

#[derive(Parser, Debug)]
pub struct SecretDisableArgs {
    /// Fully qualified path for the secret (/namespace:path)
    #[arg(
        long = "ref",
        help = "Fully qualified path for the secret (/namespace:path)",
        conflicts_with = "id",
        required_unless_present = "id"
    )]
    pub sec_ref: Option<String>,
    /// Short ID of the secret (e.g. sec_abc123)
    #[arg(long, conflicts_with = "sec_ref", required_unless_present = "sec_ref")]
    pub id: Option<String>,
}

impl SecretDisableArgs {
    pub fn sec_ref_value(&self) -> &str {
        self.sec_ref
            .as_deref()
            .or(self.id.as_deref())
            .unwrap_or_else(|| unreachable!("clap requires --ref or --id"))
    }
}

#[derive(Parser, Debug)]
pub struct SecretRestoreArgs {
    /// ID of the deleted secret — short ID (e.g. sec_01J...) or full UUID
    #[arg(long)]
    pub id: String,
}
