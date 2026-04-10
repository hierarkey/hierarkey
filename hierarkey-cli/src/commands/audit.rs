// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use clap::{Parser, Subcommand};

pub mod events;
pub mod verify;

#[derive(Subcommand)]
pub enum AuditCommand {
    /// Query audit log events
    Events(AuditEventsArgs),
    /// Verify the integrity of the audit log chain
    Verify(AuditVerifyArgs),
}

#[derive(Parser, Debug)]
pub struct AuditEventsArgs {
    /// Filter by event type (e.g. SECRET_CREATE, ACCOUNT_UPDATE)
    #[arg(long)]
    pub event_type: Option<String>,

    /// Filter by outcome: success or failure
    #[arg(long, value_parser = ["success", "failure"])]
    pub outcome: Option<String>,

    /// Filter by actor account ID (UUID)
    #[arg(long)]
    pub actor_id: Option<String>,

    /// Filter by resource type (e.g. secret, account, namespace)
    #[arg(long)]
    pub resource_type: Option<String>,

    /// Filter by resource ID (UUID)
    #[arg(long)]
    pub resource_id: Option<String>,

    /// Filter events from this date/time (RFC3339, e.g. 2025-01-01T00:00:00Z)
    #[arg(long)]
    pub from: Option<String>,

    /// Filter events up to this date/time (RFC3339)
    #[arg(long)]
    pub to: Option<String>,

    /// Page number (0-based, default 0)
    #[arg(long, default_value_t = 0)]
    pub page: u32,

    /// Number of events per page (default 50, max 500)
    #[arg(long, default_value_t = 50)]
    pub limit: u32,
}

#[derive(Parser, Debug)]
pub struct AuditVerifyArgs {
    /// Start verification from this sequence number (default: beginning)
    #[arg(long)]
    pub from_seq: Option<i64>,

    /// Maximum number of events to verify (default: all)
    #[arg(long)]
    pub limit: Option<i64>,
}
