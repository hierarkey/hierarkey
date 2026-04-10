// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::audit::AuditEventsArgs;
use crate::error::CliResult;
use crate::http::ApiClient;
use crate::utils::formatting::{clip, fmt_date};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tabled::settings::Style;
use tabled::{Table, Tabled};
#[derive(Deserialize, Serialize)]
struct AuditQueryResult {
    events: Vec<AuditEventRow>,
    total: i64,
    page: u32,
    limit: u32,
}

#[derive(Deserialize, Serialize)]
struct AuditEventRow {
    seq: i64,
    id: String,
    event_type: String,
    outcome: String,
    actor_id: Option<String>,
    actor_type: Option<String>,
    actor_name: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    resource_name: Option<String>,
    request_id: Option<String>,
    trace_id: Option<String>,
    client_ip: Option<String>,
    metadata: Option<Value>,
    created_at: chrono::DateTime<chrono::Utc>,
    chain_hash: String,
}

#[derive(Tabled)]
struct AuditTableEntry {
    #[tabled(rename = "SEQ")]
    seq: i64,
    #[tabled(rename = "TIME")]
    time: String,
    #[tabled(rename = "EVENT TYPE")]
    event_type: String,
    #[tabled(rename = "OUTCOME")]
    outcome: String,
    #[tabled(rename = "ACTOR")]
    actor: String,
    #[tabled(rename = "RESOURCE")]
    resource: String,
}

fn fmt_actor(e: &AuditEventRow) -> String {
    let short_id = e.actor_id.as_deref().and_then(|id| id.split('-').next());

    match (e.actor_name.as_deref(), short_id, e.actor_type.as_deref()) {
        (Some(name), Some(id), _) => format!("{name} ({id})"),
        (Some(name), None, _) => name.to_string(),
        (None, Some(id), _) => id.to_string(),
        (None, None, Some(t)) => t.to_string(),
        _ => "-".to_string(),
    }
}

impl From<&AuditEventRow> for AuditTableEntry {
    fn from(e: &AuditEventRow) -> Self {
        let actor = fmt_actor(e);
        let resource = match (e.resource_type.as_deref(), e.resource_name.as_deref()) {
            (Some(rt), Some(rn)) => format!("{rt}/{rn}"),
            (Some(rt), None) => rt.to_string(),
            _ => "-".to_string(),
        };
        AuditTableEntry {
            seq: e.seq,
            time: fmt_date(e.created_at),
            event_type: e.event_type.clone(),
            outcome: e.outcome.clone(),
            actor,
            resource,
        }
    }
}

pub fn audit_events(client: &ApiClient, cli_args: &CliArgs, args: &AuditEventsArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let body = json!({
        "from": args.from,
        "to": args.to,
        "actor_id": args.actor_id,
        "resource_type": args.resource_type,
        "resource_id": args.resource_id,
        "event_type": args.event_type,
        "outcome": args.outcome,
        "page": args.page,
        "limit": args.limit,
    });

    let resp = client.post("/v1/audit/events").bearer_auth(token).json(&body).send()?;
    let data: AuditQueryResult = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    if cli_args.output_table {
        let entries: Vec<AuditTableEntry> = data.events.iter().map(AuditTableEntry::from).collect();
        let mut table = Table::new(&entries);
        table.with(Style::markdown());
        println!("\n{table}\n");
        println!(
            "Page {}/{}, {} total events",
            data.page + 1,
            pages(data.total, data.limit),
            data.total
        );
        return Ok(());
    }

    // Default text output
    if data.events.is_empty() {
        println!("No audit events found.");
        return Ok(());
    }

    println!(
        "{:<6}  {:<23}  {:<30}  {:<8}  {:<16}  RESOURCE",
        "SEQ", "TIME", "EVENT TYPE", "OUTCOME", "ACTOR"
    );
    for e in &data.events {
        let actor = fmt_actor(e);
        let actor = actor.as_str();
        let resource = match (e.resource_type.as_deref(), e.resource_name.as_deref()) {
            (Some(rt), Some(rn)) => format!("{rt}/{rn}"),
            (Some(rt), None) => rt.to_string(),
            _ => "-".to_string(),
        };
        println!(
            "{:<6}  {:<23}  {:<30}  {:<8}  {:<16}  {}",
            e.seq,
            fmt_date(e.created_at),
            clip(&e.event_type, 30),
            clip(&e.outcome, 8),
            clip(actor, 16),
            clip(&resource, 40),
        );
    }
    println!();
    println!(
        "Page {}/{}, {} total event(s).  Use --page and --limit to paginate.",
        data.page + 1,
        pages(data.total, data.limit),
        data.total
    );

    Ok(())
}

fn pages(total: i64, limit: u32) -> i64 {
    if limit == 0 {
        return 1;
    }
    (total + limit as i64 - 1) / limit as i64
}
