// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::account::AccountUpdateArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::{parse_labels, validate_labels};
use hierarkey_server::AccountDto;

pub fn account_update(client: &ApiClient, cli_args: &CliArgs, args: &AccountUpdateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;
    let account = args.account.value();

    let has_metadata_changes =
        args.description.is_some() || args.clear_description || !args.label.is_empty() || !args.remove_label.is_empty();

    let has_any_change = args.email.is_some()
        || args.clear_email
        || args.full_name.is_some()
        || args.clear_full_name
        || has_metadata_changes;

    if !has_any_change {
        return Err(CliError::InvalidInput(
            "No changes specified. Provide at least one field to update.".into(),
        ));
    }

    validate_labels(&args.label).map_err(|e| CliError::InvalidInput(e.to_string()))?;

    let mut body = serde_json::Map::new();

    if args.clear_email {
        body.insert("email".to_string(), serde_json::Value::Null);
    } else if let Some(ref email) = args.email {
        body.insert("email".to_string(), serde_json::Value::String(email.clone()));
    }

    if args.clear_full_name {
        body.insert("full_name".to_string(), serde_json::Value::Null);
    } else if let Some(ref full_name) = args.full_name {
        body.insert("full_name".to_string(), serde_json::Value::String(full_name.clone()));
    }

    if has_metadata_changes {
        // Fetch current account to merge metadata instead of replacing it entirely
        let resp = client
            .get(&format!("/v1/accounts/{account}"))
            .bearer_auth(&token)
            .send()?;
        let current = client.handle_response::<AccountDto>(resp)?;
        let mut meta = current.metadata.clone();

        if args.clear_description {
            meta.clear_description();
        } else if let Some(ref desc) = args.description {
            meta.add_description(desc);
        }

        let new_labels = parse_labels(&args.label);
        for (k, v) in new_labels {
            meta.add_label(&k, &v);
        }
        for key in &args.remove_label {
            meta.remove_label(key);
        }

        body.insert("metadata".to_string(), serde_json::to_value(meta)?);
    }

    let resp = client
        .patch(&format!("/v1/accounts/{account}"))
        .bearer_auth(&token)
        .json(&serde_json::Value::Object(body))
        .send()?;
    client.handle_response_unit(resp)?;

    if cli_args.output_json {
        let resp = client
            .get(&format!("/v1/accounts/{account}"))
            .bearer_auth(&token)
            .send()?;
        let data = client.handle_response::<AccountDto>(resp)?;
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        println!("Account '{account}' updated successfully.");
    }

    Ok(())
}
