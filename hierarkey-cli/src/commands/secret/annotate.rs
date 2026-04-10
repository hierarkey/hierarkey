// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::secret::SecretAnnotateArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use hierarkey_core::api::status::Outcome;
use hierarkey_core::resources::SecretRef;
use hierarkey_server::http_server::handlers::secret_response::SecretResponse;
use serde::Serialize;

#[derive(Serialize, Debug)]
struct ApiRequest {
    note: Option<String>,
    clear_note: bool,
}

pub fn secret_annotate(client: &ApiClient, cli_args: &CliArgs, args: &SecretAnnotateArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.id.is_some() {
        // Short ID — send directly
        args.sec_ref_value().to_string()
    } else {
        let sec_ref =
            SecretRef::from_string(args.sec_ref_value()).map_err(|e| CliError::InvalidInput(e.to_string()))?;
        urlencoding::encode(&sec_ref.to_string()[1..]).into_owned()
    };

    if args.note.is_none() && !args.clear_note {
        return Err(CliError::InvalidInput(
            "Please specify either --note or --clear-note when annotating a secret".into(),
        ));
    }

    let payload = ApiRequest {
        note: args.note.clone(),
        clear_note: args.clear_note,
    };

    let resp = client
        .patch(&format!("/v1/secrets/{param}/annotate"))
        .bearer_auth(token.as_str())
        .json(&payload)
        .send()?;
    let resp_body = client.handle_full_response::<SecretResponse>(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&resp_body.status)?);
    } else if resp_body.status.outcome == Outcome::Failure {
        println!("Failed to annotate secret revision: {}", resp_body.status.message);
    } else {
        println!("Secret successfully annotated.");
        println!("You can describe the secret with the following command to see the updated details:");
        println!("\n  hkey secret describe --ref {}\n", args.sec_ref_value());
    }

    Ok(())
}
