// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::namespace::{NamespaceDescribeArgs, print_describe_namespace};
use crate::error::CliResult;
use crate::http::ApiClient;
use hierarkey_server::http_server::handlers::namespace_response::NamespaceResponse;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
struct SecretSummaryResponse {
    disabled: usize,
    latest_enabled: usize,
    total_secrets: usize,
}

#[derive(Deserialize, Serialize)]
struct DescribeResponse {
    entry: NamespaceResponse,
    secret_info: Option<SecretSummaryResponse>,
}

pub fn namespace_describe(client: &ApiClient, cli_args: &CliArgs, args: &NamespaceDescribeArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let param = if args.selector.is_short_id() {
        args.selector.value().to_string()
    } else {
        // Strip leading slash and URL-encode the namespace path
        let ns = args.selector.value().trim_start_matches('/');
        urlencoding::encode(ns).into_owned()
    };

    let resp = client
        .get(&format!("/v1/namespaces/{param}"))
        .bearer_auth(token)
        .send()?;
    let data: DescribeResponse = client.handle_response(resp)?;

    if cli_args.output_json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        print_describe_namespace(data.entry);
    }

    Ok(())
}
