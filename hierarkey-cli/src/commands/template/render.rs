// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::cli::CliArgs;
use crate::commands::template::TemplateRenderArgs;
use crate::error::{CliError, CliResult};
use crate::http::ApiClient;
use base64::Engine;
use hierarkey_core::api::status::ApiErrorCode;
use hierarkey_core::resources::SecretRef;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::Write;

#[derive(Deserialize)]
struct SecretRevealResponse {
    value_b64: String,
}

/// Parse all `{{ ... }}` placeholders from a template string.
/// Returns a list of (full_match, trimmed_inner) tuples, with duplicates preserved.
fn find_placeholders(template: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut search_start = 0;

    while let Some(open) = template[search_start..].find("{{") {
        let open_abs = search_start + open;
        let inner_start = open_abs + 2;

        if let Some(close) = template[inner_start..].find("}}") {
            let close_abs = inner_start + close;
            let full_match = template[open_abs..close_abs + 2].to_string();
            let inner = template[inner_start..close_abs].trim().to_string();
            result.push((full_match, inner));
            search_start = close_abs + 2;
        } else {
            // No closing `}}` — stop searching
            break;
        }
    }

    result
}

/// A secret that could not be revealed, with the reason why.
#[derive(Debug)]
pub struct RevealFailure {
    pub sec_ref: String,
    pub reason: String,
    pub is_forbidden: bool,
}

/// Attempt to reveal every unique secret ref in `placeholders`.
///
/// Uses `reveal_fn` to fetch each value — this indirection keeps the core logic
/// testable without a live server.  Network / fatal errors from `reveal_fn` are
/// stored as failures; the caller decides how to surface them.
///
/// Returns `Ok(cache)` when every secret was fetched successfully, or
/// `Err(failures)` listing every ref that could not be revealed.
pub fn reveal_all<F>(
    placeholders: &[(String, String)],
    mut reveal_fn: F,
) -> Result<HashMap<String, String>, Vec<RevealFailure>>
where
    F: FnMut(&str) -> CliResult<String>,
{
    let mut cache: HashMap<String, String> = HashMap::new();
    let mut failures: Vec<RevealFailure> = Vec::new();

    for (_, inner) in placeholders {
        if cache.contains_key(inner) || failures.iter().any(|f| f.sec_ref == *inner) {
            continue;
        }

        match reveal_fn(inner) {
            Ok(value) => {
                cache.insert(inner.clone(), value);
            }
            Err(e) => {
                let (reason, is_forbidden) = match &e {
                    CliError::ApiError { code, message, .. } => {
                        let forbidden = *code == ApiErrorCode::Forbidden;
                        let reason = if *code == ApiErrorCode::NotFound {
                            "not found".to_string()
                        } else {
                            message.clone()
                        };
                        (reason, forbidden)
                    }
                    other => (format!("{other}"), false),
                };
                failures.push(RevealFailure {
                    sec_ref: inner.clone(),
                    reason,
                    is_forbidden,
                });
            }
        }
    }

    if failures.is_empty() { Ok(cache) } else { Err(failures) }
}

/// Format a list of reveal failures into a human-readable error message.
pub fn format_reveal_failures(failures: &[RevealFailure]) -> String {
    let count = failures.len();
    let noun = if count == 1 { "secret" } else { "secrets" };
    let mut msg = format!("{count} {noun} could not be revealed:\n");
    for f in failures {
        msg.push_str(&format!("  - {}  ({})\n", f.sec_ref, f.reason));
    }
    if failures.iter().any(|f| f.is_forbidden) {
        msg.push_str("\nHint: check that the service account has 'secret:reveal' permission on these namespaces.");
    }
    msg
}

pub fn template_render(client: &ApiClient, cli_args: &CliArgs, args: &TemplateRenderArgs) -> CliResult<()> {
    let token = cli_args.require_token()?;

    let template = fs::read_to_string(&args.file)
        .map_err(|e| CliError::InvalidInput(format!("Failed to read template file '{}': {e}", args.file)))?;

    let placeholders = find_placeholders(&template);

    if placeholders.is_empty() {
        // Nothing to render — pass through unchanged
        write_output(args.output.as_deref(), &template)?;
        return Ok(());
    }

    // Validate all secret refs before fetching anything
    for (_, inner) in &placeholders {
        SecretRef::from_string(inner)
            .map_err(|e| CliError::InvalidInput(format!("Invalid secret ref '{inner}': {e}")))?;
    }

    let reveal_fn = |sec_ref: &str| -> CliResult<String> {
        let resp = client
            .post("/v1/secrets/reveal")
            .json(&json!({ "sec_ref": sec_ref }))
            .bearer_auth(token.as_str())
            .send()?;

        let body = client.handle_response::<SecretRevealResponse>(resp)?;

        let value_bytes = base64::engine::general_purpose::STANDARD
            .decode(&body.value_b64)
            .map_err(|e| CliError::InvalidInput(format!("Failed to decode secret '{sec_ref}' from base64: {e}")))?;

        String::from_utf8(value_bytes).map_err(|_| {
            CliError::InvalidInput(format!(
                "Secret '{sec_ref}' contains non-UTF-8 bytes. Binary secrets cannot be used in templates.",
            ))
        })
    };

    let cache = reveal_all(&placeholders, reveal_fn)
        .map_err(|failures| CliError::InvalidInput(format_reveal_failures(&failures)))?;

    // Substitute all placeholders
    let mut output = template.clone();
    for (full_match, inner) in &placeholders {
        if let Some(value) = cache.get(inner) {
            output = output.replacen(full_match, value, 1);
        }
    }

    write_output(args.output.as_deref(), &output)?;

    Ok(())
}

fn write_output(path: Option<&str>, content: &str) -> CliResult<()> {
    match path {
        Some(p) => {
            fs::write(p, content)
                .map_err(|e| CliError::InvalidInput(format!("Failed to write output file '{p}': {e}")))?;
        }
        None => {
            std::io::stdout()
                .write_all(content.as_bytes())
                .map_err(|e| CliError::InvalidInput(format!("Failed to write to stdout: {e}")))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hierarkey_core::api::status::ApiErrorCode;

    // -------------------------------------------------------------------------
    // find_placeholders
    // -------------------------------------------------------------------------

    #[test]
    fn test_find_placeholders_basic() {
        let result = find_placeholders("FOO={{ /ns:key }}");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "{{ /ns:key }}");
        assert_eq!(result[0].1, "/ns:key");
    }

    #[test]
    fn test_find_placeholders_no_spaces() {
        let result = find_placeholders("FOO={{/ns:key}}");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "{{/ns:key}}");
        assert_eq!(result[0].1, "/ns:key");
    }

    #[test]
    fn test_find_placeholders_multiple() {
        let result = find_placeholders("A={{ /ns:a }}\nB={{ /ns:b }}");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1, "/ns:a");
        assert_eq!(result[1].1, "/ns:b");
    }

    #[test]
    fn test_find_placeholders_duplicate() {
        let result = find_placeholders("A={{ /ns:key }}\nB={{ /ns:key }}");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1, "/ns:key");
        assert_eq!(result[1].1, "/ns:key");
    }

    #[test]
    fn test_find_placeholders_none() {
        assert!(find_placeholders("FOO=bar\nBAZ=qux").is_empty());
    }

    #[test]
    fn test_find_placeholders_unclosed() {
        assert!(find_placeholders("FOO={{ /ns:key").is_empty());
    }

    // -------------------------------------------------------------------------
    // reveal_all
    // -------------------------------------------------------------------------

    fn forbidden_error() -> CliError {
        CliError::ApiError {
            code: ApiErrorCode::Forbidden,
            message: "Permission denied".to_string(),
            details: None,
        }
    }

    fn not_found_error() -> CliError {
        CliError::ApiError {
            code: ApiErrorCode::NotFound,
            message: "Secret not found".to_string(),
            details: None,
        }
    }

    fn placeholders_from(template: &str) -> Vec<(String, String)> {
        find_placeholders(template)
    }

    #[test]
    fn reveal_all_succeeds_when_all_secrets_available() {
        let ph = placeholders_from("A={{ /ns:a }}\nB={{ /ns:b }}");
        let result = reveal_all(&ph, |r| match r {
            "/ns:a" => Ok("value-a".to_string()),
            "/ns:b" => Ok("value-b".to_string()),
            _ => unreachable!(),
        });
        let cache = result.expect("should succeed");
        assert_eq!(cache["/ns:a"], "value-a");
        assert_eq!(cache["/ns:b"], "value-b");
    }

    #[test]
    fn reveal_all_collects_all_failures_instead_of_stopping_at_first() {
        let ph = placeholders_from("A={{ /ns:a }}\nB={{ /ns:b }}\nC={{ /ns:c }}");
        let failures = reveal_all(&ph, |_| Err(forbidden_error())).expect_err("should fail");
        assert_eq!(failures.len(), 3, "all three refs should be reported");
    }

    #[test]
    fn reveal_all_reports_partial_failure() {
        let ph = placeholders_from("A={{ /ns:ok }}\nB={{ /ns:denied }}");
        let failures = reveal_all(&ph, |r| match r {
            "/ns:ok" => Ok("good".to_string()),
            "/ns:denied" => Err(forbidden_error()),
            _ => unreachable!(),
        })
        .expect_err("should fail");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].sec_ref, "/ns:denied");
        assert!(failures[0].is_forbidden);
    }

    #[test]
    fn reveal_all_deduplicates_repeated_refs() {
        // Same ref used twice in the template — should only appear once in failures.
        let ph = placeholders_from("A={{ /ns:key }}\nB={{ /ns:key }}");
        let failures = reveal_all(&ph, |_| Err(forbidden_error())).expect_err("should fail");
        assert_eq!(failures.len(), 1, "duplicate ref should only be reported once");
    }

    #[test]
    fn reveal_all_marks_forbidden_errors() {
        let ph = placeholders_from("A={{ /ns:a }}");
        let failures = reveal_all(&ph, |_| Err(forbidden_error())).expect_err("should fail");
        assert!(failures[0].is_forbidden);
    }

    #[test]
    fn reveal_all_not_found_is_not_marked_forbidden() {
        let ph = placeholders_from("A={{ /ns:a }}");
        let failures = reveal_all(&ph, |_| Err(not_found_error())).expect_err("should fail");
        assert!(!failures[0].is_forbidden);
        assert_eq!(failures[0].reason, "not found");
    }

    // -------------------------------------------------------------------------
    // format_reveal_failures
    // -------------------------------------------------------------------------

    #[test]
    fn format_single_failure_uses_singular_noun() {
        let failures = vec![RevealFailure {
            sec_ref: "/ns:key".to_string(),
            reason: "not found".to_string(),
            is_forbidden: false,
        }];
        let msg = format_reveal_failures(&failures);
        assert!(msg.starts_with("1 secret could not be revealed"));
    }

    #[test]
    fn format_multiple_failures_uses_plural_noun() {
        let failures = vec![
            RevealFailure {
                sec_ref: "/ns:a".to_string(),
                reason: "not found".to_string(),
                is_forbidden: false,
            },
            RevealFailure {
                sec_ref: "/ns:b".to_string(),
                reason: "not found".to_string(),
                is_forbidden: false,
            },
        ];
        let msg = format_reveal_failures(&failures);
        assert!(msg.starts_with("2 secrets could not be revealed"));
    }

    #[test]
    fn format_includes_hint_when_any_failure_is_forbidden() {
        let failures = vec![
            RevealFailure {
                sec_ref: "/ns:a".to_string(),
                reason: "Permission denied".to_string(),
                is_forbidden: true,
            },
            RevealFailure {
                sec_ref: "/ns:b".to_string(),
                reason: "not found".to_string(),
                is_forbidden: false,
            },
        ];
        let msg = format_reveal_failures(&failures);
        assert!(msg.contains("Hint:"), "should include RBAC hint when any failure is Forbidden");
    }

    #[test]
    fn format_omits_hint_when_no_forbidden_failures() {
        let failures = vec![RevealFailure {
            sec_ref: "/ns:key".to_string(),
            reason: "not found".to_string(),
            is_forbidden: false,
        }];
        let msg = format_reveal_failures(&failures);
        assert!(!msg.contains("Hint:"), "should not include hint when no Forbidden errors");
    }

    #[test]
    fn format_lists_each_ref_in_output() {
        let failures = vec![
            RevealFailure {
                sec_ref: "/ns:a".to_string(),
                reason: "Permission denied".to_string(),
                is_forbidden: true,
            },
            RevealFailure {
                sec_ref: "/ns:b".to_string(),
                reason: "not found".to_string(),
                is_forbidden: false,
            },
        ];
        let msg = format_reveal_failures(&failures);
        assert!(msg.contains("/ns:a"));
        assert!(msg.contains("/ns:b"));
    }
}
