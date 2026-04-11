// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::rbac::spec::RuleSpec;
use crate::rbac::{
    AccountPattern, NamespacePattern, Permission, PolicyEffect, SecretPattern, Target, TargetKind, WhereClause,
    WhereExpr,
};
use crate::rbac::where_::WhereOperator;
use nom::error::Error;
use nom::{
    Finish, IResult, Parser,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while1},
    character::complete::{char, multispace0, multispace1},
    combinator::{all_consuming, cut, map, opt, value},
    multi::separated_list1,
    sequence::preceded,
};
use std::str::FromStr;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum RuleParseError {
    NomError(String),
    InvalidPermission(String),
    InvalidPattern(String),
    InvalidTargetKind(String),
}

impl std::fmt::Display for RuleParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(e) => write!(f, "parse error: {e}"),
            Self::InvalidPermission(p) => write!(f, "invalid permission: {p}"),
            Self::InvalidPattern(p) => write!(f, "invalid pattern: {p}"),
            Self::InvalidTargetKind(k) => write!(f, "invalid target kind: {k}"),
        }
    }
}

impl std::error::Error for RuleParseError {}

// ============================================================================
// Nom Parsers
// ============================================================================

type ParseResult<'a, O> = IResult<&'a str, O, Error<&'a str>>;

/// Parse effect: "allow" or "deny" (case-insensitive)
fn parse_effect(input: &str) -> ParseResult<'_, PolicyEffect> {
    alt((
        value(PolicyEffect::Allow, tag_no_case("allow")),
        value(PolicyEffect::Deny, tag_no_case("deny")),
    ))
    .parse(input)
}

/// Parse and convert to Permission enum
fn parse_permission_token(input: &str) -> ParseResult<'_, &str> {
    take_while1(|c: char| c.is_alphanumeric() || c == ':' || c == '*' || c == '_')(input)
}

/// Parse the "to" keyword
fn parse_to(input: &str) -> ParseResult<'_, &str> {
    tag_no_case("to").parse(input)
}

/// Parse target kind token (lex only; validate later)
/// Accepts: letters + '_'
fn parse_target_kind_token(input: &str) -> ParseResult<'_, &str> {
    take_while1(|c: char| c.is_alphabetic() || c == '_').parse(input)
}

/// Parse a pattern token (lex only; validate later)
/// Accepts: alphanumeric, /, *, :, -, _, .
fn parse_pattern_token(input: &str) -> ParseResult<'_, &str> {
    take_while1(|c: char| c.is_alphanumeric() || matches!(c, '/' | '*' | ':' | '-' | '_' | '.')).parse(input)
}

// ============================================================================
// WHERE clause parsing
// ============================================================================

/// Characters valid in a label value (used for Eq, Ne, and In list items).
fn is_value_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

/// Parse the `[v1,v2,...]` list used by the `in` operator.
fn parse_in_list(input: &str) -> ParseResult<'_, Vec<String>> {
    map(
        (
            char('['),
            separated_list1(char(','), take_while1(is_value_char)),
            char(']'),
        ),
        |(_, items, _): (_, Vec<&str>, _)| items.into_iter().map(|s| s.to_string()).collect(),
    )
    .parse(input)
}

/// Parse a single where clause. Supported forms (after a label key):
///   `key=value`        — equality
///   `key!=value`       — inequality
///   `key in [v1,v2]`  — membership
///   `key exists`       — presence check
fn parse_where_clause(input: &str) -> ParseResult<'_, WhereClause> {
    let (input, key) = take_while1(|c: char| c.is_alphanumeric() || c == '_')(input)?;
    let (input, _) = multispace0(input)?;

    // "exists" — no value
    if let Ok((rest, _)) = tag_no_case::<_, _, Error<&str>>("exists").parse(input) {
        return Ok((rest, WhereClause {
            key: key.to_string(),
            operator: WhereOperator::Exists,
            ..Default::default()
        }));
    }

    // "in [v1,v2,...]"
    if let Ok((rest, values)) = preceded(
        (tag_no_case("in"), multispace0),
        parse_in_list,
    ).parse(input) {
        return Ok((rest, WhereClause {
            key: key.to_string(),
            operator: WhereOperator::In,
            values,
            ..Default::default()
        }));
    }

    // "!=" value
    if let Ok((rest, val)) = preceded(
        tag::<_, _, Error<&str>>("!="),
        take_while1(is_value_char),
    ).parse(input) {
        return Ok((rest, WhereClause {
            key: key.to_string(),
            operator: WhereOperator::Ne,
            value: val.to_string(),
            ..Default::default()
        }));
    }

    // "=" value (default)
    let (rest, val) = preceded(char('='), take_while1(is_value_char)).parse(input)?;
    Ok((rest, WhereClause {
        key: key.to_string(),
        value: val.to_string(),
        ..Default::default()
    }))
}

/// Parse optional where expression: "where <clause> [and <clause> ...]"
fn parse_where_expr(input: &str) -> ParseResult<'_, WhereExpr> {
    preceded(
        (tag_no_case("where"), multispace1),
        map(
            separated_list1((multispace1, tag_no_case("and"), multispace1), parse_where_clause),
            |clauses| WhereExpr { clauses },
        ),
    )
    .parse(input)
}

// ============================================================================
// Raw forms (lexed but not validated)
// ============================================================================

#[derive(Debug)]
struct RawTarget<'a> {
    kind: &'a str,
    pattern: Option<&'a str>, // None for "all"
}

#[derive(Debug)]
struct RuleSpecRaw<'a> {
    effect: PolicyEffect,
    permission: &'a str,
    target: RawTarget<'a>,
    condition: Option<WhereExpr>,
}

/// Parse target kind + optional pattern into RawTarget (no validation here)
fn parse_target_raw(input: &str) -> ParseResult<'_, RawTarget<'_>> {
    let (remaining, kind) = parse_target_kind_token(input)?;

    // "all" and "platform" are singleton targets with no pattern
    if kind.eq_ignore_ascii_case("all") || kind.eq_ignore_ascii_case("platform") {
        return Ok((remaining, RawTarget { kind, pattern: None }));
    }

    // Non-singleton targets require a pattern
    let (remaining, _) = multispace1.parse(remaining)?;
    let (remaining, pat) = cut(parse_pattern_token).parse(remaining)?;
    Ok((
        remaining,
        RawTarget {
            kind,
            pattern: Some(pat),
        },
    ))
}

/// Parse the complete rule specification into raw tokens
fn parse_rule_spec_inner(input: &str) -> ParseResult<'_, RuleSpecRaw<'_>> {
    let (remaining, effect) = parse_effect(input)?;
    let (remaining, _) = multispace1(remaining)?;

    let (remaining, permission) = parse_permission_token(remaining)?;
    let (remaining, _) = multispace1(remaining)?;

    let (remaining, _) = parse_to(remaining)?;
    let (remaining, _) = multispace1(remaining)?;

    let (remaining, target) = parse_target_raw(remaining)?;

    // Optional where clause
    let (remaining, condition) = opt(preceded(multispace0, parse_where_expr)).parse(remaining)?;

    Ok((
        remaining,
        RuleSpecRaw {
            effect,
            permission,
            target,
            condition,
        },
    ))
}

// ============================================================================
// Validation / conversion: raw -> typed
// ============================================================================

fn parse_target_kind_typed(s: &str) -> Result<TargetKind, RuleParseError> {
    if s.eq_ignore_ascii_case("all") {
        Ok(TargetKind::All)
    } else if s.eq_ignore_ascii_case("platform") {
        Ok(TargetKind::Platform)
    } else if s.eq_ignore_ascii_case("namespace") {
        Ok(TargetKind::Namespace)
    } else if s.eq_ignore_ascii_case("secret") {
        Ok(TargetKind::Secret)
    } else if s.eq_ignore_ascii_case("account") {
        Ok(TargetKind::Account)
    } else {
        Err(RuleParseError::InvalidTargetKind(s.to_string()))
    }
}

fn raw_target_to_target(raw: RawTarget<'_>) -> Result<Target, RuleParseError> {
    let kind = parse_target_kind_typed(raw.kind)?;

    match kind {
        TargetKind::All => Ok(Target::All),
        TargetKind::Platform => Ok(Target::Platform),

        TargetKind::Namespace => {
            let s = raw
                .pattern
                .ok_or_else(|| RuleParseError::InvalidPattern("<missing>".into()))?;
            let pat = NamespacePattern::from_str(s).map_err(|_| RuleParseError::InvalidPattern(s.to_string()))?;
            Ok(Target::Namespace(pat))
        }

        TargetKind::Secret => {
            let s = raw
                .pattern
                .ok_or_else(|| RuleParseError::InvalidPattern("<missing>".into()))?;
            let pat = SecretPattern::from_str(s).map_err(|_| RuleParseError::InvalidPattern(s.to_string()))?;
            Ok(Target::Secret(pat))
        }

        TargetKind::Account => {
            let s = raw
                .pattern
                .ok_or_else(|| RuleParseError::InvalidPattern("<missing>".into()))?;
            let pat = AccountPattern::from_str(s).map_err(|_| RuleParseError::InvalidPattern(s.to_string()))?;
            Ok(Target::Account(pat))
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Parse a rule specification string into a RuleSpec.
///
/// Grammar:
///   "<allow|deny> <permission> to <target-kind> <pattern> [where <k>=<v> [and ...]]"
///   "<allow|deny> <permission> to all [where ...]"
///
/// Examples:
///   "allow secret:reveal to namespace /prod/**"
///   "deny  secret:*    to secret /prod:db/* where mfa=true"
///   "allow namespace:* to account admin-* where role=admin and env=prod"
///   "allow platform:admin to all"
pub fn parse_rule_spec(input: &str) -> Result<RuleSpec, RuleParseError> {
    let trimmed = input.trim();

    let raw = all_consuming(parse_rule_spec_inner)
        .parse(trimmed)
        .finish()
        .map(|(_, raw)| raw)
        .map_err(|e| RuleParseError::NomError(format!("{e}")))?;

    let permission = Permission::from_str(raw.permission)
        .map_err(|_| RuleParseError::InvalidPermission(raw.permission.to_string()))?;

    let target = raw_target_to_target(raw.target)?;

    Ok(RuleSpec {
        effect: raw.effect,
        permission,
        target,
        condition: raw.condition,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_effect() {
        assert_eq!(parse_effect("allow").unwrap().1, PolicyEffect::Allow);
        assert_eq!(parse_effect("deny").unwrap().1, PolicyEffect::Deny);
        assert_eq!(parse_effect("ALLOW").unwrap().1, PolicyEffect::Allow);
        assert_eq!(parse_effect("Deny").unwrap().1, PolicyEffect::Deny);
    }

    #[test]
    fn test_parse_permission_token() {
        assert_eq!(parse_permission_token("secret:reveal").unwrap().1, "secret:reveal");
        assert_eq!(parse_permission_token("SeCrET:REAd").unwrap().1, "SeCrET:REAd");
        assert_eq!(parse_permission_token("secret:*").unwrap().1, "secret:*");
        assert_eq!(parse_permission_token("all").unwrap().1, "all");
    }

    #[test]
    fn test_permission_validation_in_public_api() {
        // valid permission should pass
        let rule = parse_rule_spec("allow secret:reveal to namespace /prod/**").unwrap();
        assert_eq!(rule.permission, Permission::SecretReveal);

        // invalid permission should surface InvalidPermission
        let err = parse_rule_spec("allow invalid:perm to namespace /test").unwrap_err();
        match err {
            RuleParseError::InvalidPermission(p) => assert_eq!(p, "invalid:perm"),
            other => panic!("expected InvalidPermission, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_pattern_token() {
        assert_eq!(parse_pattern_token("/prod/**").unwrap().1, "/prod/**");
        assert_eq!(parse_pattern_token("/prod:db/*").unwrap().1, "/prod:db/*");
        assert_eq!(parse_pattern_token("admin-*").unwrap().1, "admin-*");
    }

    #[test]
    fn test_parse_where_clause_eq() {
        let (_, clause) = parse_where_clause("mfa=true").unwrap();
        assert_eq!(clause.key, "mfa");
        assert_eq!(clause.operator, WhereOperator::Eq);
        assert_eq!(clause.value, "true");
    }

    #[test]
    fn test_parse_where_clause_ne() {
        let (_, clause) = parse_where_clause("env!=dev").unwrap();
        assert_eq!(clause.key, "env");
        assert_eq!(clause.operator, WhereOperator::Ne);
        assert_eq!(clause.value, "dev");
    }

    #[test]
    fn test_parse_where_clause_in() {
        let (_, clause) = parse_where_clause("env in [prod,staging]").unwrap();
        assert_eq!(clause.key, "env");
        assert_eq!(clause.operator, WhereOperator::In);
        assert_eq!(clause.values, vec!["prod", "staging"]);
    }

    #[test]
    fn test_parse_where_clause_exists() {
        let (_, clause) = parse_where_clause("mfa exists").unwrap();
        assert_eq!(clause.key, "mfa");
        assert_eq!(clause.operator, WhereOperator::Exists);
    }

    #[test]
    fn test_parse_simple_rule() {
        let rule = parse_rule_spec("allow secret:reveal to namespace /prod/**").unwrap();
        assert_eq!(rule.effect, PolicyEffect::Allow);
        assert_eq!(rule.permission, Permission::SecretReveal);
        assert_eq!(rule.target, Target::Namespace(NamespacePattern::from_str("/prod/**").unwrap()));
        assert!(rule.condition.is_none());
    }

    #[test]
    fn test_parse_rule_with_where() {
        let rule = parse_rule_spec("deny secret:* to secret /prod:db/* where mfa=true").unwrap();
        assert_eq!(rule.effect, PolicyEffect::Deny);
        assert_eq!(rule.permission, Permission::SecretAll);
        assert_eq!(rule.target, Target::Secret(SecretPattern::from_str("/prod:db/*").unwrap()));
        assert!(rule.condition.is_some());
        let cond = rule.condition.unwrap();
        assert_eq!(cond.clauses.len(), 1);
        assert_eq!(cond.clauses[0].key, "mfa");
        assert_eq!(cond.clauses[0].operator, WhereOperator::Eq);
        assert_eq!(cond.clauses[0].value, "true");
    }

    #[test]
    fn test_parse_rule_with_multiple_where_clauses() {
        let rule = parse_rule_spec("allow namespace:* to account admin-* where role=admin and env=prod").unwrap();
        assert_eq!(rule.effect, PolicyEffect::Allow);
        assert_eq!(rule.permission, Permission::NamespaceAll);
        assert_eq!(rule.target, Target::Account(AccountPattern::from_str("admin-*").unwrap()));
        let cond = rule.condition.unwrap();
        assert_eq!(cond.clauses.len(), 2);
        assert_eq!(cond.clauses[0].key, "role");
        assert_eq!(cond.clauses[0].operator, WhereOperator::Eq);
        assert_eq!(cond.clauses[0].value, "admin");
        assert_eq!(cond.clauses[1].key, "env");
        assert_eq!(cond.clauses[1].operator, WhereOperator::Eq);
        assert_eq!(cond.clauses[1].value, "prod");
    }

    #[test]
    fn test_parse_rule_with_ne_condition() {
        let rule = parse_rule_spec("deny secret:reveal to namespace /prod/** where env!=dev").unwrap();
        let cond = rule.condition.unwrap();
        assert_eq!(cond.clauses[0].key, "env");
        assert_eq!(cond.clauses[0].operator, WhereOperator::Ne);
        assert_eq!(cond.clauses[0].value, "dev");
    }

    #[test]
    fn test_parse_rule_with_in_condition() {
        let rule = parse_rule_spec("allow secret:reveal to namespace /prod where env in [prod,staging]").unwrap();
        let cond = rule.condition.unwrap();
        assert_eq!(cond.clauses[0].key, "env");
        assert_eq!(cond.clauses[0].operator, WhereOperator::In);
        assert_eq!(cond.clauses[0].values, vec!["prod", "staging"]);
    }

    #[test]
    fn test_parse_rule_with_exists_condition() {
        let rule = parse_rule_spec("allow secret:reveal to namespace /prod where mfa exists").unwrap();
        let cond = rule.condition.unwrap();
        assert_eq!(cond.clauses[0].key, "mfa");
        assert_eq!(cond.clauses[0].operator, WhereOperator::Exists);
    }

    #[test]
    fn test_parse_rule_mixed_operators() {
        let rule =
            parse_rule_spec("allow secret:reveal to namespace /prod where env in [prod,staging] and tier!=free")
                .unwrap();
        let cond = rule.condition.unwrap();
        assert_eq!(cond.clauses.len(), 2);
        assert_eq!(cond.clauses[0].operator, WhereOperator::In);
        assert_eq!(cond.clauses[1].operator, WhereOperator::Ne);
    }

    #[test]
    fn test_parse_all_target() {
        // NOTE: "all" is now a TARGET KIND, not a permission.
        let rule = parse_rule_spec("allow rbac:admin to all").unwrap();
        assert_eq!(rule.effect, PolicyEffect::Allow);
        assert_eq!(rule.target, Target::All);
    }

    #[test]
    fn test_parse_platform_target() {
        let rule = parse_rule_spec("allow rbac:admin to platform").unwrap();
        assert_eq!(rule.effect, PolicyEffect::Allow);
        assert_eq!(rule.target, Target::Platform);
    }

    #[test]
    fn test_platform_target_does_not_take_a_pattern() {
        assert!(parse_rule_spec("allow rbac:admin to platform /specific").is_err());
    }

    #[test]
    fn test_parse_case_insensitive_keywords() {
        // allow/deny + to + target kind are case-insensitive
        let rule = parse_rule_spec("ALLOW secret:reveal TO Namespace /test").unwrap();
        assert_eq!(rule.effect, PolicyEffect::Allow);
        assert_eq!(rule.permission, Permission::SecretReveal);
        assert_eq!(rule.target, Target::Namespace(NamespacePattern::from_str("/test").unwrap()));
    }

    #[test]
    fn test_invalid_effect() {
        let err = parse_rule_spec("permit secret:reveal to namespace /test").unwrap_err();
        match err {
            RuleParseError::NomError(_) => {}
            other => panic!("expected NomError, got: {other:?}"),
        }
    }

    #[test]
    fn test_invalid_target_kind() {
        let err = parse_rule_spec("allow secret:reveal to namespce /test").unwrap_err();
        match err {
            RuleParseError::InvalidTargetKind(k) => assert_eq!(k, "namespce"),
            other => panic!("expected InvalidTargetKind, got: {other:?}"),
        }
    }

    #[test]
    fn test_missing_to() {
        let err = parse_rule_spec("allow secret:reveal namespace /test").unwrap_err();
        match err {
            RuleParseError::NomError(_) => {}
            other => panic!("expected NomError, got: {other:?}"),
        }
    }

    #[test]
    fn test_disallow_star_permission_if_not_supported() {
        // In the new parser, '*' is lexable as a token, but Permission::from_str should reject it.
        let err = parse_rule_spec("allow * to all").unwrap_err();
        match err {
            RuleParseError::InvalidPermission(p) => assert_eq!(p, "*"),
            other => panic!("expected InvalidPermission, got: {other:?}"),
        }
    }

    #[test]
    fn test_all_does_not_take_a_pattern() {
        // Our parse_target_raw accepts optional " *" after all (permissive).
        // The overall parser should still fail if there is a real pattern after "all".
        assert!(parse_rule_spec("allow platform:admin to all /specific").is_err());
    }

    #[test]
    fn test_rule_parse_error_display() {
        let e = RuleParseError::NomError("some detail".to_string());
        assert_eq!(e.to_string(), "parse error: some detail");

        let e = RuleParseError::InvalidPermission("bad:perm".to_string());
        assert_eq!(e.to_string(), "invalid permission: bad:perm");

        let e = RuleParseError::InvalidPattern("bad-pat".to_string());
        assert_eq!(e.to_string(), "invalid pattern: bad-pat");

        let e = RuleParseError::InvalidTargetKind("badkind".to_string());
        assert_eq!(e.to_string(), "invalid target kind: badkind");
    }

    #[test]
    fn test_invalid_pattern_via_secret_missing_colon() {
        // "secret nocolon" — valid target kind but pattern fails SecretPattern::from_str
        let err = parse_rule_spec("allow secret:reveal to secret nocolon").unwrap_err();
        match err {
            RuleParseError::InvalidPattern(p) => assert_eq!(p, "nocolon"),
            other => panic!("expected InvalidPattern, got: {other:?}"),
        }
    }

    #[test]
    fn test_invalid_pattern_via_namespace_no_leading_slash() {
        // "namespace prod" — namespace pattern must start with '/'
        let err = parse_rule_spec("allow secret:reveal to namespace prod").unwrap_err();
        match err {
            RuleParseError::InvalidPattern(p) => assert_eq!(p, "prod"),
            other => panic!("expected InvalidPattern, got: {other:?}"),
        }
    }

    #[test]
    fn test_invalid_pattern_via_account_with_slash() {
        // "account a/b" is invalid (account pattern must not contain '/')
        // Note: the parser's pattern token doesn't accept '/' in account names,
        // so this will actually be a NomError (leftover input) rather than InvalidPattern.
        // Verify it at least fails:
        assert!(parse_rule_spec("allow secret:reveal to account a/b").is_err());
    }
}
