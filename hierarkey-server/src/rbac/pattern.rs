// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::rbac::MatchKind;
use crate::rbac::target::glob_match;
use hierarkey_core::error::validation::ValidationError;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    NamespacePattern,
    SecretPattern,
    AccountPattern,
}

// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPattern {
    pub base: String,
    pub kind: MatchKind,
}

impl std::fmt::Display for AccountPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base)
    }
}

impl FromStr for AccountPattern {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ValidationError::Custom("account pattern must not be empty".into()));
        }

        if s.eq_ignore_ascii_case("all") {
            return Ok(AccountPattern {
                base: s.to_string(),
                kind: MatchKind::All,
            });
        }

        if s.contains('/') || s.contains(':') {
            return Err(ValidationError::Custom("account pattern must not contain '/' or ':'".into()));
        }

        let kind = if s.contains('*') {
            if !s.ends_with('*') || s[..s.len() - 1].contains('*') {
                return Err(ValidationError::Custom(
                    "account pattern: '*' is only allowed as a single trailing wildcard".into(),
                ));
            }
            MatchKind::PrefixOnly
        } else {
            MatchKind::Exact
        };

        Ok(AccountPattern {
            base: s.to_string(),
            kind,
        })
    }
}

impl AccountPattern {
    pub fn matches(&self, candidate: &str) -> bool {
        match self.kind {
            MatchKind::All => true,
            MatchKind::Exact => candidate == self.base,
            MatchKind::PrefixOnly => {
                let prefix = self.base.strip_suffix('*').unwrap_or(&self.base);
                candidate.starts_with(prefix)
            }
            MatchKind::Subtree | MatchKind::PrefixSubtree => false,
        }
    }

    /// Return a score representing how specific this pattern is.
    /// Higher scores win when multiple patterns match the same input.
    ///
    /// # Tier weights (must stay strictly ordered: Exact > PrefixOnly > Subtree > PrefixSubtree > All)
    ///
    /// | Kind          | Base weight | Rationale                                              |
    /// |---------------|-------------|--------------------------------------------------------|
    /// | `Exact`       | 1000        | Literal match — most specific by definition            |
    /// | `PrefixOnly`  | 700         | `foo*` matches within one level, no sub-namespaces     |
    /// | `Subtree`     | 650         | `foo/**` matches sub-namespaces but still has a prefix |
    /// | `PrefixSubtree` | 500       | `foo*/**` combines prefix wildcard with subtree walk   |
    /// | `All`         | 0           | Catch-all — least specific                             |
    ///
    /// A small bonus equal to `base.len()` is added so that longer (more specific) literal
    /// prefixes beat shorter ones within the same tier. Each `*` in the base subtracts 10
    /// to penalise patterns that are more wildcard-heavy. The gaps between tier weights (≥ 50)
    /// are deliberately large enough that no realistic combination of length bonus / wildcard
    /// penalty can cause a lower-tier pattern to outrank a higher-tier one.
    pub fn specificity_score(&self) -> u32 {
        if self.kind == MatchKind::All {
            return 0;
        }
        let base_len = self.base.len() as i32;
        let wildcard_penalty = (self.base.matches('*').count() as i32) * 10;
        let kind_weight = match self.kind {
            MatchKind::Exact => 1000,
            MatchKind::PrefixOnly => 700,
            MatchKind::Subtree => 650,
            MatchKind::PrefixSubtree => 500,
            MatchKind::All => unreachable!(),
        };
        (kind_weight + (base_len - wildcard_penalty).max(0)) as u32
    }
}

// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretPathPattern {
    inner: NamespacePattern,
}

impl std::fmt::Display for SecretPathPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.inner.kind == MatchKind::All {
            return write!(f, "all");
        }
        let display = self.inner.base.strip_prefix('/').unwrap_or(&self.inner.base);
        write!(f, "{display}")
    }
}

impl FromStr for SecretPathPattern {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ValidationError::Custom("secret path must not be empty".into()));
        }

        if s.eq_ignore_ascii_case("all") {
            return Ok(Self {
                inner: NamespacePattern {
                    base: s.to_string(),
                    kind: MatchKind::All,
                },
            });
        }

        if s.starts_with('/') {
            return Err(ValidationError::Custom(
                "secret path must not start with '/' (use 'db/password', not '/db/password')".into(),
            ));
        }
        if s.contains(':') {
            return Err(ValidationError::Custom("secret path must not contain ':'".into()));
        }

        let normalized = format!("/{s}");
        let inner = NamespacePattern::from_str(&normalized)?;
        Ok(Self { inner })
    }
}

impl SecretPathPattern {
    pub fn kind(&self) -> MatchKind {
        self.inner.kind
    }

    pub fn matches(&self, candidate_secret_path: &str) -> bool {
        if self.inner.kind == MatchKind::All {
            return !candidate_secret_path.is_empty() && !candidate_secret_path.starts_with('/');
        }
        if candidate_secret_path.is_empty() || candidate_secret_path.starts_with('/') {
            return false;
        }
        let normalized = format!("/{candidate_secret_path}");
        self.inner.matches(&normalized)
    }

    pub fn specificity_score(&self) -> u32 {
        self.inner.specificity_score()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretPattern {
    pub namespace: NamespacePattern,
    pub secret: SecretPathPattern,
}

impl std::fmt::Display for SecretPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.secret)
    }
}

impl FromStr for SecretPattern {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("all") {
            return Ok(SecretPattern {
                namespace: NamespacePattern {
                    base: "all".to_string(),
                    kind: MatchKind::All,
                },
                secret: SecretPathPattern {
                    inner: NamespacePattern {
                        base: "all".to_string(),
                        kind: MatchKind::All,
                    },
                },
            });
        }

        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ValidationError::Custom(
                "secret pattern must be '<namespace>:<secretpath>' or 'all'".into(),
            ));
        }

        let namespace = NamespacePattern::from_str(parts[0])?;
        let secret = SecretPathPattern::from_str(parts[1])?;
        Ok(SecretPattern { namespace, secret })
    }
}

impl SecretPattern {
    pub fn matches(&self, candidate: &str) -> bool {
        if self.namespace.kind == MatchKind::All && self.secret.inner.kind == MatchKind::All {
            return candidate.contains(':');
        }

        let parts: Vec<&str> = candidate.splitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }
        self.namespace.matches(parts[0]) && self.secret.matches(parts[1])
    }

    pub fn specificity_score(&self) -> u32 {
        self.namespace
            .specificity_score()
            .saturating_add(self.secret.specificity_score())
    }
}

// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacePattern {
    pub base: String,
    pub kind: MatchKind,
}

impl std::fmt::Display for NamespacePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base)
    }
}

impl FromStr for NamespacePattern {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("all") {
            return Ok(NamespacePattern {
                base: s.to_string(),
                kind: MatchKind::All,
            });
        }

        if !s.starts_with('/') {
            return Err(ValidationError::Custom("namespace pattern must start with '/'".into()));
        }
        if s == "/" {
            return Err(ValidationError::Custom(
                "namespace pattern cannot be '/' (no empty path)".into(),
            ));
        }
        if s.ends_with('/') {
            return Err(ValidationError::Custom("namespace pattern must not end with '/'".into()));
        }
        if s.contains("//") {
            return Err(ValidationError::Custom(
                "namespace pattern must not contain empty segments ('//')".into(),
            ));
        }
        if s.contains(':') {
            return Err(ValidationError::Custom("namespace pattern must not contain ':'".into()));
        }

        let segments: Vec<&str> = s.split('/').skip(1).collect();
        if segments.is_empty() {
            return Err(ValidationError::Custom(
                "namespace pattern must contain at least one segment".into(),
            ));
        }

        let is_recursive = |seg: &str| seg == "**";
        let has_any_star = |seg: &str| seg.contains('*');
        let is_trailing_star_segment = |seg: &str| seg.ends_with('*') && !seg[..seg.len() - 1].contains('*');

        for (i, seg) in segments.iter().enumerate() {
            if is_recursive(seg) && i != segments.len() - 1 {
                return Err(ValidationError::Custom(
                    "namespace pattern: '**' is only allowed as the last segment".into(),
                ));
            }
        }

        let last_is_subtree = is_recursive(segments[segments.len() - 1]);
        let mut star_segment_idx: Option<usize> = None;

        for (i, seg) in segments.iter().enumerate() {
            if is_recursive(seg) {
                continue;
            }
            if !has_any_star(seg) {
                continue;
            }
            if !is_trailing_star_segment(seg) {
                return Err(ValidationError::Custom(format!(
                    "namespace pattern: '*' is only allowed as a single trailing wildcard in a segment (got segment '{seg}')"
                )));
            }
            if star_segment_idx.is_some() {
                return Err(ValidationError::Custom(
                    "namespace pattern: only one segment may end with '*'".into(),
                ));
            }
            star_segment_idx = Some(i);
        }

        if let Some(idx) = star_segment_idx {
            if last_is_subtree {
                if idx != segments.len() - 2 {
                    return Err(ValidationError::Custom(
                        "namespace pattern: when ending with '/**', only the segment directly before '**' may end with '*'".into(),
                    ));
                }
            } else if idx != segments.len() - 1 {
                return Err(ValidationError::Custom(
                    "namespace pattern: only the last segment may end with '*' (unless the pattern ends with '/**')"
                        .into(),
                ));
            }
        }

        if !last_is_subtree && segments.last().is_some_and(|seg| seg.contains("**")) {
            return Err(ValidationError::Custom(
                "namespace pattern: '**' is only valid as the full last segment".into(),
            ));
        }

        let kind = if last_is_subtree {
            MatchKind::Subtree
        } else if segments.last().map(|seg| seg.ends_with('*')).unwrap_or(false) {
            MatchKind::PrefixOnly
        } else {
            MatchKind::Exact
        };

        Ok(NamespacePattern {
            base: s.to_string(),
            kind,
        })
    }
}

impl NamespacePattern {
    pub fn matches(&self, candidate: &str) -> bool {
        match self.kind {
            MatchKind::All => true,
            MatchKind::Exact => candidate == self.base,
            MatchKind::PrefixOnly => {
                // base stored as e.g. "/prod*"; '*' matches within a single segment (no '/' crossing)
                let prefix = self.base.strip_suffix('*').unwrap_or(&self.base);
                candidate.starts_with(prefix) && !candidate[prefix.len()..].contains('/')
            }
            MatchKind::Subtree => {
                // base stored as e.g. "/foo/**"; '**' requires at least one additional segment
                let base = self.base.strip_suffix("/**").unwrap_or(&self.base);
                candidate.starts_with(&format!("{base}/"))
            }
            MatchKind::PrefixSubtree => glob_match(candidate, &self.base),
        }
    }

    pub fn specificity_score(&self) -> u32 {
        if self.kind == MatchKind::All {
            return 0;
        }
        let base_len = self.base.len() as i32;
        let wildcard_count = match self.kind {
            MatchKind::Subtree => self.base.matches('*').count().saturating_sub(2),
            _ => self.base.matches('*').count(),
        } as i32;
        let wildcard_penalty = wildcard_count * 10;
        let kind_weight = match self.kind {
            MatchKind::Exact => 1000,
            MatchKind::PrefixOnly => 700,
            MatchKind::Subtree => 650,
            MatchKind::PrefixSubtree => 500,
            MatchKind::All => unreachable!(),
        };
        (kind_weight + (base_len - wildcard_penalty).max(0)) as u32
    }
}

// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn assert_err_contains<T, E: ToString>(res: Result<T, E>, needle: &str) {
        match res {
            Ok(_) => panic!("expected Err containing '{needle}', got Ok(_)"),
            Err(e) => {
                let err = e.to_string();
                assert!(err.contains(needle), "expected error to contain '{needle}', got: {err}");
            }
        }
    }

    // =========================================================================================
    // AccountPattern
    // =========================================================================================

    #[test]
    fn account_parse_exact_ok() {
        let p = AccountPattern::from_str("john").unwrap();
        assert_eq!(p.kind, MatchKind::Exact);
        assert_eq!(p.base, "john");
        assert_eq!(p.to_string(), "john");
    }

    #[test]
    fn account_parse_prefix_ok() {
        let p = AccountPattern::from_str("john*").unwrap();
        assert_eq!(p.kind, MatchKind::PrefixOnly);
        assert_eq!(p.base, "john*");
    }

    #[test]
    fn account_parse_all_ok() {
        let p = AccountPattern::from_str("all").unwrap();
        assert_eq!(p.kind, MatchKind::All);
    }

    #[test]
    fn account_all_case_insensitive() {
        assert_eq!(AccountPattern::from_str("ALL").unwrap().kind, MatchKind::All);
        assert_eq!(AccountPattern::from_str("All").unwrap().kind, MatchKind::All);
    }

    #[test]
    fn account_matches_all() {
        let p = AccountPattern::from_str("all").unwrap();
        assert!(p.matches("john"));
        assert!(p.matches("anyone"));
        assert!(p.matches(""));
    }

    #[test]
    fn account_all_specificity_is_zero() {
        assert_eq!(AccountPattern::from_str("all").unwrap().specificity_score(), 0);
    }

    #[test]
    fn account_parse_reject_empty() {
        assert_err_contains(AccountPattern::from_str(""), "must not be empty");
    }

    #[test]
    fn account_parse_reject_slash_or_colon() {
        assert_err_contains(AccountPattern::from_str("team/a"), "must not contain '/'");
        assert_err_contains(AccountPattern::from_str("team:a"), "must not contain '/'");
    }

    #[test]
    fn account_parse_reject_star_not_trailing() {
        assert_err_contains(AccountPattern::from_str("jo*hn"), "single trailing wildcard");
    }

    #[test]
    fn account_parse_reject_multiple_stars() {
        assert_err_contains(AccountPattern::from_str("john**"), "single trailing wildcard");
    }

    #[test]
    fn account_matches_exact() {
        let p = AccountPattern::from_str("john").unwrap();
        assert!(p.matches("john"));
        assert!(!p.matches("johnny"));
    }

    #[test]
    fn account_matches_prefix() {
        let p = AccountPattern::from_str("john*").unwrap();
        assert!(p.matches("john"));
        assert!(p.matches("johnny"));
        assert!(!p.matches("jane"));
    }

    #[test]
    fn account_specificity_ordering() {
        let all = AccountPattern::from_str("all").unwrap();
        let prefix = AccountPattern::from_str("john*").unwrap();
        let exact = AccountPattern::from_str("john").unwrap();
        assert_eq!(all.specificity_score(), 0);
        assert!(prefix.specificity_score() > all.specificity_score());
        assert!(exact.specificity_score() > prefix.specificity_score());
    }

    // =========================================================================================
    // NamespacePattern
    // =========================================================================================

    #[test]
    fn namespace_parse_all_ok() {
        let p = NamespacePattern::from_str("all").unwrap();
        assert_eq!(p.kind, MatchKind::All);
        assert_eq!(p.to_string(), "all");
    }

    #[test]
    fn namespace_all_case_insensitive() {
        assert_eq!(NamespacePattern::from_str("ALL").unwrap().kind, MatchKind::All);
    }

    #[test]
    fn namespace_matches_all() {
        let p = NamespacePattern::from_str("all").unwrap();
        assert!(p.matches("/prod"));
        assert!(p.matches("/prod/app1"));
        assert!(p.matches("anything"));
    }

    #[test]
    fn namespace_all_specificity_is_zero() {
        assert_eq!(NamespacePattern::from_str("all").unwrap().specificity_score(), 0);
    }

    #[test]
    fn namespace_parse_exact_single_segment() {
        let p = NamespacePattern::from_str("/prod").unwrap();
        assert_eq!(p.kind, MatchKind::Exact);
        assert_eq!(p.base, "/prod");
    }

    #[test]
    fn namespace_parse_prefix_star() {
        let p = NamespacePattern::from_str("/prod*").unwrap();
        assert_eq!(p.kind, MatchKind::PrefixOnly);
    }

    #[test]
    fn namespace_parse_subtree() {
        let p = NamespacePattern::from_str("/prod/**").unwrap();
        assert_eq!(p.kind, MatchKind::Subtree);
    }

    #[test]
    fn namespace_parse_reject_missing_leading_slash() {
        assert_err_contains(NamespacePattern::from_str("prod"), "must start with '/'");
    }

    #[test]
    fn namespace_parse_reject_root_only() {
        assert_err_contains(NamespacePattern::from_str("/"), "cannot be '/'");
    }

    #[test]
    fn namespace_parse_reject_trailing_slash() {
        assert_err_contains(NamespacePattern::from_str("/prod/"), "must not end with '/'");
    }

    #[test]
    fn namespace_parse_reject_double_slash() {
        assert_err_contains(NamespacePattern::from_str("/prod//app1"), "empty segments");
    }

    #[test]
    fn namespace_parse_reject_colon() {
        assert_err_contains(NamespacePattern::from_str("/prod:db"), "must not contain ':'");
    }

    #[test]
    fn namespace_parse_reject_double_star_not_last() {
        assert_err_contains(NamespacePattern::from_str("/prod/**/app1"), "only allowed as the last segment");
    }

    #[test]
    fn namespace_parse_reject_star_in_middle() {
        assert_err_contains(
            NamespacePattern::from_str("/foo*/bar"),
            "only the last segment may end with '*'",
        );
    }

    #[test]
    fn namespace_matches_exact_only() {
        let p = NamespacePattern::from_str("/prod/app1").unwrap();
        assert!(p.matches("/prod/app1"));
        assert!(!p.matches("/prod/app1/extra"));
        assert!(!p.matches("/prod/app2"));
    }

    #[test]
    fn namespace_matches_subtree() {
        let p = NamespacePattern::from_str("/foo/**").unwrap();
        assert!(p.matches("/foo/bar")); // one segment after base
        assert!(p.matches("/foo/bar/baz")); // multiple segments after base
        assert!(!p.matches("/foo")); // base itself does NOT match (**requires at least one segment)
        assert!(!p.matches("/foobar")); // no boundary crossing
        assert!(!p.matches("/other/bar"));
    }

    #[test]
    fn namespace_matches_prefix_only() {
        let p = NamespacePattern::from_str("/prod*").unwrap();
        assert!(p.matches("/prod")); // exact base matches
        assert!(p.matches("/production")); // * within same segment
        assert!(!p.matches("/prod/app")); // * does not cross '/'
        assert!(!p.matches("/staging"));
    }

    #[test]
    fn namespace_specificity_ordering() {
        let all = NamespacePattern::from_str("all").unwrap();
        let subtree = NamespacePattern::from_str("/prod/**").unwrap();
        let exact = NamespacePattern::from_str("/prod/app1").unwrap();
        assert_eq!(all.specificity_score(), 0);
        assert!(subtree.specificity_score() > all.specificity_score());
        assert!(exact.specificity_score() > subtree.specificity_score());
    }

    // =========================================================================================
    // SecretPattern
    // =========================================================================================

    #[test]
    fn secret_pattern_parse_all_ok() {
        let p = SecretPattern::from_str("all").unwrap();
        assert_eq!(p.namespace.kind, MatchKind::All);
        assert_eq!(p.secret.inner.kind, MatchKind::All);
        assert_eq!(p.to_string(), "all:all");
    }

    #[test]
    fn secret_pattern_all_matches_any_valid_secret_ref() {
        let p = SecretPattern::from_str("all").unwrap();
        assert!(p.matches("/prod/app1:db/password"));
        assert!(p.matches("/anything:whatever"));
        assert!(!p.matches("/no-colon-here"));
    }

    #[test]
    fn secret_pattern_all_specificity_is_zero() {
        assert_eq!(SecretPattern::from_str("all").unwrap().specificity_score(), 0);
    }

    #[test]
    fn secret_pattern_parse_ok_and_display() {
        let p = SecretPattern::from_str("/prod/app1:db/password").unwrap();
        assert_eq!(p.namespace.base, "/prod/app1");
        assert_eq!(p.to_string(), "/prod/app1:db/password");
    }

    #[test]
    fn secret_pattern_parse_reject_missing_colon() {
        assert_err_contains(SecretPattern::from_str("/prod/app1"), "must be '<namespace>:<secretpath>'");
    }

    #[test]
    fn secret_pattern_matches_both_parts() {
        let p = SecretPattern::from_str("/prod/app1:db/password").unwrap();
        assert!(p.matches("/prod/app1:db/password"));
        assert!(!p.matches("/prod/app1:db/other"));
        assert!(!p.matches("/prod/app2:db/password"));
    }

    // =========================================================================================
    // SecretPathPattern
    // =========================================================================================

    #[test]
    fn secret_path_parse_all_ok() {
        let p = SecretPathPattern::from_str("all").unwrap();
        assert_eq!(p.kind(), MatchKind::All);
        assert_eq!(p.to_string(), "all");
    }

    #[test]
    fn secret_path_matches_all() {
        let p = SecretPathPattern::from_str("all").unwrap();
        assert!(p.matches("db/password"));
        assert!(p.matches("anything"));
        assert!(!p.matches(""));
        assert!(!p.matches("/leading-slash"));
    }

    #[test]
    fn secret_path_parse_ok_and_display() {
        let p = SecretPathPattern::from_str("db/password").unwrap();
        assert_eq!(p.to_string(), "db/password");
    }

    #[test]
    fn secret_path_parse_reject_empty() {
        assert_err_contains(SecretPathPattern::from_str(""), "must not be empty");
    }

    #[test]
    fn secret_path_parse_reject_leading_slash() {
        assert_err_contains(SecretPathPattern::from_str("/db/password"), "must not start with '/'");
    }

    // =========================================================================================
    // Pattern enum
    // =========================================================================================

    #[test]
    fn pattern_enum_is_constructible() {
        let _ = Pattern::NamespacePattern;
        let _ = Pattern::SecretPattern;
        let _ = Pattern::AccountPattern;
    }

    // =========================================================================================
    // AccountPattern
    // =========================================================================================

    #[test]
    fn account_specificity_scores_are_reasonable() {
        // from: AccountPattern::specificity_score()
        let exact = AccountPattern::from_str("john").unwrap();
        let prefix = AccountPattern::from_str("john*").unwrap();

        assert!(exact.specificity_score() > prefix.specificity_score());
    }

    // =========================================================================================
    // SecretPathPattern
    // =========================================================================================

    #[test]
    fn secret_path_parse_ok_and_display_strips_leading_slash() {
        // from: SecretPathPattern::from_str() and Display for SecretPathPattern
        let p = SecretPathPattern::from_str("db/password").unwrap();
        assert_eq!(p.to_string(), "db/password");
    }

    #[test]
    fn secret_path_parse_reject_colon() {
        // from: SecretPathPattern::from_str()
        assert_err_contains(SecretPathPattern::from_str("db:password"), "must not contain ':'");
    }

    #[test]
    fn secret_path_matches_rejects_bad_candidate_shapes() {
        // from: SecretPathPattern::matches()
        let p = SecretPathPattern::from_str("db/password").unwrap();
        assert!(!p.matches("")); // empty candidate
        assert!(!p.matches("/db/password")); // candidate must NOT start with '/'
    }

    #[test]
    fn secret_path_matches_normalizes_candidate() {
        // from: SecretPathPattern::matches()
        let p = SecretPathPattern::from_str("db/password").unwrap();
        assert!(p.matches("db/password"));
    }

    // =========================================================================================
    // SecretPattern
    // =========================================================================================

    #[test]
    fn secret_pattern_parse_reject_bad_secretpath() {
        // from: SecretPattern::from_str() -> SecretPathPattern::from_str()
        assert_err_contains(
            SecretPattern::from_str("/prod/app1:/db/password"),
            "secret path must not start with '/'",
        );
    }

    #[test]
    fn secret_pattern_specificity_adds_components() {
        // from: SecretPattern::specificity_score()
        let p = SecretPattern::from_str("/prod/app1:db/password").unwrap();
        assert!(p.specificity_score() > 0);
        assert_eq!(
            p.specificity_score(),
            p.namespace
                .specificity_score()
                .saturating_add(p.secret.specificity_score())
        );
    }

    // =========================================================================================
    // NamespacePattern parsing
    // =========================================================================================

    #[test]
    fn namespace_parse_exact_multi_segment() {
        // from: NamespacePattern::from_str()
        let p = NamespacePattern::from_str("/prod/app1").unwrap();
        assert_eq!(p.kind, MatchKind::Exact);
        assert_eq!(p.base, "/prod/app1");
    }

    #[test]
    fn namespace_parse_prefix_last_segment_star_keeps_base_as_is() {
        // from: NamespacePattern::from_str()
        let p = NamespacePattern::from_str("/prod*").unwrap();
        assert_eq!(p.kind, MatchKind::PrefixOnly);

        // NOTE: your current code does NOT normalize away '*'
        assert_eq!(p.base, "/prod*");
    }

    #[test]
    fn namespace_parse_prefix_last_segment_star_with_path_keeps_base_as_is() {
        // from: NamespacePattern::from_str()
        let p = NamespacePattern::from_str("/prod/app*").unwrap();
        assert_eq!(p.kind, MatchKind::PrefixOnly);
        assert_eq!(p.base, "/prod/app*");
    }

    #[test]
    fn namespace_parse_subtree_keeps_base_as_is() {
        // from: NamespacePattern::from_str()
        let p = NamespacePattern::from_str("/prod/**").unwrap();
        assert_eq!(p.kind, MatchKind::Subtree);

        // NOTE: your current code does NOT normalize away '/**'
        assert_eq!(p.base, "/prod/**");
    }

    #[test]
    fn namespace_parse_reject_double_slash_empty_segment() {
        // from: NamespacePattern::from_str()
        assert_err_contains(NamespacePattern::from_str("/prod//app1"), "empty segments");
    }

    #[test]
    fn namespace_parse_reject_contains_colon() {
        // from: NamespacePattern::from_str()
        assert_err_contains(NamespacePattern::from_str("/prod:db"), "must not contain ':'");
    }

    #[test]
    fn namespace_parse_reject_star_in_middle_segment() {
        // from: NamespacePattern::from_str()
        assert_err_contains(
            NamespacePattern::from_str("/foo*/bar"),
            "only the last segment may end with '*'",
        );
    }

    #[test]
    fn namespace_parse_reject_multiple_star_segments() {
        // from: NamespacePattern::from_str()
        assert_err_contains(NamespacePattern::from_str("/foo*/bar*"), "only one segment may end with '*'");
    }

    #[test]
    fn namespace_parse_reject_star_not_trailing_in_segment() {
        // from: NamespacePattern::from_str()
        assert_err_contains(NamespacePattern::from_str("/fo*o"), "single trailing wildcard");
    }

    #[test]
    fn namespace_parse_allows_star_only_segment_current_behavior() {
        // from: NamespacePattern::from_str()
        // NOTE: Your current parser accepts "/*" (segment "*" ends with '*' and has no earlier '*').
        // If you *want* to reject it, add a rule in the parser and flip this test.
        let p = NamespacePattern::from_str("/*").unwrap();
        assert_eq!(p.kind, MatchKind::PrefixOnly);
        assert_eq!(p.base, "/*");
    }

    #[test]
    fn namespace_parse_reject_triple_star_segment() {
        // from: NamespacePattern::from_str()
        assert_err_contains(NamespacePattern::from_str("/prod/***"), "single trailing wildcard");
    }

    #[test]
    fn namespace_parse_star_allowed_only_before_subtree_when_ending_in_double_star() {
        // from: NamespacePattern::from_str()
        let p = NamespacePattern::from_str("/prod*/**").unwrap();
        // Current parser returns Subtree (not PrefixSubtree)
        assert_eq!(p.kind, MatchKind::Subtree);
        assert_eq!(p.base, "/prod*/**");
    }

    #[test]
    fn namespace_parse_reject_star_not_directly_before_subtree() {
        // from: NamespacePattern::from_str()
        assert_err_contains(
            NamespacePattern::from_str("/foo*/bar/**"),
            "when ending with '/**', only the segment directly before '**' may end with '*'",
        );
    }

    // =========================================================================================
    // NamespacePattern matching + scoring
    // =========================================================================================

    #[test]
    fn namespace_specificity_prefers_exact_over_wildcards() {
        // from: NamespacePattern::specificity_score()
        let exact = NamespacePattern::from_str("/prod/app1").unwrap();
        let subtree = NamespacePattern::from_str("/prod/**").unwrap();
        let prefix = NamespacePattern::from_str("/prod*").unwrap();

        assert!(exact.specificity_score() > subtree.specificity_score());
        assert!(exact.specificity_score() > prefix.specificity_score());
    }

    #[test]
    fn namespace_specificity_longer_is_more_specific_for_same_kind() {
        // from: NamespacePattern::specificity_score()
        let a = NamespacePattern::from_str("/prod/**").unwrap();
        let b = NamespacePattern::from_str("/prod/app1/**").unwrap();
        // both are Subtree kind; longer base should score higher (minus wildcard penalty)
        assert!(b.specificity_score() > a.specificity_score());
    }

    // =========================================================================================
    // AccountPattern — Subtree and PrefixSubtree arms (only reachable when constructed directly)
    // =========================================================================================

    #[test]
    fn account_matches_subtree_always_false() {
        // MatchKind::Subtree | PrefixSubtree branch returns false unconditionally
        let p = AccountPattern {
            base: "admin".to_string(),
            kind: MatchKind::Subtree,
        };
        assert!(!p.matches("admin"));
        assert!(!p.matches("anything"));
        assert!(!p.matches(""));
    }

    #[test]
    fn account_matches_prefix_subtree_always_false() {
        let p = AccountPattern {
            base: "admin".to_string(),
            kind: MatchKind::PrefixSubtree,
        };
        assert!(!p.matches("admin"));
        assert!(!p.matches("admin_extra"));
    }

    #[test]
    fn account_specificity_score_subtree() {
        let p = AccountPattern {
            base: "admin".to_string(),
            kind: MatchKind::Subtree,
        };
        // kind_weight=650, base_len=5, no wildcards -> 650+5=655
        assert_eq!(p.specificity_score(), 655);
    }

    #[test]
    fn account_specificity_score_prefix_subtree() {
        let p = AccountPattern {
            base: "admin".to_string(),
            kind: MatchKind::PrefixSubtree,
        };
        // kind_weight=500, base_len=5, no wildcards -> 500+5=505
        assert_eq!(p.specificity_score(), 505);
    }

    // =========================================================================================
    // SecretPattern — matches() when candidate has no colon (non-All pattern)
    // =========================================================================================

    #[test]
    fn secret_pattern_matches_returns_false_for_no_colon_candidate() {
        let p = SecretPattern::from_str("/prod/app1:db/password").unwrap();
        // candidate has no ':' -> splitn returns vec with len 1 -> false
        assert!(!p.matches("no-colon-here"));
        assert!(!p.matches("/prod"));
    }

    // =========================================================================================
    // NamespacePattern — PrefixSubtree matching and scoring (constructed directly)
    // =========================================================================================

    #[test]
    fn namespace_matches_prefix_subtree_uses_glob() {
        // PrefixSubtree dispatches to glob_match
        let p = NamespacePattern {
            base: "/prod*/**".to_string(),
            kind: MatchKind::PrefixSubtree,
        };
        assert!(p.matches("/production/app1"));
        assert!(p.matches("/prod/app1"));
        assert!(!p.matches("/staging/app1"));
    }

    #[test]
    fn namespace_specificity_prefix_subtree_less_than_subtree() {
        let subtree = NamespacePattern {
            base: "/prod".to_string(),
            kind: MatchKind::Subtree,
        };
        let prefix_subtree = NamespacePattern {
            base: "/prod".to_string(),
            kind: MatchKind::PrefixSubtree,
        };
        // PrefixSubtree has lower weight than Subtree
        assert!(prefix_subtree.specificity_score() < subtree.specificity_score());
        assert!(prefix_subtree.specificity_score() > 0);
    }
}
