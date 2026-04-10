// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

/// Utility functionsfor SQL string escaping for search wildcards
pub fn escape_ilike(term: &str) -> String {
    term.replace('\\', r"\\").replace('%', r"\%").replace('_', r"\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_ilike() {
        let input = r"100%_sure\about_this";
        let expected = r"100\%\_sure\\about\_this";
        let escaped = escape_ilike(input);
        assert_eq!(escaped, expected);
    }

    #[test]
    fn test_escape_ilike_no_special_chars() {
        let input = "justastring";
        let expected = "justastring";
        let escaped = escape_ilike(input);
        assert_eq!(escaped, expected);
    }
}
