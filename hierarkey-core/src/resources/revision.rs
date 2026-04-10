// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use crate::error::validation::ValidationError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, Postgres, Type};

/// Represents a revision of a key. Can be a specific number, or special sentinels like "active" or "latest".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Revision {
    Active,
    Latest,
    Number(u32),
}

impl Serialize for Revision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Revision::Active => serializer.serialize_str("active"),
            Revision::Latest => serializer.serialize_str("latest"),
            Revision::Number(n) => serializer.serialize_u32(*n),
        }
    }
}

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct RevisionVisitor;

        impl<'de> Visitor<'de> for RevisionVisitor {
            type Value = Revision;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(r#"a positive integer, "active", or "latest""#)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value <= 0 {
                    return Err(E::custom("revision must be >= 1"));
                }
                self.visit_u64(value as u64)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == 0 {
                    return Err(E::custom("revision must be >= 1"));
                }
                if value > u32::MAX as u64 {
                    return Err(E::custom("revision too large"));
                }
                Ok(Revision::Number(value as u32))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.eq_ignore_ascii_case("active") {
                    Ok(Revision::Active)
                } else if value.eq_ignore_ascii_case("latest") {
                    Ok(Revision::Latest)
                } else {
                    // Try parsing as number
                    value
                        .parse::<u32>()
                        .map_err(|_| E::custom(format!("invalid revision: {value}")))
                        .and_then(|n| {
                            if n == 0 {
                                Err(E::custom("revision must be >= 1"))
                            } else {
                                Ok(Revision::Number(n))
                            }
                        })
                }
            }
        }

        deserializer.deserialize_any(RevisionVisitor)
    }
}

impl Revision {
    pub fn as_number(&self) -> Option<u32> {
        match self {
            Revision::Number(n) => Some(*n),
            _ => None,
        }
    }
}

impl Default for Revision {
    fn default() -> Self {
        Revision::Number(1)
    }
}

impl TryFrom<&str> for Revision {
    type Error = crate::CkError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let s = s.trim();

        // Allow "latest" and "active" as special revision strings (case-insensitive)
        if s.eq_ignore_ascii_case("latest") {
            return Ok(Revision::Latest);
        }
        if s.eq_ignore_ascii_case("active") {
            return Ok(Revision::Active);
        }

        let rev: u32 = s.parse().map_err(|_| ValidationError::Field {
            field: "revision",
            code: "invalid_rev",
            message: format!("Invalid revision string: {s}").into(),
        })?;

        // Reserve top 100 values for sentinels/flags.
        const RESERVED: u32 = 100;
        let max_user_rev = u32::MAX - RESERVED;

        if rev == 0 {
            return Err(ValidationError::Field {
                field: "revision",
                code: "invalid_rev",
                message: "Revision must be >= 1".into(),
            }
            .into());
        }

        if rev > max_user_rev {
            return Err(ValidationError::Field {
                field: "revision",
                code: "invalid_rev",
                message: format!("Revision too large; max allowed is {max_user_rev}").into(),
            }
            .into());
        }

        Ok(Revision::Number(rev))
    }
}

impl From<u32> for Revision {
    fn from(value: u32) -> Self {
        Revision::Number(value)
    }
}

impl std::fmt::Display for Revision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Revision::Active => f.pad("active"),
            Revision::Latest => f.pad("latest"),
            Revision::Number(n) => {
                let s = n.to_string();
                f.pad(&s)
            }
        }
    }
}

impl Type<Postgres> for Revision {
    fn type_info() -> PgTypeInfo {
        <i32 as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <i32 as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for Revision {
    fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let rev = <i32 as Decode<Postgres>>::decode(value)?;
        Ok(Revision::Number(rev as u32))
    }
}

impl<'q> Encode<'q, Postgres> for Revision {
    fn encode_by_ref(
        &self,
        buf: &mut PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let n = match self {
            Revision::Active => return Err("Cannot encode 'Active' revision to database".into()),
            Revision::Latest => return Err("Cannot encode 'Latest' revision to database".into()),
            Revision::Number(n) => *n as i32,
        };
        <i32 as Encode<Postgres>>::encode_by_ref(&n, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_number_1() {
        assert_eq!(Revision::default(), Revision::Number(1));
    }

    #[test]
    fn from_u32() {
        assert_eq!(Revision::from(5u32), Revision::Number(5));
    }

    #[test]
    fn as_number_for_number_variant() {
        assert_eq!(Revision::Number(7).as_number(), Some(7));
    }

    #[test]
    fn as_number_for_sentinels_is_none() {
        assert_eq!(Revision::Active.as_number(), None);
        assert_eq!(Revision::Latest.as_number(), None);
    }

    #[test]
    fn display_active() {
        assert_eq!(Revision::Active.to_string(), "active");
    }

    #[test]
    fn display_latest() {
        assert_eq!(Revision::Latest.to_string(), "latest");
    }

    #[test]
    fn display_number() {
        assert_eq!(Revision::Number(42).to_string(), "42");
    }

    #[test]
    fn try_from_str_active_case_insensitive() {
        assert_eq!(Revision::try_from("active").unwrap(), Revision::Active);
        assert_eq!(Revision::try_from("ACTIVE").unwrap(), Revision::Active);
        assert_eq!(Revision::try_from("Active").unwrap(), Revision::Active);
    }

    #[test]
    fn try_from_str_latest_case_insensitive() {
        assert_eq!(Revision::try_from("latest").unwrap(), Revision::Latest);
        assert_eq!(Revision::try_from("LATEST").unwrap(), Revision::Latest);
    }

    #[test]
    fn try_from_str_number() {
        assert_eq!(Revision::try_from("5").unwrap(), Revision::Number(5));
        assert_eq!(Revision::try_from("  3  ").unwrap(), Revision::Number(3));
    }

    #[test]
    fn try_from_str_zero_is_error() {
        assert!(Revision::try_from("0").is_err());
    }

    #[test]
    fn try_from_str_too_large_is_error() {
        let too_large = (u32::MAX - 99).to_string();
        assert!(Revision::try_from(too_large.as_str()).is_err());
    }

    #[test]
    fn try_from_str_invalid_is_error() {
        assert!(Revision::try_from("abc").is_err());
        assert!(Revision::try_from("").is_err());
        assert!(Revision::try_from("-1").is_err());
    }

    #[test]
    fn serialize_active() {
        let json = serde_json::to_string(&Revision::Active).unwrap();
        assert_eq!(json, r#""active""#);
    }

    #[test]
    fn serialize_latest() {
        let json = serde_json::to_string(&Revision::Latest).unwrap();
        assert_eq!(json, r#""latest""#);
    }

    #[test]
    fn serialize_number() {
        let json = serde_json::to_string(&Revision::Number(3)).unwrap();
        assert_eq!(json, "3");
    }

    #[test]
    fn deserialize_string_active() {
        let rev: Revision = serde_json::from_str(r#""active""#).unwrap();
        assert_eq!(rev, Revision::Active);
    }

    #[test]
    fn deserialize_string_latest() {
        let rev: Revision = serde_json::from_str(r#""latest""#).unwrap();
        assert_eq!(rev, Revision::Latest);
    }

    #[test]
    fn deserialize_integer() {
        let rev: Revision = serde_json::from_str("5").unwrap();
        assert_eq!(rev, Revision::Number(5));
    }

    #[test]
    fn deserialize_string_number() {
        let rev: Revision = serde_json::from_str(r#""7""#).unwrap();
        assert_eq!(rev, Revision::Number(7));
    }

    #[test]
    fn deserialize_zero_integer_is_error() {
        assert!(serde_json::from_str::<Revision>("0").is_err());
    }

    #[test]
    fn deserialize_zero_string_is_error() {
        assert!(serde_json::from_str::<Revision>(r#""0""#).is_err());
    }

    #[test]
    fn deserialize_invalid_string_is_error() {
        assert!(serde_json::from_str::<Revision>(r#""bogus""#).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        for rev in [
            Revision::Active,
            Revision::Latest,
            Revision::Number(1),
            Revision::Number(999),
        ] {
            let json = serde_json::to_string(&rev).unwrap();
            let restored: Revision = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, rev);
        }
    }

    #[test]
    fn ordering() {
        assert!(Revision::Active < Revision::Latest);
        assert!(Revision::Latest < Revision::Number(1));
        assert!(Revision::Number(1) < Revision::Number(2));
    }

    #[test]
    fn deserialize_negative_integer_is_error() {
        // Triggers visit_i64 with negative value
        assert!(serde_json::from_str::<Revision>("-1").is_err());
        assert!(serde_json::from_str::<Revision>("-100").is_err());
    }

    #[test]
    fn deserialize_positive_i64_as_number() {
        // Triggers visit_i64 with positive value
        let rev: Revision = serde_json::from_str("3").unwrap();
        assert_eq!(rev, Revision::Number(3));
    }

    #[test]
    fn deserialize_too_large_u64_is_error() {
        // Triggers value > u32::MAX as u64 branch in visit_u64
        let too_large: u64 = u32::MAX as u64 + 1;
        let json = too_large.to_string();
        assert!(serde_json::from_str::<Revision>(&json).is_err());
    }

    #[test]
    fn deserialize_unexpected_type_is_error() {
        // Triggers the `expecting` message path via wrong type
        assert!(serde_json::from_str::<Revision>("true").is_err());
        assert!(serde_json::from_str::<Revision>("null").is_err());
        assert!(serde_json::from_str::<Revision>("[]").is_err());
    }

    #[test]
    fn deserialize_string_active_case_variants() {
        let rev: Revision = serde_json::from_str(r#""ACTIVE""#).unwrap();
        assert_eq!(rev, Revision::Active);
        let rev: Revision = serde_json::from_str(r#""LATEST""#).unwrap();
        assert_eq!(rev, Revision::Latest);
    }
}
