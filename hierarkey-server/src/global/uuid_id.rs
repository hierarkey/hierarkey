// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

pub trait Identifier: Send + Sync {
    fn to_uuid(&self) -> String;
}

impl std::fmt::Debug for dyn Identifier + Send + Sync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identifier {{ uuid: {} }}", self.to_uuid())
    }
}

#[macro_export]
macro_rules! uuid_id {
    ($name:ident) => {
        $crate::uuid_id!($name, "");
    };
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(pub ::uuid::Uuid);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn new() -> Self {
                Self(::uuid::Uuid::now_v7())
            }
        }

        impl $crate::global::uuid_id::Identifier for $name {
            /// Returns the raw UUID string (no prefix)
            fn to_uuid(&self) -> String {
                self.0.to_string()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl TryFrom<&str> for $name {
            type Error = hierarkey_core::CkError;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                s.parse::<Self>()
            }
        }

        impl std::ops::Deref for $name {
            type Target = ::uuid::Uuid;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.to_uuid())
            }
        }

        impl std::str::FromStr for $name {
            type Err = hierarkey_core::CkError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let s = input.strip_prefix(Self::PREFIX).unwrap_or(input);

                if let Ok(u) = s.parse::<::ulid::Ulid>() {
                    let id: ::uuid::Uuid = u.into();
                    return Ok(Self(id));
                }

                let u = ::uuid::Uuid::parse_str(s).map_err(|_| {
                    hierarkey_core::error::validation::ValidationError::Field {
                        field: "id",
                        code: "invalid_format",
                        message: format!(
                            "ID must be a valid ULID string prefixed with '{}_' or a UUID string prefixed with '{}_'",
                            Self::PREFIX,
                            Self::PREFIX
                        )
                        .into(),
                    }
                })?;

                Ok(Self(u))
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&self.to_string())
                } else {
                    self.0.serialize(serializer)
                }
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                    s.parse::<Self>().map_err(::serde::de::Error::custom)
                } else {
                    let id = <::uuid::Uuid as ::serde::Deserialize>::deserialize(deserializer)?;
                    Ok(Self(id))
                }
            }
        }

        impl sqlx::Type<sqlx::Postgres> for $name {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                <uuid::Uuid as sqlx::Type<sqlx::Postgres>>::type_info()
            }

            fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
                <uuid::Uuid as sqlx::Type<sqlx::Postgres>>::compatible(ty)
            }
        }

        impl<'r> sqlx::Decode<'r, sqlx::Postgres> for $name {
            fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                let uuid = <uuid::Uuid as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
                Ok(Self(uuid))
            }
        }

        impl<'q> sqlx::Encode<'q, sqlx::Postgres> for $name {
            fn encode_by_ref(
                &self,
                buf: &mut sqlx::postgres::PgArgumentBuffer,
            ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
                <uuid::Uuid as sqlx::Encode<sqlx::Postgres>>::encode_by_ref(&self.0, buf)
            }
        }
    };
}
