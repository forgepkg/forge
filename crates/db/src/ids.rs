//! Strongly-typed identifier newtypes.
//!
//! ## Design decision
//!
//! The DAO layer uses sqlx **compile-time-checked** macros (`query_as!`,
//! `query!`). Those macros infer Rust types directly from the Postgres column
//! types: a `bigint` PK becomes `i64`. Mapping every id column onto a newtype
//! would require either `#[sqlx(try_from = "i64")]` overrides on every struct
//! field or `as` casts on every bind parameter, which fights the macros for no
//! real safety win inside the DB crate.
//!
//! So the rule is:
//!   * [`crate::model`] structs and DAO signatures use plain `i64` for ids.
//!   * These newtypes exist for the *core / service* layer to wrap ids at API
//!     boundaries where mixing up a `RepositoryId` and a `ComponentId` would be
//!     a real bug. They convert to/from `i64` cheaply.
//!
//! Each newtype is `#[sqlx(transparent)]` so it can still be used directly with
//! the runtime-checked query API (`sqlx::query_as::<_, T>`) if a caller prefers
//! that, and so it round-trips through `Encode`/`Decode` as a bare `i64`.

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, sqlx::Type,
        )]
        #[sqlx(transparent)]
        pub struct $name(pub i64);

        impl From<i64> for $name {
            fn from(v: i64) -> Self {
                Self(v)
            }
        }

        impl From<$name> for i64 {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

id_newtype!(
    /// Primary key of a `repository` row.
    RepositoryId
);
id_newtype!(
    /// Primary key of a `component` row.
    ComponentId
);
id_newtype!(
    /// Primary key of an `asset` row.
    AssetId
);
id_newtype!(
    /// Primary key of an `app_user` row.
    UserId
);
id_newtype!(
    /// Primary key of a `token` row.
    TokenId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_i64() {
        let id = RepositoryId::from(42);
        assert_eq!(id.0, 42);
        assert_eq!(i64::from(id), 42);
        assert_eq!(id.to_string(), "42");
    }

    #[test]
    fn ids_are_distinct_types() {
        // This is a compile-time guarantee; the assertion is just a smoke test.
        let r = RepositoryId::from(1);
        let c = ComponentId::from(1);
        assert_eq!(r.0, c.0);
    }
}
