//! Authorization seam (Slice 1: deliberately coarse, spec §5).
//!
//! These three async predicates are the **single extension point** a later
//! slice (§12.4 RBAC) will replace. Keep the signatures stable:
//! `async fn can_*(&Principal, &Repository) -> bool`. They are `async` today
//! even though Slice-1 logic is synchronous, so a future per-user policy can do
//! DB lookups without a breaking change.
//!
//! ## Slice-1 rules
//! * **read**  — any authenticated `User`, **or** an `Anonymous` caller when
//!   `repository.anonymous_read` is set.
//! * **write** (push / delete / relist) — any authenticated `User`. Never
//!   anonymous.
//! * **admin** — a `User` with `is_admin`.

use forge_db::model::Repository;

use super::principal::Principal;

/// May `principal` read (download / list / search) `repo`?
pub async fn can_read(principal: &Principal, repo: &Repository) -> bool {
    match principal {
        Principal::User { .. } => true,
        Principal::Anonymous { .. } => repo.anonymous_read,
        Principal::Unauthenticated => false,
    }
}

/// May `principal` write (push / delete / relist) to `repo`?
///
/// Writing always requires an authenticated user; anonymous callers can never
/// write, regardless of `anonymous_read`.
pub async fn can_write(principal: &Principal, _repo: &Repository) -> bool {
    matches!(principal, Principal::User { .. })
}

/// May `principal` perform admin operations on `repo`?
///
/// Requires an authenticated user with the admin flag.
pub async fn can_admin(principal: &Principal, _repo: &Repository) -> bool {
    matches!(principal, Principal::User { is_admin: true, .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    /// Build a minimal [`Repository`] with the given `anonymous_read` flag.
    fn repo(anonymous_read: bool) -> Repository {
        Repository {
            id: 1,
            name: "nuget-hosted".into(),
            format: "nuget".into(),
            kind: "hosted".into(),
            anonymous_read,
            online: true,
            config: json!({}),
            remote_url: None,
            package_delay_seconds: 0,
            upstream_username: None,
            upstream_password: None,
            allow_private_upstream: false,
            metadata_ttl_seconds: None,
            not_found_ttl_seconds: None,
            allow_redeploy: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn user(is_admin: bool) -> Principal {
        Principal::User {
            user_id: 42,
            token_id: Some(7),
            is_admin,
        }
    }

    fn anon() -> Principal {
        Principal::Anonymous {
            ip: "127.0.0.1".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn authz_matrix() {
        // (principal, anonymous_read, can_read, can_write, can_admin)
        let cases: &[(&str, Principal, bool, bool, bool, bool)] = &[
            (
                "admin user, anon_read off",
                user(true),
                false,
                true,
                true,
                true,
            ),
            (
                "admin user, anon_read on",
                user(true),
                true,
                true,
                true,
                true,
            ),
            (
                "plain user, anon_read off",
                user(false),
                false,
                true,
                true,
                false,
            ),
            (
                "plain user, anon_read on",
                user(false),
                true,
                true,
                true,
                false,
            ),
            ("anon, anon_read on", anon(), true, true, false, false),
            ("anon, anon_read off", anon(), false, false, false, false),
            (
                "unauthenticated, anon_read on",
                Principal::Unauthenticated,
                true,
                false,
                false,
                false,
            ),
            (
                "unauthenticated, anon_read off",
                Principal::Unauthenticated,
                false,
                false,
                false,
                false,
            ),
        ];

        for (label, p, anon_read, want_read, want_write, want_admin) in cases {
            let r = repo(*anon_read);
            assert_eq!(can_read(p, &r).await, *want_read, "read: {label}");
            assert_eq!(can_write(p, &r).await, *want_write, "write: {label}");
            assert_eq!(can_admin(p, &r).await, *want_admin, "admin: {label}");
        }
    }
}
