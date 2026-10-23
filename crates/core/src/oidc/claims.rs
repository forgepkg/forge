//! Claim → `app_user` mapping and `is_admin` derivation (slice 12.2, §3.6).
//!
//! Pure functions over an already-verified [`IdTokenClaims`] set and a small
//! [`ClaimMapping`] config. No I/O — identity resolution / provisioning lives in
//! [`super::resolve_user`]; this module only decides *what the claims say*.
//!
//! ## Why a core-side config struct
//!
//! The server crate owns the full `OidcConfig` (TOML/env). To avoid a
//! `core → server` dependency inversion, the server maps the claim-relevant
//! fields into this [`ClaimMapping`] when it builds the [`super::OidcProvider`].
//! The mapping logic and its tests then live entirely in `core`.

use super::jwks::IdTokenClaims;

/// The claim-name + admin-mapping configuration the claim extractor needs.
///
/// Built by the server from its `OidcConfig`; kept here so claim mapping is a
/// pure, unit-testable `core` concern.
#[derive(Debug, Clone)]
pub struct ClaimMapping {
    /// Claim used as the `app_user.username` (fallback chain: this → `email`
    /// claim, only when `email_verified` is true → `sub`).
    pub username_claim: String,
    /// Claim carrying the user's email.
    pub email_claim: String,
    /// Claim carrying the user's display name.
    pub display_name_claim: String,
    /// Claim whose values are matched against [`Self::admin_groups`] (Entra:
    /// `roles` for app roles, `groups` for security groups).
    pub admin_claim: String,
    /// Values that grant `is_admin`. **Empty ⇒ OIDC never grants admin** (admins
    /// stay locally managed) — the safe default.
    pub admin_groups: Vec<String>,
    /// Allow-gate: every listed claim must carry (one of) its allowed values,
    /// or the login is refused — e.g. `tid` (Entra tenant), `hd` (Google
    /// Workspace domain) or `groups`. Empty ⇒ any token the issuer signs for
    /// this client may sign in.
    pub required_claims: std::collections::BTreeMap<String, Vec<String>>,
}

impl Default for ClaimMapping {
    fn default() -> Self {
        Self {
            username_claim: "preferred_username".into(),
            email_claim: "email".into(),
            display_name_claim: "name".into(),
            admin_claim: "roles".into(),
            admin_groups: Vec::new(),
            required_claims: Default::default(),
        }
    }
}

/// Whether the verified claims pass the realm's allow-gate
/// ([`ClaimMapping::required_claims`]): each required claim must be present
/// and carry one of its allowed values (a string claim, or any element of an
/// array claim). Booleans and numbers compare by their JSON text.
pub fn claims_allowed(claims: &IdTokenClaims, mapping: &ClaimMapping) -> bool {
    mapping.required_claims.iter().all(|(name, allowed)| {
        let value = match name.as_str() {
            "sub" => Some(serde_json::Value::String(claims.sub.clone())),
            "iss" => Some(serde_json::Value::String(claims.iss.clone())),
            _ => claims.additional.get(name).cloned(),
        };
        let text = |v: &serde_json::Value| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Some(v.to_string()),
            _ => None,
        };
        let present: Vec<String> = match value {
            Some(serde_json::Value::Array(items)) => items.iter().filter_map(text).collect(),
            Some(other) => text(&other).into_iter().collect(),
            None => Vec::new(),
        };
        present.iter().any(|p| allowed.iter().any(|a| a == p))
    })
}

/// The user-facing facts extracted from a verified ID token.
///
/// `username` is always present (the fallback chain guarantees it falls back to
/// the immutable `sub`). `email`/`display_name` are best-effort and stored
/// denormalized on `external_identity` for display only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedClaims {
    /// The resolved username (username claim → email claim when verified →
    /// `sub`).
    pub username: String,
    /// The claim [`Self::username`] came from: the realm's username claim,
    /// its email claim or `sub`. A new account must be named by a UPN, and a
    /// login whose username is none is refused with a message that names
    /// this claim.
    pub username_claim: String,
    /// Email, if the configured email claim was a non-empty string.
    pub email: Option<String>,
    /// Display name, if the configured display-name claim was a non-empty string.
    pub display_name: Option<String>,
    /// Whether the claims grant admin (admin-claim values ∩ `admin_groups` ≠ ∅).
    pub is_admin: bool,
    /// Whether the IdP is **authoritative** for admin (`admin_groups` is
    /// configured). Only then does a login grant *or revoke* admin; with an
    /// empty `admin_groups` admins stay locally managed and a login never
    /// touches the user's admin state.
    pub admin_managed: bool,
}

/// Extract the username/email/display-name and compute `is_admin` from a
/// verified ID token.
pub fn map_claims(claims: &IdTokenClaims, mapping: &ClaimMapping) -> MappedClaims {
    let email = string_claim(claims, &mapping.email_claim);
    // An unverified email is attacker-chosen at many IdPs: never let it become
    // the username (which can drive account linking) — neither as the
    // fallback nor when the username claim *is* the email claim (a common
    // `username_claim = "email"` setup); fall back to `sub`.
    // The username is stored canonical (trimmed, NFC, lowercased) like every
    // other account name; a claim with no canonical form falls through.
    let canonical = |raw: String| forge_db::username::canonical_username(&raw).ok();
    let username_is_email =
        mapping.username_claim == mapping.email_claim || mapping.username_claim == "email";
    let (username, username_claim) = string_claim(claims, &mapping.username_claim)
        .filter(|_| !username_is_email || email_verified(claims))
        .and_then(canonical)
        .map(|u| (u, mapping.username_claim.clone()))
        .or_else(|| {
            email
                .clone()
                .filter(|_| email_verified(claims))
                .and_then(canonical)
                .map(|u| (u, mapping.email_claim.clone()))
        })
        .or_else(|| canonical(claims.sub.clone()).map(|u| (u, "sub".to_string())))
        .unwrap_or_else(|| ("oidc-user".to_string(), "sub".to_string()));
    let display_name = string_claim(claims, &mapping.display_name_claim);
    let is_admin = derive_is_admin(claims, mapping);
    MappedClaims {
        username,
        username_claim,
        email,
        display_name,
        is_admin,
        admin_managed: !mapping.admin_groups.is_empty(),
    }
}

/// Whether the token asserts `email_verified` (a JSON `true`, or the string
/// `"true"` some IdPs emit). Absent ⇒ unverified.
fn email_verified(claims: &IdTokenClaims) -> bool {
    match claims.additional.get("email_verified") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Read a claim as a non-empty trimmed string, looking in both the registered
/// fields and the flattened `additional` map.
///
/// `sub`/`iss` are registered on [`IdTokenClaims`]; everything else
/// (`preferred_username`, `email`, `name`, …) lands in `additional`.
fn string_claim(claims: &IdTokenClaims, name: &str) -> Option<String> {
    match name {
        "sub" => non_empty(&claims.sub),
        "iss" => non_empty(&claims.iss),
        _ => claims
            .additional
            .get(name)
            .and_then(|v| v.as_str())
            .and_then(non_empty),
    }
}

/// `is_admin` is true iff any value of the configured `admin_claim` is present in
/// `admin_groups`. An empty `admin_groups` never grants admin (safe default).
///
/// The admin claim may be a single string or an array of strings (Entra emits
/// `roles`/`groups` as JSON arrays); both shapes are matched.
fn derive_is_admin(claims: &IdTokenClaims, mapping: &ClaimMapping) -> bool {
    if mapping.admin_groups.is_empty() {
        return false;
    }
    let Some(value) = claims.additional.get(&mapping.admin_claim) else {
        return false;
    };
    let present: Vec<&str> = match value {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(items) => items.iter().filter_map(|v| v.as_str()).collect(),
        _ => return false,
    };
    present
        .iter()
        .any(|v| mapping.admin_groups.iter().any(|g| g == v))
}

/// Trim and reject empty strings.
fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build an [`IdTokenClaims`] with `sub`/`iss` plus arbitrary additional
    /// claims from a JSON object.
    fn claims_with(sub: &str, extra: serde_json::Value) -> IdTokenClaims {
        let additional = extra.as_object().cloned().unwrap_or_default();
        IdTokenClaims {
            sub: sub.to_string(),
            iss: "https://issuer.example/v2.0".into(),
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            nonce: None,
            azp: None,
            additional,
        }
    }

    fn mapping() -> ClaimMapping {
        ClaimMapping {
            username_claim: "preferred_username".into(),
            email_claim: "email".into(),
            display_name_claim: "name".into(),
            admin_claim: "roles".into(),
            admin_groups: vec!["forge-admins".into()],
            required_claims: Default::default(),
        }
    }

    #[test]
    fn required_claims_gate_logins() {
        let mut m = mapping();
        let c = claims_with(
            "sub-1",
            json!({ "tid": "tenant-a", "groups": ["dev", "ops"], "email_verified": true }),
        );
        assert!(claims_allowed(&c, &m), "no gate configured");
        m.required_claims
            .insert("tid".into(), vec!["tenant-a".into()]);
        assert!(claims_allowed(&c, &m));
        m.required_claims
            .insert("groups".into(), vec!["ops".into()]);
        assert!(claims_allowed(&c, &m), "array claims match any element");
        m.required_claims
            .insert("email_verified".into(), vec!["true".into()]);
        assert!(claims_allowed(&c, &m), "booleans compare as text");
        m.required_claims
            .insert("tid".into(), vec!["tenant-b".into()]);
        assert!(
            !claims_allowed(&c, &m),
            "a guest from another tenant is refused"
        );
        let mut m = mapping();
        m.required_claims
            .insert("hd".into(), vec!["corp.example".into()]);
        assert!(!claims_allowed(&c, &m), "a missing claim is refused");
    }

    #[test]
    fn maps_primary_username_claim() {
        let c = claims_with(
            "sub-1",
            json!({ "preferred_username": "alice@corp", "email": "a@corp", "name": "Alice" }),
        );
        let m = map_claims(&c, &mapping());
        assert_eq!(m.username, "alice@corp");
        assert_eq!(m.email.as_deref(), Some("a@corp"));
        assert_eq!(m.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn username_falls_back_to_verified_email_then_sub() {
        // No preferred_username → verified email.
        let c = claims_with(
            "sub-1",
            json!({ "email": "bob@corp", "email_verified": true }),
        );
        assert_eq!(map_claims(&c, &mapping()).username, "bob@corp");

        // Neither username nor email → sub.
        let c = claims_with("sub-1", json!({ "name": "NoUserNoMail" }));
        assert_eq!(map_claims(&c, &mapping()).username, "sub-1");

        // Empty-string username is treated as absent and falls through.
        let c = claims_with(
            "sub-1",
            json!({ "preferred_username": "  ", "email": "c@corp", "email_verified": "true" }),
        );
        assert_eq!(map_claims(&c, &mapping()).username, "c@corp");
    }

    #[test]
    fn unverified_email_is_not_the_username_even_as_the_username_claim() {
        let mut m = mapping();
        m.username_claim = "email".into();
        let unverified = claims_with("sub-7", json!({ "email": "Boss@Corp" }));
        assert_eq!(map_claims(&unverified, &m).username, "sub-7");
        let verified = claims_with(
            "sub-7",
            json!({ "email": "Boss@Corp", "email_verified": true }),
        );
        assert_eq!(map_claims(&verified, &m).username, "boss@corp");
        // Same when a custom email claim doubles as the username claim.
        m.email_claim = "mail".into();
        m.username_claim = "mail".into();
        let unverified = claims_with("sub-8", json!({ "mail": "boss@corp" }));
        assert_eq!(map_claims(&unverified, &m).username, "sub-8");
    }

    #[test]
    fn unverified_email_never_becomes_the_username() {
        for extra in [
            json!({ "email": "admin@corp" }),
            json!({ "email": "admin@corp", "email_verified": false }),
            json!({ "email": "admin@corp", "email_verified": "no" }),
        ] {
            let m = map_claims(&claims_with("sub-9", extra), &mapping());
            assert_eq!(m.username, "sub-9", "falls back to the stable sub");
            // Still surfaced for display.
            assert_eq!(m.email.as_deref(), Some("admin@corp"));
        }
    }

    #[test]
    fn admin_managed_follows_admin_groups() {
        let c = claims_with("sub-1", json!({ "preferred_username": "a" }));
        assert!(map_claims(&c, &mapping()).admin_managed);
        let mut m = mapping();
        m.admin_groups.clear();
        assert!(!map_claims(&c, &m).admin_managed);
    }

    #[test]
    fn is_admin_true_when_role_array_intersects() {
        let c = claims_with(
            "sub-1",
            json!({ "preferred_username": "a", "roles": ["user", "forge-admins"] }),
        );
        assert!(map_claims(&c, &mapping()).is_admin);
    }

    #[test]
    fn is_admin_true_when_role_is_single_string() {
        let c = claims_with(
            "sub-1",
            json!({ "preferred_username": "a", "roles": "forge-admins" }),
        );
        assert!(map_claims(&c, &mapping()).is_admin);
    }

    #[test]
    fn is_admin_false_when_no_intersection() {
        let c = claims_with(
            "sub-1",
            json!({ "preferred_username": "a", "roles": ["user"] }),
        );
        assert!(!map_claims(&c, &mapping()).is_admin);
    }

    #[test]
    fn is_admin_false_when_admin_groups_empty() {
        // Even if the claim contains a value, an empty admin_groups never grants.
        let mut m = mapping();
        m.admin_groups.clear();
        let c = claims_with(
            "sub-1",
            json!({ "preferred_username": "a", "roles": ["forge-admins"] }),
        );
        assert!(!map_claims(&c, &m).is_admin);
    }

    #[test]
    fn is_admin_false_when_admin_claim_absent() {
        let c = claims_with("sub-1", json!({ "preferred_username": "a" }));
        assert!(!map_claims(&c, &mapping()).is_admin);
    }

    #[test]
    fn admin_claim_can_be_groups() {
        let mut m = mapping();
        m.admin_claim = "groups".into();
        m.admin_groups = vec!["grp-object-id-123".into()];
        let c = claims_with(
            "sub-1",
            json!({ "preferred_username": "a", "groups": ["other", "grp-object-id-123"] }),
        );
        assert!(map_claims(&c, &m).is_admin);
    }
}
