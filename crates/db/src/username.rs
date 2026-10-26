//! Canonical usernames.
//!
//! A username is an identity key: the login throttle, the validated-credential
//! cache, upstream credential forwarding, account provisioning and every
//! `app_user` lookup must agree on what "the same user" is. Otherwise
//! `Alice`, `alice` and `alice ` are three accounts (and three lockout budgets)
//! for what an upstream directory treats as one person.
//!
//! The canonical form is: surrounding whitespace trimmed, Unicode NFC, then
//! lowercased (and NFC again, since lowercasing can decompose). Empty names and
//! names containing control characters are refused. Every DAO that stores or
//! looks up a username canonicalizes it, and `app_user` carries a unique index
//! on the canonical form, so no code path can create two
//! accounts that differ only in case, spacing or Unicode composition.
//!
//! A name that signs in with a password must also fit in an HTTP Basic
//! `user-id` ([`canonical_password_username`]), which cannot hold a `:`.
//!
//! Every account is named by a UPN, `local-part@domain` ([`is_upn`],
//! [`canonical_account_username`]): the name says which organization the
//! account belongs to, two organizations' `alice` cannot collide, and it is
//! the name Entra and Active Directory sign the person in with. A
//! credential-forwarding realm forwards only the local part of the name to its
//! upstream ([`upn_local_part`]).
//!
//! A directory behind a credential-forwarding realm may fold more than this
//! canonical form does (LDAP's `caseIgnoreMatch` and Active Directory ignore
//! letter width, drop soft hyphens, ...). [`may_alias_upstream`] names the
//! forms such a directory could map onto another account; they are never
//! forwarded.
//!
//! Some canonical names are [reserved](RESERVED_USERNAMES) for protocol use:
//! no account is ever created or provisioned under one
//! ([`canonical_account_username`]), and no password login is attempted for
//! one.

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

/// Longest accepted username, in bytes of its canonical form (the login
/// throttle keys on it, so it must stay bounded).
pub const MAX_USERNAME_BYTES: usize = 256;

/// The HTTP Basic username a CI workload presents with its OIDC token or an
/// exchanged workload API key (trusted publishing). Basic `oidc:<secret>` is
/// only ever checked as a workload credential, never as an account login.
pub const WORKLOAD_USERNAME: &str = "oidc";

/// Canonical names Forge keeps for itself. No account may hold one, so a
/// name with a protocol meaning can never also sign in someone (or be
/// forwarded to an upstream directory as their login):
///
/// * [`WORKLOAD_USERNAME`] (`oidc`): the workload-identity Basic username.
pub const RESERVED_USERNAMES: &[&str] = &[WORKLOAD_USERNAME];

/// Whether the canonical `name` is one of the [`RESERVED_USERNAMES`].
pub fn is_reserved_username(name: &str) -> bool {
    RESERVED_USERNAMES.contains(&name)
}

/// Why a username was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidUsername {
    /// Empty (or whitespace only).
    #[error("username must not be empty")]
    Empty,
    /// Contains a control character (newline, NUL, escape, ...).
    #[error("username must not contain control characters")]
    ControlCharacter,
    /// Longer than [`MAX_USERNAME_BYTES`].
    #[error("username must be at most {MAX_USERNAME_BYTES} bytes")]
    TooLong,
    /// Contains a `:` where the name signs in with a password
    /// ([`canonical_password_username`]).
    #[error("username must not contain ':'")]
    Colon,
    /// One of the [`RESERVED_USERNAMES`], refused for a new account
    /// ([`canonical_account_username`]).
    #[error("username is reserved")]
    Reserved,
    /// Not a UPN ([`is_upn`]), refused for a new account
    /// ([`canonical_account_username`]).
    #[error("username must be a UPN such as alice@example.com")]
    NotUpn,
}

/// The canonical form of `raw` (see the [module docs](self)).
pub fn canonical_username(raw: &str) -> Result<String, InvalidUsername> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(InvalidUsername::Empty);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(InvalidUsername::ControlCharacter);
    }
    let lowered = trimmed.nfc().collect::<String>().to_lowercase();
    let canonical: String = lowered.nfc().collect();
    if canonical.len() > MAX_USERNAME_BYTES {
        return Err(InvalidUsername::TooLong);
    }
    Ok(canonical)
}

/// The canonical form of a username that signs in with a password: a local
/// account, or a login forwarded to a credential-forwarding realm.
///
/// Such a name must not contain `:`. HTTP Basic carries `user-id:password`
/// and splits it at the first colon (RFC 7617), so `mallory:abc` with the
/// password `def` reaches an upstream as `mallory` / `abc:def`: the upstream
/// would vouch for one account while Forge signs in another. Feed clients
/// cannot send such a name over Basic either. Federated names (OIDC claims)
/// and lookups of stored rows use [`canonical_username`].
pub fn canonical_password_username(raw: &str) -> Result<String, InvalidUsername> {
    let canonical = canonical_username(raw)?;
    if canonical.contains(':') {
        return Err(InvalidUsername::Colon);
    }
    Ok(canonical)
}

/// The canonical name for a **new** account: [`canonical_password_username`]
/// when the account signs in with a password (`with_password`: a local or a
/// credential-forwarding account), else [`canonical_username`]; either way a
/// [reserved](RESERVED_USERNAMES) name is refused, and the name must be a UPN
/// ([`is_upn`]). Lookups of existing rows keep using [`canonical_username`].
pub fn canonical_account_username(
    raw: &str,
    with_password: bool,
) -> Result<String, InvalidUsername> {
    let canonical = if with_password {
        canonical_password_username(raw)?
    } else {
        canonical_username(raw)?
    };
    if is_reserved_username(&canonical) {
        return Err(InvalidUsername::Reserved);
    }
    if !is_upn(&canonical) {
        return Err(InvalidUsername::NotUpn);
    }
    Ok(canonical)
}

/// The local part of a UPN (`alice` of `alice@example.com`): the name a
/// credential-forwarding realm sends its upstream. `None` for a name that is
/// not a UPN.
pub fn upn_local_part(name: &str) -> Option<&str> {
    is_upn(name)
        .then(|| name.split_once('@').map(|(local, _)| local))
        .flatten()
}

/// Longest DNS label of a UPN's domain, in characters.
const MAX_DOMAIN_LABEL_CHARS: usize = 63;

/// Whether the canonical `name` is a UPN, `local-part@domain`:
///
/// * exactly one `@`;
/// * a non-empty local part without whitespace;
/// * a domain that is a DNS name of at least two labels, without a trailing
///   dot. Each label is 1 to 63 characters of letters, digits and `-`, and
///   does not start or end with `-`; the last one is not all digits (so an
///   IPv4 address is not a domain).
///
/// A Unicode domain counts in its canonical form (NFC, lowercased, as
/// [`canonical_username`] leaves it), an `xn--` A-label as written.
pub fn is_upn(name: &str) -> bool {
    let mut parts = name.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if local.is_empty() || local.chars().any(char::is_whitespace) {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| is_domain_label(label))
        && !labels
            .last()
            .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()))
}

/// One label of a UPN's domain (see [`is_upn`]). A letter is any Unicode
/// letter, with the combining marks many scripts write theirs with.
fn is_domain_label(label: &str) -> bool {
    let len = label.chars().count();
    (1..=MAX_DOMAIN_LABEL_CHARS).contains(&len)
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .chars()
            .all(|c| c == '-' || c.is_alphanumeric() || is_combining_mark(c))
}

/// Whether a canonical `name` may stand for another account in a directory
/// that folds compatibility characters: it changes under Unicode NFKC
/// (full-width or ligature letters, superscripts, ...) or contains a
/// default-ignorable code point (soft hyphen, zero-width characters, ...).
/// The upstream would vouch for the plain name's account while Forge signs in
/// the one of this spelling, so a deactivation of the plain name would not
/// hold.
pub fn may_alias_upstream(name: &str) -> bool {
    name.chars().any(is_default_ignorable) || name.nfkc().ne(name.chars())
}

/// Unicode `Default_Ignorable_Code_Point` (DerivedCoreProperties.txt).
fn is_default_ignorable(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF0..=0xFFF8
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_a_folding_directory_could_alias_are_flagged() {
        for plain in [
            "mallory",
            "corp.mallory",
            "maria.müller",
            "ñandú",
            "user@corp.example",
        ] {
            let canonical = canonical_username(plain).unwrap();
            assert!(!may_alias_upstream(&canonical), "{plain:?}");
        }
        for alias in [
            "ｍａｌｌｏｒｙ",  // full-width letters
            "mal\u{00AD}lory", // soft hyphen
            "mal\u{200B}lory", // zero-width space
            "ﬁona",            // ligature
            "mallory²",        // superscript
        ] {
            let canonical = canonical_username(alias).unwrap();
            assert!(may_alias_upstream(&canonical), "{alias:?}");
        }
    }

    #[test]
    fn trims_lowercases_and_composes() {
        assert_eq!(canonical_username("  Alice ").unwrap(), "alice");
        assert_eq!(
            canonical_username("ALICE@Corp.Example").unwrap(),
            "alice@corp.example"
        );
        // "é" written as e + combining acute (NFD) equals the precomposed form.
        assert_eq!(
            canonical_username("Jos\u{0065}\u{0301}").unwrap(),
            canonical_username("jos\u{00e9}").unwrap()
        );
        assert_eq!(canonical_username("jos\u{00e9}").unwrap(), "jos\u{00e9}");
    }

    #[test]
    fn refuses_empty_control_and_oversized_names() {
        assert_eq!(canonical_username(""), Err(InvalidUsername::Empty));
        assert_eq!(canonical_username(" \t "), Err(InvalidUsername::Empty));
        assert_eq!(
            canonical_username("al\u{0}ice"),
            Err(InvalidUsername::ControlCharacter)
        );
        assert_eq!(
            canonical_username("alice\nadmin"),
            Err(InvalidUsername::ControlCharacter)
        );
        assert_eq!(
            canonical_username("al\u{1b}[31mice"),
            Err(InvalidUsername::ControlCharacter)
        );
        assert_eq!(
            canonical_username(&"a".repeat(MAX_USERNAME_BYTES + 1)),
            Err(InvalidUsername::TooLong)
        );
        assert!(canonical_username(&"a".repeat(MAX_USERNAME_BYTES)).is_ok());
    }

    #[test]
    fn password_usernames_refuse_a_colon() {
        assert_eq!(
            canonical_password_username(" Alice@Corp.Example ").unwrap(),
            "alice@corp.example"
        );
        for raw in ["mallory:abc", ":alice", "alice:", "a:b:c"] {
            assert_eq!(
                canonical_password_username(raw),
                Err(InvalidUsername::Colon),
                "{raw}"
            );
            // Federated names and stored rows keep their canonical form.
            assert!(canonical_username(raw).is_ok(), "{raw}");
        }
        // The other refusals still come first.
        assert_eq!(
            canonical_password_username(" "),
            Err(InvalidUsername::Empty)
        );
    }

    #[test]
    fn new_accounts_refuse_reserved_names_in_any_spelling() {
        for raw in ["oidc", "OIDC", " Oidc "] {
            for with_password in [true, false] {
                assert_eq!(
                    canonical_account_username(raw, with_password),
                    Err(InvalidUsername::Reserved),
                    "{raw:?}"
                );
            }
            // A lookup still canonicalizes it (logins refuse it elsewhere).
            assert_eq!(canonical_username(raw).unwrap(), WORKLOAD_USERNAME);
        }
        assert_eq!(
            canonical_account_username(" Alice@Example.COM ", true).unwrap(),
            "alice@example.com"
        );
        assert_eq!(
            canonical_account_username("oidc-2@example.com", false).unwrap(),
            "oidc-2@example.com"
        );
        // The password rules still apply first.
        assert_eq!(
            canonical_account_username("oidc:x", true),
            Err(InvalidUsername::Colon)
        );
    }

    #[test]
    fn new_accounts_need_a_upn() {
        for raw in ["alice", "admin", "corp\\alice", "alice@corp"] {
            for with_password in [true, false] {
                assert_eq!(
                    canonical_account_username(raw, with_password),
                    Err(InvalidUsername::NotUpn),
                    "{raw:?}"
                );
            }
            // A stored name is still looked up as it is.
            assert!(canonical_username(raw).is_ok(), "{raw:?}");
        }
        assert_eq!(
            InvalidUsername::NotUpn.to_string(),
            "username must be a UPN such as alice@example.com"
        );
    }

    #[test]
    fn upns_accept_subdomains_unicode_and_a_labels() {
        for raw in [
            "alice@example.com",
            "alice.smith@corp.example.com",
            "a@b.c",
            "first.last+ci@mail.example.org",
            "o'brien@example.ie",
            "x-1@a-b.example",
            // A Unicode domain in canonical form, and written decomposed
            // (canonicalization composes it).
            "jürgen@müller.example",
            "J\u{00FC}rgen@M\u{0075}\u{0308}ller.Example",
            "ñandú@bücher.example",
            "user@例え.テスト",
            "user@उदाहरण.परीक्षा",
            // An A-label as written.
            "jürgen@xn--mller-kva.example",
            "alice@xn--bcher-kva.xn--tckwe",
        ] {
            let canonical = canonical_username(raw).unwrap();
            assert!(is_upn(&canonical), "{raw:?} -> {canonical:?}");
            assert_eq!(canonical_account_username(raw, true).unwrap(), canonical);
        }
        let label = "a".repeat(MAX_DOMAIN_LABEL_CHARS);
        assert!(is_upn(&format!("alice@{label}.example")));
        let unicode_label = "ü".repeat(MAX_DOMAIN_LABEL_CHARS);
        assert!(is_upn(&format!("alice@{unicode_label}.example")));
    }

    #[test]
    fn upns_refuse_malformed_names() {
        let long_label = "a".repeat(MAX_DOMAIN_LABEL_CHARS + 1);
        for raw in [
            // No `@`, or two.
            "alice",
            "alice.example.com",
            "alice@corp@example.com",
            "@@example.com",
            // An empty local part or domain.
            "@example.com",
            "alice@",
            // Whitespace in the local part.
            "alice smith@example.com",
            "alice\u{00A0}smith@example.com",
            // A single-label domain.
            "alice@localhost",
            "alice@corp",
            // A trailing dot, or an empty label.
            "alice@example.com.",
            "alice@.example.com",
            "alice@example..com",
            // A leading or trailing hyphen.
            "alice@-corp.example",
            "alice@corp-.example",
            "alice@corp.-example",
            "alice@corp.example-",
            // A label over 63 characters.
            &format!("alice@{long_label}.example"),
            &format!("alice@corp.{long_label}"),
            // Characters a DNS label cannot hold.
            "alice@corp_1.example",
            "alice@corp example.com",
            "alice@[127.0.0.1]",
            "alice@exa*mple.com",
            // An IPv4 address is not a domain.
            "alice@127.0.0.1",
        ] {
            let canonical = canonical_username(raw).unwrap();
            assert!(!is_upn(&canonical), "{raw:?}");
            assert_eq!(
                canonical_account_username(raw, false),
                Err(InvalidUsername::NotUpn),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn the_local_part_is_what_forwarding_sends() {
        assert_eq!(upn_local_part("alice@example.com"), Some("alice"));
        assert_eq!(
            upn_local_part("first.last+ci@corp.example"),
            Some("first.last+ci")
        );
        for not_upn in ["alice", "alice@corp", "a@b@c.example"] {
            assert_eq!(upn_local_part(not_upn), None, "{not_upn}");
        }
    }

    #[test]
    fn is_idempotent() {
        for raw in ["Alice", "ß", "İstanbul", "ΣΊΣΥΦΟΣ", "Ǆemal", "e\u{301}"] {
            let once = canonical_username(raw).unwrap();
            assert_eq!(canonical_username(&once).unwrap(), once, "{raw}");
        }
    }
}
