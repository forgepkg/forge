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
//! on the canonical form (migration 0021), so no code path can create two
//! accounts that differ only in case, spacing or Unicode composition.
//!
//! A name that signs in with a password must also fit in an HTTP Basic
//! `user-id` ([`canonical_password_username`]), which cannot hold a `:`.
//!
//! A directory behind a credential-forwarding realm may fold more than this
//! canonical form does (LDAP's `caseIgnoreMatch` and Active Directory ignore
//! letter width, drop soft hyphens, ...). [`may_alias_upstream`] names the
//! forms such a directory could map onto another account; they are never
//! forwarded.

use unicode_normalization::UnicodeNormalization;

/// Longest accepted username, in bytes of its canonical form (the login
/// throttle keys on it, so it must stay bounded).
pub const MAX_USERNAME_BYTES: usize = 256;

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

/// Whether a canonical `name` may stand for another account in a directory
/// that folds compatibility characters: it changes under Unicode NFKC
/// (full-width or ligature letters, superscripts, ...) or contains a
/// default-ignorable code point (soft hyphen, zero-width characters, ...).
/// Forge would provision a separate account for it, so a deactivation of the
/// plain name would not hold.
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
    fn is_idempotent() {
        for raw in ["Alice", "ß", "İstanbul", "ΣΊΣΥΦΟΣ", "Ǆemal", "e\u{301}"] {
            let once = canonical_username(raw).unwrap();
            assert_eq!(canonical_username(&once).unwrap(), once, "{raw}");
        }
    }
}
