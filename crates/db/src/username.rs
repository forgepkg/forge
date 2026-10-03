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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn is_idempotent() {
        for raw in ["Alice", "ß", "İstanbul", "ΣΊΣΥΦΟΣ", "Ǆemal", "e\u{301}"] {
            let once = canonical_username(raw).unwrap();
            assert_eq!(canonical_username(&once).unwrap(), once, "{raw}");
        }
    }
}
