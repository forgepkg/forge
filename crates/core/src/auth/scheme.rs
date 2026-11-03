//! Reading the scheme of an `Authorization` header.
//!
//! An authentication scheme is a case-insensitive token (RFC 9110 §11.1):
//! `Basic`, `basic` and `BASIC` name the same scheme. Every reader of the
//! request's own credentials goes through [`credentials`], so none of them
//! takes a credential in another case for no credential at all (#584) —
//! behind a trusted-header realm's proxy the headers would then name the
//! caller instead of the request's own credential being checked.

use http::HeaderMap;

/// The credentials of an `Authorization` value of `scheme`, trimmed: the
/// text after the scheme and the space that ends it, when the value's scheme
/// is `scheme` in any case. `None` for another scheme, or a scheme alone.
/// The credentials may be empty (`Basic  `); the caller decides what that is.
pub fn credentials<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let (name, rest) = value.split_once(' ')?;
    name.eq_ignore_ascii_case(scheme).then(|| rest.trim())
}

/// The non-empty credentials of the request's `Authorization` header when
/// its scheme is `scheme` in any case ([`credentials`]).
pub fn header_credentials<'a>(headers: &'a HeaderMap, scheme: &str) -> Option<&'a str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    credentials(value, scheme).filter(|c| !c.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_is_read_in_any_case() {
        for value in [
            "Basic abc",
            "basic abc",
            "BASIC abc",
            "bAsIc abc",
            "Basic  abc ",
        ] {
            assert_eq!(credentials(value, "Basic"), Some("abc"), "{value}");
        }
        for value in ["Bearer t", "bearer t", "BEARER t", "bEaReR t"] {
            assert_eq!(credentials(value, "Bearer"), Some("t"), "{value}");
        }
    }

    #[test]
    fn another_scheme_or_a_scheme_alone_is_none() {
        assert_eq!(credentials("Bearer abc", "Basic"), None);
        assert_eq!(credentials("Basicabc", "Basic"), None);
        assert_eq!(credentials("Basic", "Basic"), None);
        assert_eq!(credentials("Basic ", "Basic"), Some(""));
    }

    #[test]
    fn header_credentials_are_never_empty() {
        let mut headers = HeaderMap::new();
        assert_eq!(header_credentials(&headers, "Bearer"), None);
        headers.insert(http::header::AUTHORIZATION, "BEARER tok".parse().unwrap());
        assert_eq!(header_credentials(&headers, "bearer"), Some("tok"));
        assert_eq!(header_credentials(&headers, "Basic"), None);
        headers.insert(http::header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(header_credentials(&headers, "Bearer"), None);
    }
}
