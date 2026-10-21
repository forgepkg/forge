//! Flat container (`PackageBaseAddress/3.0.0`), spec §6 + Appendix A.
//!
//! * `GET {base}/flat/{id}/index.json` → `{ "versions": [..] }` (normalized,
//!   lowercased, **including unlisted**; 404 if the id has no versions).
//! * `GET {base}/flat/{id}/{version}/{file}` → `.nupkg` bytes or `.nuspec` XML.
//!
//! Ids are lowercased and versions normalized via the repository [`Format`]
//! before lookup, so callers may use any casing / version spelling.
//!
//! When the blob source serves byte ranges ([`NupkgBytes::serves_ranges`]),
//! a `.nupkg` download answers a single-range `Range` request with `206`
//! (`416` when it lies past the end). Anything else — several ranges, an
//! unparsable header, an `If-Range` (no validators are served) — gets the
//! whole package, as RFC 9110 allows.
//!
//! [`NupkgBytes::serves_ranges`]: crate::routes::NupkgBytes::serves_ranges

use std::ops::Range;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::routes::{package_id, repo_error_response, RouteContext};

/// Handler: `GET`/`HEAD` `/flat/{id}/index.json`.
pub async fn versions(State(ctx): State<RouteContext>, Path(id): Path<String>) -> Response {
    let Some(lower) = package_id(&ctx, &id) else {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    };
    let versions = match ctx.ops.list_versions(&ctx.repo, &lower).await {
        Ok(v) => v,
        Err(e) => return repo_error_response(e),
    };
    if versions.is_empty() {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    }
    let body: Value = json!({
        "versions": versions.iter().map(|v| v.version.clone()).collect::<Vec<_>>(),
    });
    Json(body).into_response()
}

/// Handler: `GET`/`HEAD` `/flat/{id}/{version}/{filename}`.
///
/// Dispatches on the filename extension: `*.nupkg` streams the package blob,
/// `*.nuspec` serves the stored manifest. The id/version embedded in the
/// filename are not trusted; the `{id}`/`{version}` path segments drive lookup.
pub async fn content(
    State(ctx): State<RouteContext>,
    method: Method,
    headers: HeaderMap,
    Path((id, version, filename)): Path<(String, String, String)>,
) -> Response {
    let Some(lower) = package_id(&ctx, &id) else {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    };
    let Some(norm_ver) = super::package_version(&ctx, &version) else {
        return (StatusCode::NOT_FOUND, "invalid version").into_response();
    };

    let lower_file = filename.to_ascii_lowercase();
    if lower_file.ends_with(".nupkg") {
        serve_nupkg(&ctx, &lower, &norm_ver, method == Method::HEAD, &headers).await
    } else if lower_file.ends_with(".nuspec") {
        serve_nuspec(&ctx, &lower, &norm_ver).await
    } else {
        (StatusCode::NOT_FOUND, "unknown content").into_response()
    }
}

async fn serve_nupkg(
    ctx: &RouteContext,
    id: &str,
    version: &str,
    head: bool,
    request: &HeaderMap,
) -> Response {
    // A HEAD (a probe, a mirror tool) is not a download.
    let resolved = if head {
        ctx.ops.resolve_nupkg_head(&ctx.repo, id, version).await
    } else {
        ctx.ops.resolve_nupkg(&ctx.repo, id, version).await
    };
    let loc = match resolved {
        Ok(Some(l)) => l,
        Ok(None) => return (StatusCode::NOT_FOUND, "package not found").into_response(),
        Err(e) => return repo_error_response(e),
    };
    let size = u64::try_from(loc.size).unwrap_or(0);
    let ranges = ctx.nupkg.serves_ranges();
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&loc.content_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    if ranges {
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    }
    let requested = if ranges && !head {
        byte_range(request, size)
    } else {
        ByteRange::Full
    };
    let (status, range) = match requested {
        ByteRange::Full => (StatusCode::OK, None),
        ByteRange::Partial(range) => {
            headers.insert(
                header::CONTENT_RANGE,
                header_value(format!("bytes {}-{}/{size}", range.start, range.end - 1)),
            );
            (StatusCode::PARTIAL_CONTENT, Some(range))
        }
        ByteRange::Unsatisfiable => {
            headers.insert(
                header::CONTENT_RANGE,
                header_value(format!("bytes */{size}")),
            );
            return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
        }
    };
    let length = range.as_ref().map_or(size, |r| r.end - r.start);
    headers.insert(header::CONTENT_LENGTH, header_value(length.to_string()));
    // A HEAD only needs the headers; don't open (or bill) an S3 GET for it.
    if head {
        return (status, headers).into_response();
    }
    let stream = match ctx.nupkg.open(&loc, range).await {
        Ok(s) => s,
        Err(e) => return repo_error_response(e),
    };
    (status, headers, Body::from_stream(stream)).into_response()
}

/// A header value built from ASCII digits and punctuation.
fn header_value(value: String) -> HeaderValue {
    HeaderValue::from_str(&value).expect("ASCII header value")
}

/// What a request's `Range` header asks of a body of some size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ByteRange {
    /// No (usable) range: the whole body, `200`.
    Full,
    /// One satisfiable range, `206`.
    Partial(Range<u64>),
    /// A range starting past the end, `416`.
    Unsatisfiable,
}

/// The [`ByteRange`] a request asks of a `size`-byte body. Only one
/// `bytes` range is honored; anything else is answered in full.
pub fn byte_range(request: &HeaderMap, size: u64) -> ByteRange {
    // `If-Range` needs a validator to compare with, and none is served.
    if request.contains_key(header::IF_RANGE) {
        return ByteRange::Full;
    }
    let mut values = request.get_all(header::RANGE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return ByteRange::Full;
    };
    let Some((unit, spec)) = value.to_str().ok().and_then(|v| v.split_once('=')) else {
        return ByteRange::Full;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") || spec.contains(',') {
        return ByteRange::Full;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return ByteRange::Full;
    };
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            // All digits: only too many of them fail to parse.
            .then(|| s.parse::<u64>().unwrap_or(u64::MAX))
    };
    let (first, last) = (first.trim(), last.trim());
    if first.is_empty() {
        // `-N`: the last N bytes.
        return match number(last) {
            None => ByteRange::Full,
            Some(0) => ByteRange::Unsatisfiable,
            Some(_) if size == 0 => ByteRange::Unsatisfiable,
            Some(n) => ByteRange::Partial(size.saturating_sub(n)..size),
        };
    }
    let Some(start) = number(first) else {
        return ByteRange::Full;
    };
    let end = if last.is_empty() {
        size
    } else {
        match number(last) {
            Some(last) if last >= start => last.saturating_add(1).min(size),
            _ => return ByteRange::Full,
        }
    };
    if start >= size {
        return ByteRange::Unsatisfiable;
    }
    ByteRange::Partial(start..end)
}

async fn serve_nuspec(ctx: &RouteContext, id: &str, version: &str) -> Response {
    let bytes = match ctx.ops.resolve_nuspec(&ctx.repo, id, version).await {
        Ok(Some(b)) => b,
        Ok(None) => return (StatusCode::NOT_FOUND, "nuspec not found").into_response(),
        Err(e) => return repo_error_response(e),
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/xml".to_string()),
            (header::CONTENT_LENGTH, bytes.len().to_string()),
        ],
        Body::from(bytes),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(value: &str, size: u64) -> ByteRange {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_str(value).unwrap());
        byte_range(&headers, size)
    }

    #[test]
    fn single_ranges_are_honored() {
        assert_eq!(range("bytes=0-99", 1000), ByteRange::Partial(0..100));
        assert_eq!(range("bytes=990-", 1000), ByteRange::Partial(990..1000));
        assert_eq!(range("bytes=-10", 1000), ByteRange::Partial(990..1000));
        assert_eq!(range("Bytes = 5-5", 1000), ByteRange::Partial(5..6));
        // Past the end is clamped; a suffix longer than the body is all of it.
        assert_eq!(range("bytes=900-5000", 1000), ByteRange::Partial(900..1000));
        assert_eq!(range("bytes=-5000", 1000), ByteRange::Partial(0..1000));
        assert_eq!(
            range("bytes=0-99999999999999999999999", 10),
            ByteRange::Partial(0..10)
        );
    }

    #[test]
    fn a_range_past_the_end_is_unsatisfiable() {
        assert_eq!(range("bytes=1000-", 1000), ByteRange::Unsatisfiable);
        assert_eq!(range("bytes=1000-1001", 1000), ByteRange::Unsatisfiable);
        assert_eq!(range("bytes=-0", 1000), ByteRange::Unsatisfiable);
        assert_eq!(range("bytes=0-", 0), ByteRange::Unsatisfiable);
    }

    #[test]
    fn anything_else_gets_the_whole_body() {
        for value in [
            "bytes=0-1,5-6",
            "items=0-1",
            "bytes=5-1",
            "bytes=a-b",
            "bytes=0x1-2",
            "bytes=",
            "bytes=-",
            "0-1",
        ] {
            assert_eq!(range(value, 1000), ByteRange::Full, "{value}");
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1"));
        headers.insert(header::IF_RANGE, HeaderValue::from_static("\"x\""));
        assert_eq!(byte_range(&headers, 1000), ByteRange::Full);
        assert_eq!(byte_range(&HeaderMap::new(), 1000), ByteRange::Full);
    }
}
