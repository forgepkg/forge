//! What every feed response and package transfer shares, whatever the
//! format: the browser hardening of feed responses, byte ranges of
//! downloads, streaming a stored package, and the bounds on a multipart
//! upload's preamble.

use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use forge_core::repo::{NupkgLocation, RepoError};
use futures_util::{Stream, StreamExt};

/// `Content-Security-Policy` of every feed response: no subresources, no
/// script, and an opaque-origin sandbox, so even a document a browser renders
/// (e.g. a `.nuspec` opened as XML with an XHTML `<script>`) runs nothing and
/// cannot reach the admin origin's cookies or API.
pub const FEED_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; sandbox";

/// Make a feed response inert in a browser: a sandboxing CSP (always, over any
/// weaker policy), `Content-Disposition: attachment` (unless the response
/// named a file) and `X-Content-Type-Options: nosniff`.
///
/// Package clients ignore all three. The server applies this to every feed
/// response, including the ones it answers before a format sees the request
/// (unknown repository, 401/403).
pub fn harden_response_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(FEED_CONTENT_SECURITY_POLICY),
    );
    if !headers.contains_key(header::CONTENT_DISPOSITION) {
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment"),
        );
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

/// A package body streamed from the blob store chunk by chunk.
pub type BlobByteStream = std::pin::Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>;

/// Stream the bytes of a stored package blob — never buffered whole in
/// memory.
#[async_trait]
pub trait PackageBytes: Send + Sync {
    /// Open `range` of the blob at `loc` (all of it for `None`) as a byte
    /// stream. A range is only asked for when [`Self::serves_ranges`].
    async fn open(
        &self,
        loc: &NupkgLocation,
        range: Option<Range<u64>>,
    ) -> Result<BlobByteStream, RepoError>;

    /// Whether [`Self::open`] serves byte ranges, so downloads answer `Range`
    /// requests (`206`). Off by default: the server enables it with the
    /// local blob cache, which serves ranges from the cached file.
    fn serves_ranges(&self) -> bool {
        false
    }
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

/// A header value of ASCII digits and punctuation.
pub(crate) fn numeric_header(value: String) -> HeaderValue {
    HeaderValue::from_str(&value).expect("ASCII header value")
}

/// Stream the stored package at `location` as the answer to a download
/// with `request`'s headers (`head`: a `HEAD`, answered from the metadata
/// alone): its content type and length, and a single `Range` when the blob
/// source serves ranges (with the local blob cache).
pub async fn serve_package(
    state: &crate::state::AppState,
    location: &NupkgLocation,
    request: &HeaderMap,
    head: bool,
) -> Response {
    let size = u64::try_from(location.size).unwrap_or(0);
    let blobs = state.blob_bytes();
    let ranges = blobs.serves_ranges();
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&location.content_type) {
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
                numeric_header(format!("bytes {}-{}/{size}", range.start, range.end - 1)),
            );
            (StatusCode::PARTIAL_CONTENT, Some(range))
        }
        ByteRange::Unsatisfiable => {
            headers.insert(
                header::CONTENT_RANGE,
                numeric_header(format!("bytes */{size}")),
            );
            return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
        }
    };
    let length = range.as_ref().map_or(size, |r| r.end - r.start);
    headers.insert(header::CONTENT_LENGTH, numeric_header(length.to_string()));
    // A HEAD needs the headers only; don't open (or bill) a GET for it.
    if head {
        return (status, headers).into_response();
    }
    match blobs.open(location, range).await {
        Ok(stream) => (status, headers, Body::from_stream(stream)).into_response(),
        Err(e) => crate::plugins::repo_error(e),
    }
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

/// Most bytes a push body may carry before the headers of its first part are
/// complete (any preamble, the first boundary and the part headers). The
/// multipart parser buffers everything up to the first boundary in memory, so
/// without this bound one request could make it hold `max_upload_bytes`.
pub const MAX_MULTIPART_PREAMBLE_BYTES: usize = 64 * 1024;

/// The `boundary` parameter of a `multipart/form-data` content type.
pub fn multipart_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"').to_string())
            .filter(|b| !b.is_empty())
    })
}

/// Pass `body` through unchanged, but fail it (setting `overrun`) once
/// [`MAX_MULTIPART_PREAMBLE_BYTES`] have gone by without the first part's
/// headers being complete.
pub fn preamble_guard(
    body: impl Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
    boundary: &str,
    overrun: Arc<AtomicBool>,
) -> impl Stream<Item = Result<Bytes, axum::Error>> + Send + 'static {
    let delimiter = format!("--{boundary}").into_bytes();
    async_stream::try_stream! {
        let mut head: Option<Vec<u8>> = Some(Vec::new());
        let mut delimiter_at: Option<usize> = None;
        // How far `head` has been searched for what is still being looked
        // for. Each search resumes a needle's length before that, so a match
        // split across chunks is found and a body trickled in tiny chunks
        // costs linear, not quadratic, time.
        let mut searched = 0usize;
        futures_util::pin_mut!(body);
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            if let Some(seen) = head.as_mut() {
                // Only the first MAX + 1 bytes matter: the first part's
                // headers must end within them.
                let room = (MAX_MULTIPART_PREAMBLE_BYTES + 1).saturating_sub(seen.len());
                seen.extend_from_slice(&chunk[..chunk.len().min(room)]);
                if delimiter_at.is_none() {
                    let from = searched.saturating_sub(delimiter.len());
                    match find(&seen[from..], &delimiter) {
                        Some(i) => {
                            delimiter_at = Some(from + i);
                            searched = from + i;
                        }
                        None => searched = seen.len(),
                    }
                }
                let mut headers_end = None;
                if let Some(at) = delimiter_at {
                    let from = searched.saturating_sub(4).max(at);
                    match find(&seen[from..], b"\r\n\r\n") {
                        Some(i) => headers_end = Some(from + i + 4),
                        None => searched = seen.len(),
                    }
                }
                if headers_end.is_some_and(|end| end <= MAX_MULTIPART_PREAMBLE_BYTES) {
                    head = None;
                } else if seen.len() > MAX_MULTIPART_PREAMBLE_BYTES {
                    overrun.store(true, Ordering::Relaxed);
                    Err(axum::Error::new(std::io::Error::other(
                        "multipart preamble exceeds its limit",
                    )))?;
                }
            }
            yield chunk;
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
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
