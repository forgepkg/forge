//! Serving a stored file (the `serve-file` action): its bytes (whole or one
//! range), its validators and conditional requests, its content type and
//! the repository's content disposition.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use forge_db::model::Repository;
use forge_db::raw_dao::{self, RawFile};
use forge_plugin::api::files;
use forge_storage::BlobRef;

use crate::feed::{byte_range, ByteRange};
use crate::state::AppState;

/// The `ETag` of a file: its SHA-256, a strong validator.
pub fn etag(file: &RawFile) -> String {
    format!("\"{}\"", file.blob_sha256)
}

/// `t` as an HTTP date (IMF-fixdate, whole seconds).
pub fn http_date(t: DateTime<Utc>) -> String {
    httpdate::fmt_http_date(system_time(t))
}

fn system_time(t: DateTime<Utc>) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(t.timestamp()).unwrap_or(0))
}

/// Whether the request's preconditions say the client's copy is current
/// (`If-None-Match`, else `If-Modified-Since`): answer 304.
fn not_modified(request: &HeaderMap, etag: &str, modified: DateTime<Utc>) -> bool {
    if let Some(value) = request.get(header::IF_NONE_MATCH) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        // Weak comparison: `W/"x"` matches `"x"`.
        return value
            .split(',')
            .map(str::trim)
            .any(|tag| tag == "*" || tag.strip_prefix("W/").unwrap_or(tag) == etag);
    }
    request
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok())
        .is_some_and(|since| system_time(modified) <= since)
}

/// The range a request asks for, honoring `If-Range`: a range is served
/// only while the client's validator (the `ETag`, or the `Last-Modified`
/// date) is still the file's.
fn requested_range(request: &HeaderMap, size: u64, etag: &str, modified: &str) -> ByteRange {
    match request.get(header::IF_RANGE).map(|v| v.to_str()) {
        None => byte_range(request, size),
        Some(Ok(validator)) if validator.trim() == etag || validator.trim() == modified => {
            let mut without = request.clone();
            without.remove(header::IF_RANGE);
            byte_range(&without, size)
        }
        Some(_) => ByteRange::Full,
    }
}

/// `Content-Disposition` of a file of `repo`: a download (`attachment`), or
/// with the repository's `inline` option for display, naming the file.
pub fn content_disposition(repo: &Repository, file_path: &str) -> HeaderValue {
    let kind = if repo.inline_content() {
        "inline"
    } else {
        "attachment"
    };
    let name = files::file_name(file_path);
    let plain = name
        .chars()
        .all(|c| c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\');
    let value = if plain {
        format!("{kind}; filename=\"{name}\"")
    } else {
        // RFC 6266: an ASCII fallback, and the UTF-8 name.
        let fallback: String = name
            .chars()
            .map(|c| {
                if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!(
            "{kind}; filename=\"{fallback}\"; filename*=UTF-8''{}",
            percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC)
        )
    };
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

fn header(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// The headers every answer for `file` carries.
fn validators(out: &mut HeaderMap, etag: &str, modified: &str) {
    out.insert(header::ETAG, header(etag));
    out.insert(header::LAST_MODIFIED, header(modified));
}

/// Answer `GET`/`HEAD` of `file`, served by `repo` (the repository the
/// request named: a group's options apply to what its members serve).
pub async fn file(
    state: &AppState,
    repo: &Repository,
    file: &RawFile,
    request: &HeaderMap,
    head: bool,
) -> Response {
    let etag = etag(file);
    let modified = http_date(file.updated_at);
    if not_modified(request, &etag, file.updated_at) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        validators(response.headers_mut(), &etag, &modified);
        return response;
    }
    let size = u64::try_from(file.size).unwrap_or(0);
    let range = requested_range(request, size, &etag, &modified);
    if range == ByteRange::Unsatisfiable {
        let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_RANGE, header(&format!("bytes */{size}")));
        validators(response.headers_mut(), &etag, &modified);
        return response;
    }
    let (status, span) = match &range {
        ByteRange::Partial(span) => (StatusCode::PARTIAL_CONTENT, Some(span.clone())),
        _ => (StatusCode::OK, None),
    };
    let length = span.as_ref().map_or(size, |s| s.end - s.start);
    let body = if head {
        Body::empty()
    } else {
        let blob = BlobRef {
            sha256: &file.blob_sha256,
            s3_key: &file.s3_key,
            size,
        };
        match state.blob_store.open(blob, span.clone()).await {
            Ok(stream) => Body::from_stream(stream),
            Err(error) if error.is_unavailable() => {
                tracing::warn!(%error, path = %file.path, "files: object store unavailable");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "30")],
                    "object store unavailable",
                )
                    .into_response();
            }
            Err(error) => {
                tracing::error!(%error, path = %file.path, s3_key = %file.s3_key, "files: blob read failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
            }
        }
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let out = response.headers_mut();
    out.insert(header::CONTENT_TYPE, header(&file.content_type));
    out.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    out.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    out.insert(
        header::CONTENT_DISPOSITION,
        content_disposition(repo, &file.path),
    );
    validators(out, &etag, &modified);
    if let Some(span) = &span {
        out.insert(
            header::CONTENT_RANGE,
            header(&format!(
                "bytes {}-{}/{size}",
                span.start,
                span.end.saturating_sub(1)
            )),
        );
    }
    if !head {
        let pool = state.pool.clone();
        let id = file.id;
        tokio::spawn(async move {
            if let Err(error) = raw_dao::touch_downloaded(&pool, id).await {
                tracing::debug!(%error, "files: could not record a download");
            }
        });
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_file() -> RawFile {
        let t = DateTime::parse_from_rfc3339("2026-10-01T12:00:00.250Z")
            .unwrap()
            .with_timezone(&Utc);
        RawFile {
            id: 1,
            repository_id: 1,
            path: "dir/file.tgz".into(),
            blob_sha256: "ab".repeat(32),
            s3_key: "k".into(),
            size: 10,
            content_type: "application/gzip".into(),
            sha512_base64: String::new(),
            sha1: "cd".repeat(20),
            md5: "ef".repeat(16),
            created_at: t,
            updated_at: t,
            last_downloaded_at: None,
            upstream_etag: None,
            upstream_last_modified: None,
            checked_at: None,
        }
    }

    #[test]
    fn preconditions() {
        let file = raw_file();
        let tag = etag(&file);
        let mut h = HeaderMap::new();
        assert!(!not_modified(&h, &tag, file.updated_at));
        h.insert(header::IF_NONE_MATCH, header(&format!("\"x\", W/{tag}")));
        assert!(not_modified(&h, &tag, file.updated_at));
        h.insert(header::IF_NONE_MATCH, header("\"other\""));
        // An `If-None-Match` that fails decides; the date is not consulted.
        h.insert(
            header::IF_MODIFIED_SINCE,
            header(&http_date(file.updated_at)),
        );
        assert!(!not_modified(&h, &tag, file.updated_at));
        h.remove(header::IF_NONE_MATCH);
        // Sub-second precision is not part of an HTTP date.
        assert!(not_modified(&h, &tag, file.updated_at));
        let earlier = file.updated_at - chrono::Duration::seconds(5);
        h.insert(header::IF_MODIFIED_SINCE, header(&http_date(earlier)));
        assert!(!not_modified(&h, &tag, file.updated_at));
    }

    #[test]
    fn if_range_needs_the_current_validator() {
        let file = raw_file();
        let tag = etag(&file);
        let date = http_date(file.updated_at);
        let mut h = HeaderMap::new();
        h.insert(header::RANGE, header("bytes=2-"));
        assert_eq!(
            requested_range(&h, 10, &tag, &date),
            ByteRange::Partial(2..10)
        );
        h.insert(header::IF_RANGE, header(&tag));
        assert_eq!(
            requested_range(&h, 10, &tag, &date),
            ByteRange::Partial(2..10)
        );
        h.insert(header::IF_RANGE, header(&date));
        assert_eq!(
            requested_range(&h, 10, &tag, &date),
            ByteRange::Partial(2..10)
        );
        h.insert(header::IF_RANGE, header("\"stale\""));
        assert_eq!(requested_range(&h, 10, &tag, &date), ByteRange::Full);
    }

    #[test]
    fn dispositions_name_the_file() {
        let mut repo = forge_db::model::Repository {
            id: 1,
            name: "r".into(),
            format: "raw".into(),
            kind: "hosted".into(),
            anonymous_read: false,
            online: true,
            config: serde_json::json!({}),
            remote_url: None,
            package_delay_seconds: 0,
            upstream_username: None,
            upstream_password: None,
            upstream_password_enc: None,
            metadata_ttl_seconds: None,
            not_found_ttl_seconds: None,
            allow_redeploy: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(
            content_disposition(&repo, "a/b.txt"),
            "attachment; filename=\"b.txt\""
        );
        repo.config = serde_json::json!({"content_disposition": "inline"});
        assert_eq!(
            content_disposition(&repo, "a/\"ä\".txt"),
            "inline; filename=\"___.txt\"; filename*=UTF-8''%22%C3%A4%22%2Etxt"
        );
    }
}
