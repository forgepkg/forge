//! Conditional-write (`If-None-Match: *`) behavior of `BlobStore::put_if_absent`
//! against a scripted fake S3 — covers both code paths from the design spec
//! (§3.7: "a fake S3 returning 412 vs. not") without Docker, unlike
//! `s3_tests.rs` which needs a live versitygw.
//!
//! The fake is a minimal HTTP/1.1 responder: it records every request (method +
//! whether `If-None-Match` was sent), answers from a per-test script keyed on
//! the request shape, and closes the connection after each response so the SDK
//! never pipelines.

use std::sync::{Arc, Mutex};

use forge_storage::{BlobStore, ConditionalWrites, S3Config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One request as observed by the fake backend.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    conditional: bool,
}

/// A canned response: HTTP status + optional S3 XML error code for the body.
#[derive(Debug, Clone, Copy)]
struct Resp {
    status: u16,
    code: Option<&'static str>,
}

const OK: Resp = Resp {
    status: 200,
    code: None,
};
const NOT_FOUND: Resp = Resp {
    status: 404,
    code: Some("NoSuchKey"),
};
const PRECONDITION_FAILED: Resp = Resp {
    status: 412,
    code: Some("PreconditionFailed"),
};
const NOT_IMPLEMENTED: Resp = Resp {
    status: 501,
    code: Some("NotImplemented"),
};

/// Spawn the fake S3. `script` maps each observed request to a response.
async fn spawn_fake_s3<F>(script: F) -> (String, Arc<Mutex<Vec<Seen>>>)
where
    F: Fn(&Seen) -> Resp + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let log = seen.clone();
    let script = Arc::new(script);

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let log = log.clone();
            let script = script.clone();
            tokio::spawn(async move {
                // Read the head (status line + headers) byte-by-byte-ish until
                // the blank line, then drain exactly Content-Length body bytes.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    let n = match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_blank_line(&buf) {
                        break pos;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let content_length = header(&head, "content-length")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut have = buf.len() - (head_end + 4);
                while have < content_length {
                    let n = match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    have += n;
                }

                let req = Seen {
                    method: head.split_whitespace().next().unwrap_or("").to_string(),
                    conditional: header(&head, "if-none-match").is_some(),
                };
                let resp = script(&req);
                let is_head = req.method == "HEAD";
                log.lock().unwrap().push(req);

                let body = match resp.code {
                    // HEAD responses carry no body even on errors.
                    Some(code) if !is_head => format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <Error><Code>{code}</Code><Message>{code}</Message></Error>"
                    ),
                    _ => String::new(),
                };
                let reply = format!(
                    "HTTP/1.1 {} {}\r\n\
                     content-type: application/xml\r\n\
                     content-length: {}\r\n\
                     connection: close\r\n\
                     \r\n{}",
                    resp.status,
                    reason(resp.status),
                    body.len(),
                    body
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    (endpoint, seen)
}

/// Offset of the `\r\n\r\n` separating headers from body, if present.
fn find_blank_line(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Case-insensitive single-header lookup in a raw request head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        412 => "Precondition Failed",
        501 => "Not Implemented",
        _ => "Unknown",
    }
}

/// A `BlobStore` pointed at the fake backend.
fn store(endpoint: &str, mode: ConditionalWrites) -> BlobStore {
    BlobStore::new(S3Config {
        endpoint: endpoint.to_string(),
        region: "us-east-1".into(),
        bucket: "forge-test".into(),
        access_key: "test".into(),
        secret_key: "test".into(),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: mode,
    })
}

/// A small temp file to upload.
async fn body_file() -> tempfile::NamedTempFile {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tokio::fs::write(tmp.path(), b"conditional-write test body")
        .await
        .unwrap();
    tmp
}

/// 412 on the conditional PUT is the dedup hit: `Ok(false)`, and the whole
/// answer took a single round trip (no HEAD at all).
#[tokio::test]
async fn conditional_412_is_a_dedup_hit() {
    let (endpoint, seen) = spawn_fake_s3(|_| PRECONDITION_FAILED).await;
    let s = store(&endpoint, ConditionalWrites::On);
    let tmp = body_file().await;

    let uploaded = s.put_if_absent("k/412", tmp.path()).await.unwrap();
    assert!(!uploaded, "412 means already present");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "one conditional PUT, no HEAD: {seen:?}");
    assert_eq!(seen[0].method, "PUT");
    assert!(seen[0].conditional, "If-None-Match was sent");
}

/// A 2xx conditional PUT uploads in a single round trip.
#[tokio::test]
async fn conditional_2xx_uploads_in_one_round_trip() {
    let (endpoint, seen) = spawn_fake_s3(|_| OK).await;
    let s = store(&endpoint, ConditionalWrites::On);
    let tmp = body_file().await;

    let uploaded = s.put_if_absent("k/2xx", tmp.path()).await.unwrap();
    assert!(uploaded);

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method, "PUT");
    assert!(seen[0].conditional);
}

/// `auto` against a versitygw-shaped backend (501 NotImplemented for the
/// conditional header): the put falls back to HEAD-then-PUT, still succeeds,
/// and the verdict is latched — the next put never tries the header again.
#[tokio::test]
async fn auto_falls_back_on_not_implemented_and_latches() {
    let (endpoint, seen) = spawn_fake_s3(|req| match (req.method.as_str(), req.conditional) {
        ("PUT", true) => NOT_IMPLEMENTED,
        ("HEAD", _) => NOT_FOUND,
        _ => OK,
    })
    .await;
    let s = store(&endpoint, ConditionalWrites::Auto);
    let tmp = body_file().await;

    // First put: conditional PUT (501) → HEAD (404) → plain PUT (200).
    let uploaded = s.put_if_absent("k/first", tmp.path()).await.unwrap();
    assert!(uploaded, "fallback path still uploads");
    {
        let seen = seen.lock().unwrap();
        let shape: Vec<(&str, bool)> = seen
            .iter()
            .map(|r| (r.method.as_str(), r.conditional))
            .collect();
        assert_eq!(
            shape,
            vec![("PUT", true), ("HEAD", false), ("PUT", false)],
            "501 → HEAD-then-PUT retry of the same put"
        );
    }

    // Second put (through a clone, like a worker would hold): the latch means
    // straight HEAD-then-PUT, no conditional attempt.
    let uploaded = s
        .clone()
        .put_if_absent("k/second", tmp.path())
        .await
        .unwrap();
    assert!(uploaded);
    let seen = seen.lock().unwrap();
    let tail: Vec<(&str, bool)> = seen[3..]
        .iter()
        .map(|r| (r.method.as_str(), r.conditional))
        .collect();
    assert_eq!(
        tail,
        vec![("HEAD", false), ("PUT", false)],
        "latched: no further If-None-Match attempts"
    );
}

/// `off` never sends the conditional header — the original HEAD-then-PUT.
#[tokio::test]
async fn off_never_sends_conditional_header() {
    let (endpoint, seen) = spawn_fake_s3(|req| match req.method.as_str() {
        "HEAD" => NOT_FOUND,
        _ => OK,
    })
    .await;
    let s = store(&endpoint, ConditionalWrites::Off);
    let tmp = body_file().await;

    let uploaded = s.put_if_absent("k/off", tmp.path()).await.unwrap();
    assert!(uploaded);

    let seen = seen.lock().unwrap();
    let shape: Vec<(&str, bool)> = seen
        .iter()
        .map(|r| (r.method.as_str(), r.conditional))
        .collect();
    assert_eq!(shape, vec![("HEAD", false), ("PUT", false)]);
}

/// `off` dedup hit: HEAD says present, no PUT happens.
#[tokio::test]
async fn off_head_hit_skips_the_put() {
    let (endpoint, seen) = spawn_fake_s3(|_| OK).await;
    let s = store(&endpoint, ConditionalWrites::Off);
    let tmp = body_file().await;

    let uploaded = s.put_if_absent("k/present", tmp.path()).await.unwrap();
    assert!(!uploaded, "HEAD 200 is the dedup hit");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method, "HEAD");
}

/// `on` against a backend without support surfaces the error instead of
/// silently degrading (it is an explicit operator promise).
#[tokio::test]
async fn on_surfaces_not_implemented() {
    let (endpoint, seen) = spawn_fake_s3(|_| NOT_IMPLEMENTED).await;
    let s = store(&endpoint, ConditionalWrites::On);
    let tmp = body_file().await;

    let err = s.put_if_absent("k/on", tmp.path()).await.unwrap_err();
    assert!(
        format!("{err}").contains("NotImplemented"),
        "501 propagates in `on` mode: {err}"
    );

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "no fallback in `on` mode: {seen:?}");
    assert!(seen[0].conditional);
}
