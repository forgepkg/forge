//! A gate in front of the shared versitygw: a TCP proxy that records every
//! S3 request passing through it (method and path) and can be closed to
//! simulate an S3 outage — new connections are dropped at once and open ones
//! are cut, as when the object store goes away.
//!
//! Requests are told apart by parsing the client's side of each connection
//! as HTTP/1.1 (request head, then `Content-Length` bytes of body), which is
//! all the S3 client sends with checksums off.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

/// See the [module docs](self).
pub struct S3Gate {
    endpoint: String,
    inner: Arc<Inner>,
    accept: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct Inner {
    down: AtomicBool,
    requests: Mutex<Vec<(String, String)>>,
    connections: Mutex<Vec<AbortHandle>>,
}

impl S3Gate {
    /// Open a gate to the shared versitygw of the e2e stacks.
    pub async fn start() -> S3Gate {
        Self::start_to(crate::stack::shared_s3_endpoint().await).await
    }

    /// Open a gate to the S3 endpoint `upstream` (`http://host:port`).
    pub async fn start_to(upstream: &str) -> S3Gate {
        let upstream = upstream
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gate");
        let endpoint = format!("http://{}", listener.local_addr().expect("gate addr"));
        let inner = Arc::new(Inner::default());
        let state = inner.clone();
        let accept = tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                if state.down.load(Ordering::SeqCst) {
                    drop(client);
                    continue;
                }
                let task = tokio::spawn(forward(client, upstream.clone(), state.clone()));
                let mut connections = state.connections.lock().unwrap();
                connections.retain(|c| !c.is_finished());
                connections.push(task.abort_handle());
            }
        });
        S3Gate {
            endpoint,
            inner,
            accept,
        }
    }

    /// The endpoint to configure as `s3.endpoint`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Close (`true`: S3 is down) or reopen the gate.
    pub fn set_down(&self, down: bool) {
        self.inner.down.store(down, Ordering::SeqCst);
        if down {
            for connection in self.inner.connections.lock().unwrap().drain(..) {
                connection.abort();
            }
        }
    }

    /// Every request that passed so far: `(method, path)`.
    pub fn requests(&self) -> Vec<(String, String)> {
        self.inner.requests.lock().unwrap().clone()
    }

    /// `GET`s of stored blobs (object keys under `blobs/`) so far.
    pub fn blob_gets(&self) -> usize {
        self.requests()
            .iter()
            .filter(|(method, path)| method == "GET" && path.contains("/blobs/"))
            .count()
    }
}

impl Drop for S3Gate {
    fn drop(&mut self) {
        self.accept.abort();
        self.set_down(true);
    }
}

/// Pipe one connection to `upstream`, recording the requests on the way.
async fn forward(client: TcpStream, upstream: String, state: Arc<Inner>) {
    let Ok(server) = TcpStream::connect(&upstream).await else {
        return;
    };
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let to_server = async {
        let mut scanner = RequestScanner::default();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let seen = scanner.feed(&buf[..n]);
            if !seen.is_empty() {
                state.requests.lock().unwrap().extend(seen);
            }
            if server_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = server_write.shutdown().await;
    };
    let to_client = async {
        let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
    };
    tokio::join!(to_server, to_client);
}

/// Splits a client's byte stream into HTTP/1.1 requests.
#[derive(Default)]
struct RequestScanner {
    buf: Vec<u8>,
    body_left: u64,
    /// A framing it does not follow (chunked): stop recording.
    lost: bool,
}

impl RequestScanner {
    fn feed(&mut self, data: &[u8]) -> Vec<(String, String)> {
        let mut seen = Vec::new();
        if self.lost {
            return seen;
        }
        self.buf.extend_from_slice(data);
        loop {
            if self.body_left > 0 {
                let n = self.body_left.min(self.buf.len() as u64);
                self.buf.drain(..n as usize);
                self.body_left -= n;
                if self.body_left > 0 {
                    break;
                }
            }
            let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                break;
            };
            let head = String::from_utf8_lossy(&self.buf[..end]).into_owned();
            self.buf.drain(..end + 4);
            let mut line = head.lines().next().unwrap_or("").split_whitespace();
            let method = line.next().unwrap_or("").to_string();
            let path = line.next().unwrap_or("").to_string();
            seen.push((method, path));
            let header = |name: &str| {
                head.lines().skip(1).find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case(name)
                        .then(|| v.trim().to_ascii_lowercase())
                })
            };
            if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
                self.lost = true;
                tracing::warn!("S3 gate: chunked request body; no longer counting this connection");
                break;
            }
            self.body_left = header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
        seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_requests_and_skips_bodies() {
        let mut s = RequestScanner::default();
        // The PUT's 10-byte body looks like a request line, and is skipped.
        let stream = b"PUT /b/blobs/x HTTP/1.1\r\ncontent-length: 10\r\n\r\nGET /fake!\
                       GET /b/blobs/y HTTP/1.1\r\nhost: h\r\n\r\nHEAD /b HTTP/1.1\r\n\r\n";
        // Fed in awkward pieces.
        let mut seen = Vec::new();
        for piece in stream.chunks(7) {
            seen.extend(s.feed(piece));
        }
        let methods: Vec<_> = seen.iter().map(|(m, p)| format!("{m} {p}")).collect();
        assert_eq!(methods, ["PUT /b/blobs/x", "GET /b/blobs/y", "HEAD /b"]);
    }
}
