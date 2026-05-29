//! Streaming content hashing.
//!
//! [`HashingWriter`] wraps a [`tokio::io::AsyncWrite`] (typically a temp file)
//! and feeds every byte that streams through it into both a SHA-256 and a
//! SHA-512 digest while also counting the total size. This lets us compute the
//! content address and the upload checksum in a single pass over the body —
//! no second read of the temp file.

use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// An [`AsyncWrite`] adapter that hashes bytes as they pass through to an inner
/// writer.
///
/// Call [`HashingWriter::finalize`] once writing is complete to flush the inner
/// writer and obtain the digests and byte count.
pub struct HashingWriter<W> {
    inner: W,
    sha256: Sha256,
    sha512: Sha512,
    size: u64,
}

impl<W> HashingWriter<W> {
    /// Wrap `inner`, starting fresh digests and a zero byte count.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            sha256: Sha256::new(),
            sha512: Sha512::new(),
            size: 0,
        }
    }
}

impl<W> HashingWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Flush the inner writer and return `(sha256_hex, sha512_base64, size)`.
    ///
    /// * `sha256_hex` — lowercase hex of the SHA-256 digest (the content
    ///   address / blob key material).
    /// * `sha512_base64` — standard (RFC 4648) base64 of the SHA-512 digest
    ///   (e.g. for the NuGet package hash / asset integrity field).
    /// * `size` — total bytes written.
    pub async fn finalize(mut self) -> std::io::Result<(String, String, u64)> {
        self.inner.flush().await?;
        let sha256 = hex_lower(&self.sha256.finalize());
        let sha512 = base64::engine::general_purpose::STANDARD.encode(self.sha512.finalize());
        Ok((sha256, sha512, self.size))
    }
}

/// Lowercase hex encoding of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl<W> AsyncWrite for HashingWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                // Only hash the bytes the inner writer actually accepted.
                this.sha256.update(&buf[..n]);
                this.sha512.update(&buf[..n]);
                this.size += n as u64;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Hash `input` by streaming it through a `HashingWriter` over an in-memory
    /// sink, returning `(sha256_hex, sha512_base64, size)`.
    async fn hash_bytes(input: &[u8]) -> (String, String, u64) {
        let sink: Vec<u8> = Vec::new();
        let mut w = HashingWriter::new(sink);
        w.write_all(input).await.unwrap();
        w.finalize().await.unwrap()
    }

    #[tokio::test]
    async fn empty_string_vectors() {
        let (sha256, sha512, size) = hash_bytes(b"").await;
        assert_eq!(size, 0);
        // Known NIST vectors for the empty input.
        assert_eq!(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // base64 of the empty-string SHA-512 digest.
        assert_eq!(
            sha512,
            "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
        );
    }

    #[tokio::test]
    async fn abc_vectors() {
        let (sha256, sha512, size) = hash_bytes(b"abc").await;
        assert_eq!(size, 3);
        assert_eq!(
            sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha512,
            "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="
        );
    }

    #[tokio::test]
    async fn multiple_writes_accumulate() {
        // Streaming in chunks must match hashing the concatenation in one go.
        let sink: Vec<u8> = Vec::new();
        let mut w = HashingWriter::new(sink);
        w.write_all(b"a").await.unwrap();
        w.write_all(b"b").await.unwrap();
        w.write_all(b"c").await.unwrap();
        let (sha256, _sha512, size) = w.finalize().await.unwrap();
        assert_eq!(size, 3);
        assert_eq!(
            sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
