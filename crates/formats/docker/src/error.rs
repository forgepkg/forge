//! Distribution-spec error responses: `{"errors":[{"code","message","detail"}]}`.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// The error codes of the distribution spec (plus Docker's `UNAVAILABLE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    BlobUnknown,
    BlobUploadInvalid,
    BlobUploadUnknown,
    DigestInvalid,
    ManifestBlobUnknown,
    ManifestInvalid,
    ManifestUnknown,
    NameInvalid,
    NameUnknown,
    SizeInvalid,
    Unauthorized,
    Denied,
    Unsupported,
    TooManyRequests,
    /// Docker distribution's code for a temporarily unavailable service.
    Unavailable,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::BlobUnknown => "BLOB_UNKNOWN",
            Code::BlobUploadInvalid => "BLOB_UPLOAD_INVALID",
            Code::BlobUploadUnknown => "BLOB_UPLOAD_UNKNOWN",
            Code::DigestInvalid => "DIGEST_INVALID",
            Code::ManifestBlobUnknown => "MANIFEST_BLOB_UNKNOWN",
            Code::ManifestInvalid => "MANIFEST_INVALID",
            Code::ManifestUnknown => "MANIFEST_UNKNOWN",
            Code::NameInvalid => "NAME_INVALID",
            Code::NameUnknown => "NAME_UNKNOWN",
            Code::SizeInvalid => "SIZE_INVALID",
            Code::Unauthorized => "UNAUTHORIZED",
            Code::Denied => "DENIED",
            Code::Unsupported => "UNSUPPORTED",
            Code::TooManyRequests => "TOOMANYREQUESTS",
            Code::Unavailable => "UNAVAILABLE",
        }
    }
}

/// An error answered to a registry client.
#[derive(Debug, Clone)]
pub struct OciError {
    pub status: StatusCode,
    pub code: Code,
    pub message: String,
    pub detail: Option<serde_json::Value>,
    /// Extra response headers (a `WWW-Authenticate` challenge, `Range` of an
    /// upload, `Retry-After`).
    pub headers: Vec<(header::HeaderName, HeaderValue)>,
}

impl OciError {
    pub fn new(status: StatusCode, code: Code, message: impl Into<String>) -> Self {
        OciError {
            status,
            code,
            message: message.into(),
            detail: None,
            headers: Vec::new(),
        }
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn with_header(mut self, name: header::HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    pub fn blob_unknown(digest: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            Code::BlobUnknown,
            "blob unknown to registry",
        )
        .with_detail(serde_json::json!({ "digest": digest }))
    }

    pub fn manifest_unknown(reference: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            Code::ManifestUnknown,
            "manifest unknown",
        )
        .with_detail(serde_json::json!({ "reference": reference }))
    }

    pub fn name_unknown(name: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            Code::NameUnknown,
            "repository name not known to registry",
        )
        .with_detail(serde_json::json!({ "name": name }))
    }

    pub fn name_invalid(name: &str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            Code::NameInvalid,
            "invalid repository name",
        )
        .with_detail(serde_json::json!({ "name": name }))
    }

    pub fn upload_unknown() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            Code::BlobUploadUnknown,
            "blob upload unknown to registry",
        )
    }

    pub fn digest_invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Code::DigestInvalid, message)
    }

    pub fn manifest_invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Code::ManifestInvalid, message)
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, Code::Denied, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, Code::Unsupported, message)
    }

    pub fn too_large(limit: u64) -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            Code::SizeInvalid,
            format!("content exceeds the limit of {limit} bytes"),
        )
    }

    /// The service cannot answer now (staging full, upstream down, offline
    /// repository): 503 with `Retry-After`.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, Code::Unavailable, message)
            .with_header(header::RETRY_AFTER, HeaderValue::from_static("30"))
    }

    /// An internal failure; the details go to the log, not the client.
    pub fn internal(context: &str, error: impl std::fmt::Display) -> Self {
        tracing::error!(error = %error, "registry: {context}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Code::Unavailable,
            "internal error",
        )
    }
}

impl From<sqlx::Error> for OciError {
    fn from(e: sqlx::Error) -> Self {
        OciError::internal("database error", e)
    }
}

impl OciError {
    /// A failed read from the object store (through the local blob cache):
    /// 503 with `Retry-After` while S3 cannot be reached, a server error
    /// otherwise.
    pub(crate) fn storage_read(context: &str, error: forge_storage::S3Error) -> Self {
        if error.is_unavailable() {
            tracing::warn!(%error, "registry: {context}: the object store is unavailable");
            OciError::object_store_unavailable()
        } else {
            OciError::internal(context, error)
        }
    }

    fn object_store_unavailable() -> Self {
        OciError::unavailable("the object store is unavailable; retry later")
    }
}

/// A request body that could not be read: the client aborted it, or it
/// stalled past the idle timeout. Travels inside the I/O error staging the
/// body fails with.
#[derive(Debug)]
pub(crate) struct RequestBodyError(pub axum::Error);

impl std::fmt::Display for RequestBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reading the request body: {}", self.0)
    }
}

impl std::error::Error for RequestBodyError {}

impl From<forge_storage::CasError> for OciError {
    fn from(e: forge_storage::CasError) -> Self {
        match e {
            forge_storage::CasError::TooLarge { limit } => OciError::too_large(limit),
            forge_storage::CasError::StagingFull { .. } => {
                OciError::unavailable("temporary storage is full; retry later")
            }
            e if e.is_unavailable() => {
                tracing::warn!(error = %e, "registry: the object store is unavailable");
                OciError::object_store_unavailable()
            }
            forge_storage::CasError::Io(e)
                if e.get_ref()
                    .is_some_and(|inner| inner.is::<RequestBodyError>()) =>
            {
                tracing::debug!(error = %e, "registry: the upload body could not be read");
                OciError::new(
                    StatusCode::BAD_REQUEST,
                    Code::BlobUploadInvalid,
                    "the request body could not be read",
                )
            }
            other => OciError::internal("storage error", other),
        }
    }
}

impl IntoResponse for OciError {
    fn into_response(self) -> Response {
        let mut error = serde_json::json!({
            "code": self.code.as_str(),
            "message": self.message,
        });
        if let Some(detail) = self.detail {
            error["detail"] = detail;
        }
        let body = serde_json::json!({ "errors": [error] }).to_string();
        let mut response = (
            self.status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response();
        for (name, value) in self.headers {
            response.headers_mut().insert(name, value);
        }
        response
    }
}

/// Result alias of registry handlers.
pub type OciResult<T> = Result<T, OciError>;

#[cfg(test)]
mod tests {
    use forge_storage::{CasError, S3Error};

    use super::*;

    fn down() -> S3Error {
        S3Error::Unavailable("connection refused".into())
    }

    #[test]
    fn an_unavailable_object_store_answers_503_with_retry_after() {
        // Also when a stream read from S3 failed while it was staged (the
        // finish of a chunked upload).
        for e in [
            CasError::S3(down()),
            CasError::Io(std::io::Error::other(down())),
        ] {
            let e = OciError::from(e);
            assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(e.code, Code::Unavailable);
            assert!(e
                .headers
                .iter()
                .any(|(name, _)| name == header::RETRY_AFTER));
        }
        let e = OciError::storage_read("blob read", down());
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
        let e = OciError::storage_read("blob read", S3Error::S3("access denied".into()));
        assert_eq!(e.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn an_unreadable_request_body_is_the_clients_error() {
        let aborted = std::io::Error::other(RequestBodyError(axum::Error::new(
            "connection reset by peer",
        )));
        let e = OciError::from(CasError::Io(aborted));
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert_eq!(e.code, Code::BlobUploadInvalid);
        // Staging's own I/O errors stay server errors.
        let e = OciError::from(CasError::Io(std::io::Error::other("disk full")));
        assert_eq!(e.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
