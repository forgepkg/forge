//! Distribution-spec error responses:
//! `{"errors":[{"code","message","detail"}]}`, for the errors of the
//! protocol and for what the host refused or failed ([`ImageError`]).

use forge_plugin_api::images::{ImageError, Permission};
use forge_plugin_api::Response;
use serde_json::{json, Value};

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
#[derive(Debug, Clone, PartialEq)]
pub struct OciError {
    pub status: u16,
    pub code: Code,
    pub message: String,
    pub detail: Option<Value>,
    /// Extra response headers (`Range` of an upload, `Retry-After`).
    pub headers: Vec<(String, String)>,
}

impl OciError {
    pub fn new(status: u16, code: Code, message: impl Into<String>) -> Self {
        OciError {
            status,
            code,
            message: message.into(),
            detail: None,
            headers: Vec::new(),
        }
    }

    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn blob_unknown(digest: &str) -> Self {
        Self::new(404, Code::BlobUnknown, "blob unknown to registry")
            .with_detail(json!({ "digest": digest }))
    }

    pub fn manifest_unknown(reference: &str) -> Self {
        Self::new(404, Code::ManifestUnknown, "manifest unknown")
            .with_detail(json!({ "reference": reference }))
    }

    pub fn name_unknown(name: &str) -> Self {
        Self::new(
            404,
            Code::NameUnknown,
            "repository name not known to registry",
        )
        .with_detail(json!({ "name": name }))
    }

    pub fn name_invalid(name: &str) -> Self {
        Self::new(400, Code::NameInvalid, "invalid repository name")
            .with_detail(json!({ "name": name }))
    }

    pub fn upload_unknown() -> Self {
        Self::new(
            404,
            Code::BlobUploadUnknown,
            "blob upload unknown to registry",
        )
    }

    pub fn digest_invalid(message: impl Into<String>) -> Self {
        Self::new(400, Code::DigestInvalid, message)
    }

    pub fn manifest_invalid(message: impl Into<String>) -> Self {
        Self::new(400, Code::ManifestInvalid, message)
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(403, Code::Denied, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(405, Code::Unsupported, message)
    }

    pub fn too_large(limit: u64) -> Self {
        Self::new(
            413,
            Code::SizeInvalid,
            format!("content exceeds the limit of {limit} bytes"),
        )
    }

    /// An upload chunk that does not fit: 416 with the `Range` received so
    /// far.
    pub fn chunk(message: &str, size: u64) -> Self {
        Self::new(416, Code::BlobUploadInvalid, message).with_header("range", &upload_range(size))
    }

    /// The service cannot answer now: 503 with `Retry-After`.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(503, Code::Unavailable, message).with_header("retry-after", "30")
    }

    /// The JSON response.
    pub fn into_response(self) -> Response {
        let mut error = json!({
            "code": self.code.as_str(),
            "message": self.message,
        });
        if let Some(detail) = self.detail {
            error["detail"] = detail;
        }
        let body = json!({ "errors": [error] }).to_string();
        let mut response = Response::new(self.status, "application/json", body);
        response.headers.extend(self.headers);
        response
    }
}

/// `Range` of an upload: the inclusive end of the bytes received.
pub fn upload_range(size: u64) -> String {
    format!("0-{}", size.saturating_sub(1))
}

/// The token-scope actions a permission needs.
pub fn scope_actions(permission: Permission) -> &'static str {
    match permission {
        Permission::Read => "pull",
        Permission::Write => "pull,push",
        Permission::Delete => "delete",
    }
}

/// What the host refused or failed, as the client sees it.
pub fn of(error: &ImageError) -> OciError {
    match error {
        ImageError::NotAnEndpoint => {
            OciError::new(404, Code::NameUnknown, "not a registry endpoint")
        }
        ImageError::NameInvalid { name, hint } => {
            let invalid = OciError::name_invalid(name);
            match hint {
                Some(hint) => invalid.with_detail(json!({ "name": name, "hint": hint })),
                None => invalid,
            }
        }
        ImageError::NameUnknown { name } => OciError::name_unknown(name),
        ImageError::AuthenticationRequired { scope } => {
            let required = OciError::new(401, Code::Unauthorized, "authentication required");
            match scope {
                Some((name, permission)) => required
                    .with_detail(json!({ "name": name, "action": scope_actions(*permission) })),
                None => required,
            }
        }
        ImageError::InvalidToken => {
            OciError::new(401, Code::Unauthorized, "invalid or expired registry token")
        }
        ImageError::InvalidCredentials => {
            OciError::new(401, Code::Unauthorized, "invalid credentials")
        }
        ImageError::Denied { name, permission } => {
            OciError::denied("requested access to the resource is denied")
                .with_detail(json!({ "name": name, "action": scope_actions(*permission) }))
        }
        ImageError::Unsupported { status, message } => {
            OciError::new(*status, Code::Unsupported, message.clone())
        }
        ImageError::Offline => OciError::unavailable("repository is offline"),
        ImageError::BlobUnknown { digest } => OciError::blob_unknown(digest),
        ImageError::ManifestUnknown { reference } => OciError::manifest_unknown(reference),
        ImageError::UploadUnknown => OciError::upload_unknown(),
        ImageError::DigestMismatch => {
            OciError::digest_invalid("the uploaded content does not match the digest")
        }
        ImageError::ChunkOutOfOrder { size } => {
            OciError::chunk("the chunk does not continue the upload", *size)
        }
        ImageError::ChunkLength { size } => {
            OciError::chunk("the chunk length does not match its Content-Range", *size)
        }
        ImageError::TooLarge { limit } => OciError::too_large(*limit),
        ImageError::BodyUnreadable => OciError::new(
            400,
            Code::BlobUploadInvalid,
            "the request body could not be read",
        ),
        ImageError::ManifestInvalid(message) => OciError::manifest_invalid(message.clone()),
        ImageError::ManifestBlobUnknown { digest, manifest } => OciError::new(
            400,
            Code::ManifestBlobUnknown,
            if *manifest {
                "the index references a manifest unknown to this repository"
            } else {
                "the manifest references a blob unknown to this repository"
            },
        )
        .with_detail(json!({ "digest": digest })),
        ImageError::TagImmutable { tag } => OciError::denied(format!(
            "tag {tag:?} already exists and tags are immutable in this repository"
        ))
        .with_detail(json!({ "tag": tag })),
        ImageError::BlobReferenced { digest } => OciError::new(
            409,
            Code::Denied,
            "the blob is referenced by a manifest of this image; delete the manifest first",
        )
        .with_detail(json!({ "digest": digest })),
        ImageError::NoLongerAllowed => {
            OciError::denied("the workload identity may no longer change this repository")
        }
        ImageError::RateLimited => OciError::new(
            429,
            Code::TooManyRequests,
            "the upstream registry rate-limits this proxy; retry later",
        ),
        ImageError::Unavailable(message) => OciError::unavailable(message.clone()),
        ImageError::Internal => OciError::new(500, Code::Unavailable, "internal error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(response: &Response) -> Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    fn header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn errors_carry_their_code_status_and_detail() {
        let response = of(&ImageError::Denied {
            name: "docker/app".into(),
            permission: Permission::Write,
        })
        .into_response();
        assert_eq!(response.status, 403);
        let denied = body(&response);
        assert_eq!(denied["errors"][0]["code"], "DENIED");
        assert_eq!(denied["errors"][0]["detail"]["action"], "pull,push");

        let response = of(&ImageError::ChunkOutOfOrder { size: 100 }).into_response();
        assert_eq!(response.status, 416);
        assert_eq!(header(&response, "range"), Some("0-99"));

        let response =
            of(&ImageError::Unavailable("the object store is down".into())).into_response();
        assert_eq!(response.status, 503);
        assert_eq!(header(&response, "retry-after"), Some("30"));
        assert_eq!(body(&response)["errors"][0]["code"], "UNAVAILABLE");

        let response = of(&ImageError::Internal).into_response();
        assert_eq!(response.status, 500);
        assert_eq!(body(&response)["errors"][0]["message"], "internal error");
    }

    #[test]
    fn upload_ranges() {
        assert_eq!(upload_range(0), "0-0");
        assert_eq!(upload_range(1), "0-0");
        assert_eq!(upload_range(100), "0-99");
    }
}
