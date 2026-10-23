//! Changing files of a hosted raw repository: `PUT` of one file, a
//! multipart form of several (the web UI's upload, and the form fields of
//! Nexus' component upload), and `DELETE`.
//!
//! An upload is streamed to the staging directory under the repository's
//! upload limit, hashed on the way (SHA-256 and SHA-512 by the CAS, SHA-1
//! and MD5 here, for the checksum sidecars), stored content-addressed, and
//! recorded in one transaction with the deployment policy applied under the
//! row lock: a path that exists is replaced only with `allow_redeploy` and
//! the delete permission, and the same content again is accepted as is.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use bytes::Bytes;
use forge_core::auth::principal::{AuthMethod, Principal};
use forge_core::authz::Action;
use forge_core::repo::{PackageMutation, PublishAuthorizationContext, WriteError};
use forge_db::model::{DeploymentPolicy, RepoKind, Repository};
use forge_db::raw_dao::{self, NewRawFile, Redeploy, StoreOutcome};
use forge_storage::{CasError, StoredBlob};
use futures_util::{Stream, TryStreamExt};
use md5::Md5;
use serde::Serialize;
use sha1::{Digest as _, Sha1};

use super::{path, Raw, RawError};
use crate::dispatch::principal_allows_protocol_mutations;

/// Most files one multipart upload may carry.
pub const MAX_FILES_PER_UPLOAD: usize = 100;

/// Largest text field of a multipart upload.
const MAX_TEXT_FIELD_BYTES: usize = 4096;

/// Who may change files through a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The `/raw` protocol: an API token or a workload identity, as for
    /// every package client (never a browser session).
    Protocol,
    /// The web UI's endpoints: a signed-in session (whose CSRF token the
    /// principal middleware checked) or a token.
    Browser,
}

/// Uploaded content, stored in the CAS (its reference still to be taken),
/// with the digests the CAS does not keep.
pub struct Ingested {
    pub stored: StoredBlob,
    pub sha1: String,
    pub md5: String,
}

#[derive(Default)]
struct Digests {
    sha1: Sha1,
    md5: Md5,
}

/// Stage `body` (at most `limit` bytes) and store it content-addressed.
pub async fn ingest<S, E>(raw: &Raw<'_>, body: S, limit: u64) -> Result<Ingested, RawError>
where
    S: Stream<Item = Result<Bytes, E>> + Send + Unpin,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let digests = Arc::new(Mutex::new(Digests::default()));
    let tap = digests.clone();
    let body = body
        .map_err(std::io::Error::other)
        .inspect_ok(move |chunk| {
            let mut d = tap.lock().unwrap_or_else(PoisonError::into_inner);
            d.sha1.update(chunk);
            d.md5.update(chunk);
        });
    let staged = raw
        .state
        .cas
        .stage(tokio_util::io::StreamReader::new(body), limit)
        .await
        .map_err(cas_error)?;
    let digests = std::mem::take(&mut *digests.lock().unwrap_or_else(PoisonError::into_inner));
    let stored = raw.state.cas.commit(staged).await.map_err(cas_error)?;
    Ok(Ingested {
        stored,
        sha1: hex::encode(digests.sha1.finalize()),
        md5: hex::encode(digests.md5.finalize()),
    })
}

/// An ingest failure as the answer to the request.
pub fn cas_error(error: CasError) -> RawError {
    match error {
        CasError::TooLarge { limit } => RawError::TooLarge(limit),
        CasError::StagingFull { .. } => {
            RawError::Unavailable("temporary staging space is exhausted; retry later".into())
        }
        e if e.is_unavailable() => RawError::Unavailable("object store unavailable".into()),
        CasError::Io(e) => RawError::BadRequest(format!("the upload could not be read: {e}")),
        e => RawError::Internal(format!("store upload: {e}")),
    }
}

/// The content type to store for a file at `path`: the one the client
/// declared, unless it only says "bytes" (or a form encoding), else the one
/// its extension suggests.
pub fn content_type(declared: Option<&str>, path: &str) -> String {
    let declared = declared.map(str::trim).filter(|ct| {
        let essence = ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        !matches!(
            essence.as_str(),
            "" | "application/octet-stream"
                | "binary/octet-stream"
                | "application/x-www-form-urlencoded"
                | "multipart/form-data"
        ) && ct.len() <= 255
            && !ct.chars().any(char::is_control)
            && ct.parse::<mime_guess::mime::Mime>().is_ok()
    });
    match declared {
        Some(ct) => ct.to_string(),
        None => mime_guess::from_path(path)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_string(),
    }
}

/// The answer to an upload or delete that needs `action` on `repo`, when it
/// may not happen; `None` when it may.
async fn refusal(raw: &Raw<'_>, repo: &Repository, action: Action, via: Via) -> Option<RawError> {
    if repo.kind() != RepoKind::Hosted {
        return Some(RawError::MethodNotAllowed(
            "files are uploaded to and deleted from hosted repositories",
        ));
    }
    let credential = match via {
        Via::Protocol => principal_allows_protocol_mutations(&raw.principal),
        Via::Browser => {
            matches!(
                raw.principal,
                Principal::User { method, .. } if method != AuthMethod::Password
            ) || matches!(raw.principal, Principal::Workload { .. })
        }
    };
    if !credential {
        return Some(RawError::CredentialRequired);
    }
    let allowed = match action {
        Action::Delete => raw.state.authz.can_delete(&raw.principal, repo).await,
        _ => raw.state.authz.can_write(&raw.principal, repo).await,
    };
    if !allowed {
        return Some(RawError::Denied);
    }
    if repo.deployment_policy() == DeploymentPolicy::ReadOnly {
        return Some(RawError::MethodNotAllowed("the repository is read-only"));
    }
    None
}

/// Record a workload's change in the trusted-publishing ledger, inside the
/// transaction that makes it.
async fn record(
    raw: &Raw<'_>,
    repo: &Repository,
    action: PackageMutation,
    path: &str,
    sha256: &str,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), RawError> {
    if !matches!(raw.principal, Principal::Workload { .. }) {
        return Ok(());
    }
    let context = PublishAuthorizationContext {
        principal: raw.principal,
        action,
        package_id: path.to_string(),
        package_version: sha256.to_string(),
    };
    crate::dispatch::workload_ledger_policy(repo)
        .record_in_transaction(&context, tx)
        .await
        .map_err(|e| match e {
            WriteError::ForbiddenPackage { .. } => RawError::Forbidden(
                "the workload identity may no longer change this repository".into(),
            ),
            other => RawError::Internal(format!("trusted-publishing record: {other}")),
        })
}

/// One file of an upload, ready to be recorded.
struct Pending {
    path: String,
    content_type: String,
    ingested: Ingested,
}

/// What became of one uploaded file.
#[derive(Debug, Serialize)]
pub struct Stored {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// `created` | `replaced` | `unchanged`.
    pub status: &'static str,
}

/// Record `files` in one transaction: all of them or none.
async fn record_all(
    raw: &Raw<'_>,
    repo: &Repository,
    files: Vec<Pending>,
) -> Result<Vec<Stored>, RawError> {
    let policy = repo.deployment_policy();
    let replace = raw
        .state
        .authz
        .package_filter_for(&raw.principal, repo, Action::Delete)
        .await;
    let may_delete = raw.state.authz.can_delete(&raw.principal, repo).await;
    let grace = raw.state.config.outbox.grace();
    let mut tx = raw.state.pool.begin().await?;
    let mut out = Vec::with_capacity(files.len());
    for file in &files {
        let stored = &file.ingested.stored;
        let replaceable =
            policy == DeploymentPolicy::AllowRedeploy && may_delete && replace.allows(&file.path);
        let new = NewRawFile {
            path: &file.path,
            sha256: &stored.sha256,
            size: i64::try_from(stored.size).map_err(|_| RawError::TooLarge(stored.size))?,
            content_type: &file.content_type,
            sha512_base64: &stored.sha512_base64,
            sha1: &file.ingested.sha1,
            md5: &file.ingested.md5,
            upstream_etag: None,
            upstream_last_modified: None,
            checked: false,
        };
        let redeploy = if replaceable {
            Redeploy::Allow
        } else {
            Redeploy::Deny
        };
        let status =
            match raw_dao::store(&mut tx, repo.id, &new, stored.ingest_token, redeploy, grace)
                .await?
            {
                StoreOutcome::Created(_) => "created",
                StoreOutcome::Replaced(_) => "replaced",
                StoreOutcome::Unchanged(_) => "unchanged",
                StoreOutcome::Exists if policy == DeploymentPolicy::AllowRedeploy => {
                    return Err(RawError::Forbidden(format!(
                        "{} exists; replacing a file needs the delete permission",
                        file.path
                    )));
                }
                StoreOutcome::Exists => {
                    return Err(RawError::Conflict(format!(
                        "{} exists and the repository does not allow redeploying it",
                        file.path
                    )));
                }
            };
        if status != "unchanged" {
            record(
                raw,
                repo,
                PackageMutation::Publish,
                &file.path,
                &stored.sha256,
                &mut tx,
            )
            .await?;
        }
        out.push(Stored {
            path: file.path.clone(),
            size: stored.size,
            sha256: stored.sha256.clone(),
            status,
        });
    }
    tx.commit().await?;
    Ok(out)
}

/// `PUT /raw/<repo>/<path>`: store the request body as the file.
pub async fn put(raw: &Raw<'_>, repo: &Repository, path: &str, req: Request<Body>) -> Response {
    match put_inner(raw, repo, path, req).await {
        Ok(Stored {
            status: "created", ..
        }) => StatusCode::CREATED.into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn put_inner(
    raw: &Raw<'_>,
    repo: &Repository,
    path: &str,
    req: Request<Body>,
) -> Result<Stored, RawError> {
    if let Some(refused) = refusal(raw, repo, Action::Write, Via::Protocol).await {
        return Err(refused);
    }
    let write = raw
        .state
        .authz
        .package_filter_for(&raw.principal, repo, Action::Write)
        .await;
    if !write.allows(path) {
        return Err(RawError::Forbidden(format!("you may not upload to {path}")));
    }
    let limit = raw.state.upload_limit(repo);
    let declared_length = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared_length.is_some_and(|len| len > limit) {
        return Err(RawError::TooLarge(limit));
    }
    let declared = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let ingested = ingest(raw, req.into_body().into_data_stream(), limit).await?;
    let pending = Pending {
        path: path.to_string(),
        content_type: content_type(declared.as_deref(), path),
        ingested,
    };
    let mut stored = record_all(raw, repo, vec![pending]).await?;
    Ok(stored.remove(0))
}

/// `POST /raw/<repo>/<directory>/` (and the web UI's upload): a
/// `multipart/form-data` body whose file parts are stored under
/// `directory`, each at its part's file name. Nexus' field names work too:
/// `raw.directory` (or `directory`) names a subdirectory, and
/// `<field>.filename` (`raw.asset1.filename`) the name of the file part
/// `<field>`. Every file is recorded, or none.
pub async fn multipart(
    raw: &Raw<'_>,
    repo: &Repository,
    directory: &str,
    req: Request<Body>,
    via: Via,
) -> Response {
    match multipart_inner(raw, repo, directory, req, via).await {
        Ok(files) => {
            let status = if files.iter().any(|f| f.status == "created") {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (status, Json(serde_json::json!({ "files": files }))).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// A file part, staged and stored, its name to be decided.
struct FilePart {
    field: String,
    file_name: String,
    declared: Option<String>,
    ingested: Ingested,
}

async fn multipart_inner(
    raw: &Raw<'_>,
    repo: &Repository,
    directory: &str,
    req: Request<Body>,
    via: Via,
) -> Result<Vec<Stored>, RawError> {
    if let Some(refused) = refusal(raw, repo, Action::Write, via).await {
        return Err(refused);
    }
    let Some(boundary) = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::feed::multipart_boundary)
    else {
        return Err(RawError::BadRequest(
            "upload files as multipart/form-data (or PUT a single file to its path)".into(),
        ));
    };
    let limit = raw.state.upload_limit(repo);
    let overrun = Arc::new(AtomicBool::new(false));
    let guarded = crate::feed::preamble_guard(
        req.into_body().into_data_stream(),
        &boundary,
        overrun.clone(),
    );
    let constraints = multer::Constraints::new()
        .size_limit(multer::SizeLimit::new().per_field(limit.saturating_add(1)));
    let mut form = multer::Multipart::with_constraints(guarded, boundary, constraints);
    let form_error = |e: multer::Error| match e {
        multer::Error::FieldSizeExceeded { .. } => RawError::TooLarge(limit),
        _ if overrun.load(Ordering::Relaxed) => {
            RawError::BadRequest("multipart body: no part within the first 64 KiB".into())
        }
        e => RawError::BadRequest(format!("multipart body: {e}")),
    };

    let mut parts: Vec<FilePart> = Vec::new();
    let mut texts: BTreeMap<String, String> = BTreeMap::new();
    while let Some(mut part) = form.next_field().await.map_err(form_error)? {
        let field = part.name().unwrap_or("").to_string();
        match part.file_name().map(str::to_string) {
            Some(file_name) => {
                if parts.len() == MAX_FILES_PER_UPLOAD {
                    return Err(RawError::BadRequest(format!(
                        "at most {MAX_FILES_PER_UPLOAD} files per upload"
                    )));
                }
                let declared = part.content_type().map(|m| m.to_string());
                let ingested = ingest(raw, part, limit).await?;
                parts.push(FilePart {
                    field,
                    file_name,
                    declared,
                    ingested,
                });
            }
            None => {
                let mut text = Vec::new();
                while let Some(chunk) = part.chunk().await.map_err(form_error)? {
                    text.extend_from_slice(&chunk);
                    if text.len() > MAX_TEXT_FIELD_BYTES {
                        return Err(RawError::BadRequest(format!(
                            "form field {field:?} is longer than {MAX_TEXT_FIELD_BYTES} bytes"
                        )));
                    }
                }
                let text = String::from_utf8(text).map_err(|_| {
                    RawError::BadRequest(format!("form field {field:?} is not UTF-8"))
                })?;
                texts.insert(field, text);
            }
        }
    }
    if parts.is_empty() {
        return Err(RawError::BadRequest("the form holds no file".into()));
    }

    // The fields: a subdirectory, and the names of file parts.
    let mut subdirectory = String::new();
    let fields: HashSet<&str> = parts.iter().map(|p| p.field.as_str()).collect();
    for (name, value) in &texts {
        match name.as_str() {
            "directory" | "raw.directory" => subdirectory = value.clone(),
            other
                if other
                    .strip_suffix(".filename")
                    .is_some_and(|field| fields.contains(field)) => {}
            other => {
                return Err(RawError::BadRequest(format!(
                    "unknown form field {other:?} (file parts, directory and <file field>.filename are accepted)"
                )))
            }
        }
    }
    let base = path::normalize_directory(&subdirectory)
        .map_err(|e| RawError::BadRequest(format!("directory: {e}")))?;
    let directory = format!("{directory}{base}");

    let write = raw
        .state
        .authz
        .package_filter_for(&raw.principal, repo, Action::Write)
        .await;
    let mut seen = HashSet::new();
    let mut pending = Vec::with_capacity(parts.len());
    for part in parts {
        let name = texts
            .get(&format!("{}.filename", part.field))
            .unwrap_or(&part.file_name);
        let target = path::join(&directory, name)
            .map_err(|e| RawError::BadRequest(format!("file name {name:?}: {e}")))?;
        if !seen.insert(target.clone()) {
            return Err(RawError::BadRequest(format!(
                "the form holds {target} twice"
            )));
        }
        if !write.allows(&target) {
            return Err(RawError::Forbidden(format!(
                "you may not upload to {target}"
            )));
        }
        pending.push(Pending {
            content_type: content_type(part.declared.as_deref(), &target),
            path: target,
            ingested: part.ingested,
        });
    }
    record_all(raw, repo, pending).await
}

/// `DELETE /raw/<repo>/<path>` (and the web UI's delete).
pub async fn delete(raw: &Raw<'_>, repo: &Repository, path: &str, via: Via) -> Response {
    match delete_inner(raw, repo, path, via).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn delete_inner(
    raw: &Raw<'_>,
    repo: &Repository,
    path: &str,
    via: Via,
) -> Result<(), RawError> {
    if let Some(refused) = refusal(raw, repo, Action::Delete, via).await {
        return Err(refused);
    }
    let filter = raw
        .state
        .authz
        .package_filter_for(&raw.principal, repo, Action::Delete)
        .await;
    // Outside the caller's selector: as unknown.
    if !filter.allows(path) {
        return Err(RawError::NotFound);
    }
    let Some(file) = raw_dao::find(&raw.state.pool, repo.id, path).await? else {
        return Err(RawError::NotFound);
    };
    let mut tx = raw.state.pool.begin().await?;
    if !raw_dao::delete(&mut tx, repo.id, path, raw.state.config.outbox.grace()).await? {
        return Err(RawError::NotFound);
    }
    record(
        raw,
        repo,
        PackageMutation::Delete,
        path,
        &file.blob_sha256,
        &mut tx,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types_come_from_the_client_or_the_extension() {
        assert_eq!(content_type(Some("text/csv"), "a/b.bin"), "text/csv");
        assert_eq!(
            content_type(Some("text/plain; charset=utf-8"), "a/b.bin"),
            "text/plain; charset=utf-8"
        );
        // curl --data-binary and generic clients say nothing specific.
        for generic in [
            None,
            Some(""),
            Some("application/x-www-form-urlencoded"),
            Some("application/octet-stream"),
            Some("not a type"),
        ] {
            assert_eq!(content_type(generic, "x/readme.txt"), "text/plain");
            assert_eq!(
                content_type(generic, "x/blob.unknown-ext"),
                "application/octet-stream"
            );
        }
        assert_eq!(content_type(None, "x/a.json"), "application/json");
    }
}
