//! Changing the files of a hosted repository: receiving a multipart form
//! (the `form` query), storing files from the request body or the form's
//! parts (`store`), and deleting a file (`remove`), for the format's plugin
//! and for the web UI.
//!
//! An upload is streamed to the staging directory under the repository's
//! upload limit, hashed on the way (SHA-256 and SHA-512 by the CAS, SHA-1
//! and MD5 here, for checksum sidecars), stored content-addressed, and
//! recorded in one transaction with the deployment policy applied under the
//! row lock: a path that exists is replaced only with `allow_redeploy` and
//! the delete permission, and the same content again is accepted as is.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use bytes::Bytes;
use forge_core::auth::principal::{AuthMethod, Principal};
use forge_core::authz::Level;
use forge_core::repo::{PackageMutation, PublishAuthorizationContext, WriteError};
use forge_db::model::{DeploymentPolicy, RepoKind, Repository};
use forge_db::raw_dao::{self, NewRawFile, Redeploy, StoreOutcome};
use forge_plugin::api::files;
use forge_storage::{CasError, StoredBlob};
use futures_util::{Stream, TryStreamExt};
use md5::Md5;
use serde::Serialize;
use sha1::{Digest as _, Sha1};

use super::{FileError, Files};
use crate::dispatch::principal_allows_protocol_mutations;

/// Most files one multipart upload may carry.
pub const MAX_FILES_PER_UPLOAD: usize = 100;

/// Largest text field of a multipart upload.
const MAX_TEXT_FIELD_BYTES: usize = 4096;

/// Who may change files through a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The format's protocol: an API token or a workload identity, as for
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

/// One part of a received form.
pub enum Part {
    /// A file part: its declared name and content type, staged and stored.
    File {
        field: String,
        name: String,
        content_type: Option<String>,
        ingested: Box<Ingested>,
    },
    /// Any other field.
    Text { field: String, value: String },
}

/// A file to store, and where its content comes from.
pub struct Upload {
    pub path: String,
    /// The content type the client declared.
    pub declared: Option<String>,
    pub content: Content,
}

/// The content of an [`Upload`].
pub enum Content {
    /// The request body, still to be read.
    Body(Request<Body>),
    /// Received already (a form's file part).
    Staged(Ingested),
}

/// Stage `body` (at most `limit` bytes) and store it content-addressed.
pub async fn ingest<S, E>(files: &Files<'_>, body: S, limit: u64) -> Result<Ingested, FileError>
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
    let staged = files
        .state
        .cas
        .stage(tokio_util::io::StreamReader::new(body), limit)
        .await
        .map_err(cas_error)?;
    let digests = std::mem::take(&mut *digests.lock().unwrap_or_else(PoisonError::into_inner));
    let stored = files.state.cas.commit(staged).await.map_err(cas_error)?;
    Ok(Ingested {
        stored,
        sha1: hex::encode(digests.sha1.finalize()),
        md5: hex::encode(digests.md5.finalize()),
    })
}

/// An ingest failure as the answer to the request.
pub fn cas_error(error: CasError) -> FileError {
    match error {
        CasError::TooLarge { limit } => FileError::TooLarge(limit),
        CasError::StagingFull { .. } => {
            FileError::Unavailable("temporary staging space is exhausted; retry later".into())
        }
        e if e.is_unavailable() => FileError::Unavailable("object store unavailable".into()),
        CasError::Io(e) => FileError::BadRequest(format!("the upload could not be read: {e}")),
        e => FileError::Internal(format!("store upload: {e}")),
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

/// A path the format named, checked against the store's rules.
fn checked_path(path: &str) -> Result<&str, FileError> {
    files::validate_path(path)
        .map(|()| path)
        .map_err(|e| FileError::Internal(format!("the format named path {path:?}: {e}")))
}

/// Why an upload or delete that needs `level` on `repo` may not happen;
/// `None` when it may.
pub async fn refusal(
    files: &Files<'_>,
    repo: &Repository,
    level: Level,
    via: Via,
) -> Option<FileError> {
    if repo.kind() != RepoKind::Hosted {
        return Some(FileError::MethodNotAllowed(
            "files are uploaded to and deleted from hosted repositories",
        ));
    }
    let credential = match via {
        Via::Protocol => principal_allows_protocol_mutations(&files.principal),
        Via::Browser => {
            matches!(
                files.principal,
                Principal::User { method, .. } if method != AuthMethod::Password
            ) || matches!(files.principal, Principal::Workload { .. })
        }
    };
    if !credential {
        return Some(FileError::CredentialRequired);
    }
    let allowed = match level {
        Level::Delete => files.state.authz.can_delete(&files.principal, repo).await,
        _ => files.state.authz.can_write(&files.principal, repo).await,
    };
    if !allowed {
        return Some(FileError::Denied);
    }
    if repo.deployment_policy() == DeploymentPolicy::ReadOnly {
        return Some(FileError::MethodNotAllowed("the repository is read-only"));
    }
    None
}

/// Record a workload's change in the trusted-publishing ledger, inside the
/// transaction that makes it.
async fn record(
    files: &Files<'_>,
    repo: &Repository,
    action: PackageMutation,
    path: &str,
    sha256: &str,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), FileError> {
    if !matches!(files.principal, Principal::Workload { .. }) {
        return Ok(());
    }
    let context = PublishAuthorizationContext {
        principal: files.principal.clone(),
        action,
        package_id: path.to_string(),
        package_version: sha256.to_string(),
    };
    crate::dispatch::workload_ledger_policy(repo)
        .record_in_transaction(&context, tx)
        .await
        .map_err(|e| match e {
            WriteError::ForbiddenPackage { .. } => FileError::Forbidden(
                "the workload identity may no longer change this repository".into(),
            ),
            other => FileError::Internal(format!("trusted-publishing record: {other}")),
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

/// Record `files` in one transaction: all of them or none. The files are
/// stored in the order of their content's hash, so the blob rows they lock
/// are locked in the order every other writer takes them in; the answer
/// lists them in the order given.
async fn record_all(
    files: &Files<'_>,
    repo: &Repository,
    pending: Vec<Pending>,
) -> Result<Vec<Stored>, FileError> {
    let policy = repo.deployment_policy();
    let replace = files
        .state
        .authz
        .package_filter_for(&files.principal, repo, Level::Delete)
        .await;
    let may_delete = files.state.authz.can_delete(&files.principal, repo).await;
    let grace = files.state.config.outbox.grace();
    let mut tx = files.state.pool.begin().await?;
    let mut order: Vec<usize> = (0..pending.len()).collect();
    order.sort_by(|&a, &b| {
        pending[a]
            .ingested
            .stored
            .sha256
            .cmp(&pending[b].ingested.stored.sha256)
    });
    let mut out: Vec<Option<Stored>> = (0..pending.len()).map(|_| None).collect();
    for index in order {
        let file = &pending[index];
        let stored = &file.ingested.stored;
        let replaceable =
            policy == DeploymentPolicy::AllowRedeploy && may_delete && replace.allows(&file.path);
        let new = NewRawFile {
            path: &file.path,
            sha256: &stored.sha256,
            size: i64::try_from(stored.size).map_err(|_| FileError::TooLarge(stored.size))?,
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
                    return Err(FileError::Forbidden(format!(
                        "{} exists; replacing a file needs the delete permission",
                        file.path
                    )));
                }
                StoreOutcome::Exists => {
                    return Err(FileError::Conflict(format!(
                        "{} exists and the repository does not allow redeploying it",
                        file.path
                    )));
                }
            };
        if status != "unchanged" {
            record(
                files,
                repo,
                PackageMutation::Publish,
                &file.path,
                &stored.sha256,
                &mut tx,
            )
            .await?;
        }
        out[index] = Some(Stored {
            path: file.path.clone(),
            size: stored.size,
            sha256: stored.sha256.clone(),
            status,
        });
    }
    tx.commit().await?;
    Ok(out.into_iter().flatten().collect())
}

/// Store `uploads` in hosted `repo`, all of them or none, with the caller's
/// write permission (and selector) on every path.
pub async fn store(
    files: &Files<'_>,
    repo: &Repository,
    uploads: Vec<Upload>,
    via: Via,
) -> Result<Vec<Stored>, FileError> {
    if let Some(refused) = refusal(files, repo, Level::Write, via).await {
        return Err(refused);
    }
    let write = files
        .state
        .authz
        .package_filter_for(&files.principal, repo, Level::Write)
        .await;
    let mut seen = HashSet::new();
    for upload in &uploads {
        let path = checked_path(&upload.path)?;
        if !seen.insert(path) {
            return Err(FileError::BadRequest(format!(
                "the upload holds {path} twice"
            )));
        }
        if !write.allows(path) {
            return Err(FileError::Forbidden(format!(
                "you may not upload to {path}"
            )));
        }
    }
    let limit = files.state.upload_limit(repo);
    let mut pending = Vec::with_capacity(uploads.len());
    for upload in uploads {
        let ingested = match upload.content {
            Content::Staged(ingested) => ingested,
            Content::Body(req) => {
                let declared_length = req
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                if declared_length.is_some_and(|len| len > limit) {
                    return Err(FileError::TooLarge(limit));
                }
                ingest(files, req.into_body().into_data_stream(), limit).await?
            }
        };
        pending.push(Pending {
            content_type: content_type(upload.declared.as_deref(), &upload.path),
            path: upload.path,
            ingested,
        });
    }
    record_all(files, repo, pending).await
}

/// Receive the `multipart/form-data` body of `req` for hosted `repo`: every
/// file part staged and stored (at most [`MAX_FILES_PER_UPLOAD`], each
/// within the repository's upload limit), every other field read (at most
/// [`MAX_TEXT_FIELD_BYTES`]), in the order of the form.
pub async fn receive_form(
    files: &Files<'_>,
    repo: &Repository,
    req: Request<Body>,
    via: Via,
) -> Result<Vec<Part>, FileError> {
    if let Some(refused) = refusal(files, repo, Level::Write, via).await {
        return Err(refused);
    }
    let Some(boundary) = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::feed::multipart_boundary)
    else {
        return Err(FileError::BadRequest(
            "upload files as multipart/form-data (or PUT a single file to its path)".into(),
        ));
    };
    let limit = files.state.upload_limit(repo);
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
        multer::Error::FieldSizeExceeded { .. } => FileError::TooLarge(limit),
        _ if overrun.load(Ordering::Relaxed) => {
            FileError::BadRequest("multipart body: no part within the first 64 KiB".into())
        }
        e => FileError::BadRequest(format!("multipart body: {e}")),
    };

    let mut parts: Vec<Part> = Vec::new();
    let mut file_parts = 0;
    while let Some(mut part) = form.next_field().await.map_err(form_error)? {
        let field = part.name().unwrap_or("").to_string();
        match part.file_name().map(str::to_string) {
            Some(name) => {
                if file_parts == MAX_FILES_PER_UPLOAD {
                    return Err(FileError::BadRequest(format!(
                        "at most {MAX_FILES_PER_UPLOAD} files per upload"
                    )));
                }
                file_parts += 1;
                let content_type = part.content_type().map(|m| m.to_string());
                let ingested = ingest(files, part, limit).await?;
                parts.push(Part::File {
                    field,
                    name,
                    content_type,
                    ingested: Box::new(ingested),
                });
            }
            None => {
                let mut text = Vec::new();
                while let Some(chunk) = part.chunk().await.map_err(form_error)? {
                    text.extend_from_slice(&chunk);
                    if text.len() > MAX_TEXT_FIELD_BYTES {
                        return Err(FileError::BadRequest(format!(
                            "form field {field:?} is longer than {MAX_TEXT_FIELD_BYTES} bytes"
                        )));
                    }
                }
                let value = String::from_utf8(text).map_err(|_| {
                    FileError::BadRequest(format!("form field {field:?} is not UTF-8"))
                })?;
                parts.push(Part::Text { field, value });
            }
        }
    }
    Ok(parts)
}

/// Delete the file at `path` of hosted `repo`: `false` when there is none
/// the caller may delete (one outside its selector is as unknown).
pub async fn remove(
    files: &Files<'_>,
    repo: &Repository,
    path: &str,
    via: Via,
) -> Result<bool, FileError> {
    if let Some(refused) = refusal(files, repo, Level::Delete, via).await {
        return Err(refused);
    }
    let path = checked_path(path)?;
    let filter = files
        .state
        .authz
        .package_filter_for(&files.principal, repo, Level::Delete)
        .await;
    if !filter.allows(path) {
        return Ok(false);
    }
    let Some(file) = raw_dao::find(&files.state.pool, repo.id, path).await? else {
        return Ok(false);
    };
    let mut tx = files.state.pool.begin().await?;
    if !raw_dao::delete(&mut tx, repo.id, path, files.state.config.outbox.grace()).await? {
        return Ok(false);
    }
    record(
        files,
        repo,
        PackageMutation::Delete,
        path,
        &file.blob_sha256,
        &mut tx,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
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
