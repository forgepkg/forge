//! The indexes the host keeps for the repositories of a format whose
//! descriptor says `indexes` (apt): files made of a repository's packages
//! by the format's plugin ([`FormatPlugin::index`]), signed with the
//! repository's OpenPGP keys ([`signing`]), and stored as the repository's
//! files in the file store.
//!
//! An index is made when a client asks for one of its files
//! ([`Query::Index`]) and what it is made of changed since the generation
//! the repository serves: the listed versions and their packages, the
//! repository's options, its signing keys, and the format's version (the
//! generation's *fingerprint*, kept in `repository_index`). A publish, a
//! delete, an unlist or a key rotation needs no hook of its own: the next
//! `apt-get update` finds the fingerprint changed.
//!
//! A new generation replaces the previous one all at once: its files are
//! stored, the previous generation's other files deleted and the
//! fingerprint recorded in one transaction, which also checks that the
//! packages and keys it was made of are still the repository's (else it is
//! made again). Content-addressed files (apt's `by-hash/` copies) stay for
//! a day after the last generation that named them, for clients that read
//! an older `Release`.
//!
//! Every package is listed, whatever the reader's package selector: an
//! index is signed once for every client, so a selector limits what a
//! reader may download, not what the index names.
//!
//! [`FormatPlugin::index`]: forge_plugin::api::FormatPlugin::index
//! [`Query::Index`]: forge_plugin::api::Query::Index

pub mod signing;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};

use forge_crypto::ExposeSecret;
use forge_db::model::{RepoKind, Repository};
use forge_db::raw_dao::{self, NewRawFile, RawFile, Redeploy};
use forge_db::signing_key_dao::{self, NewSigningKey, SigningKeyRow};
use forge_db::{index_dao, repository_dao};
use forge_plugin::api::{self as protocol, files, SignatureKind};
use forge_plugin::Plugin;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

use crate::state::AppState;
use signing::{Key, KeyInfo, SigningError};

/// Bumped when the host signs or stores indexes differently, so that every
/// repository's index is made again.
const HOST_GENERATION: &str = "1";

/// How long a content-addressed index file outlives the last generation
/// that named it.
const KEEP_CONTENT_ADDRESSED: chrono::Duration = chrono::Duration::days(1);

/// The most an index may hold, its files together.
const MAX_INDEX_BYTES: usize = 1024 * 1024 * 1024;

/// The most files an index may hold.
const MAX_INDEX_FILES: usize = 10_000;

/// Why an index could not be served.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    /// The database or the object store is unavailable.
    #[error("{0}")]
    Unavailable(String),
    /// A failure of Forge or of the plugin.
    #[error("{0}")]
    Internal(String),
}

impl From<sqlx::Error> for IndexError {
    fn from(e: sqlx::Error) -> Self {
        forge_db::observe_error(&e);
        match e {
            sqlx::Error::PoolTimedOut => IndexError::Unavailable("database busy".into()),
            e => IndexError::Internal(format!("database: {e}")),
        }
    }
}

impl From<forge_db::secret_dao::SecretDbError> for IndexError {
    fn from(e: forge_db::secret_dao::SecretDbError) -> Self {
        IndexError::Internal(format!("signing keys: {e}"))
    }
}

impl From<SigningError> for IndexError {
    fn from(e: SigningError) -> Self {
        IndexError::Internal(format!("signing: {e}"))
    }
}

/// One generation made at a time per repository and process; across
/// processes the commit's checks keep the newest.
type Gates = HashMap<i64, Weak<tokio::sync::Mutex<()>>>;
static GATES: LazyLock<Mutex<Gates>> = LazyLock::new(Default::default);

fn gate(repository_id: i64) -> Arc<tokio::sync::Mutex<()>> {
    let mut gates = GATES.lock().unwrap_or_else(PoisonError::into_inner);
    if gates.len() >= 1024 {
        gates.retain(|_, weak| weak.strong_count() > 0);
    }
    if let Some(existing) = gates.get(&repository_id).and_then(Weak::upgrade) {
        return existing;
    }
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    gates.insert(repository_id, Arc::downgrade(&gate));
    gate
}

/// Whether `repo` keeps indexes: a hosted repository of a format with
/// indexes.
pub fn keeps_indexes(state: &AppState, repo: &Repository) -> bool {
    repo.kind() == RepoKind::Hosted
        && state
            .formats
            .plugin(&repo.format)
            .is_some_and(|plugin| plugin.descriptor().indexes)
}

/// The user id of a key Forge makes for `repo`.
fn key_user_id(state: &AppState, repo: &Repository) -> String {
    let host = url::Url::parse(&state.config.public_base_url())
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "forge".into());
    format!("{} (Forge {host})", repo.name)
}

/// Store `key` as a signing key of `repo`. `None` when it has the key
/// already.
pub async fn add_key(
    state: &AppState,
    repo: &Repository,
    key: &Key,
) -> Result<Option<KeyInfo>, IndexError> {
    let info = key.info()?;
    let secret = forge_crypto::PlaintextSecret::from(key.to_sealable()?);
    let mut tx = forge_db::begin(&state.pool).await?;
    let stored = signing_key_dao::insert(
        &mut tx,
        &state.envelope,
        repo.id,
        &NewSigningKey {
            fingerprint: &info.fingerprint,
            algorithm: &info.algorithm,
            user_id: &info.user_id,
            public_key: &info.public_key,
        },
        &secret,
    )
    .await?;
    tx.commit().await?;
    Ok(stored.map(|_| info))
}

/// Generate a key for `repo` and store it.
pub async fn generate_key(state: &AppState, repo: &Repository) -> Result<KeyInfo, IndexError> {
    let user_id = key_user_id(state, repo);
    let key = tokio::task::spawn_blocking(move || Key::generate(&user_id))
        .await
        .map_err(|e| IndexError::Internal(format!("key generation: {e}")))??;
    add_key(state, repo, &key)
        .await?
        .ok_or_else(|| IndexError::Internal("a new key exists already".into()))
}

/// The signing keys of `repo`, a new one generated when it has none.
pub async fn keys(state: &AppState, repo: &Repository) -> Result<Vec<SigningKeyRow>, IndexError> {
    let keys = signing_key_dao::list(&state.pool, repo.id).await?;
    if !keys.is_empty() {
        return Ok(keys);
    }
    let user_id = key_user_id(state, repo);
    let key = tokio::task::spawn_blocking(move || Key::generate(&user_id))
        .await
        .map_err(|e| IndexError::Internal(format!("key generation: {e}")))??;
    let info = key.info()?;
    let secret = forge_crypto::PlaintextSecret::from(key.to_sealable()?);
    let mut tx = forge_db::begin(&state.pool).await?;
    // Locked, so that two first requests store one key, not two.
    repository_dao::lock_repository(&mut *tx, repo.id).await?;
    if signing_key_dao::list(&mut *tx, repo.id).await?.is_empty() {
        signing_key_dao::insert(
            &mut tx,
            &state.envelope,
            repo.id,
            &NewSigningKey {
                fingerprint: &info.fingerprint,
                algorithm: &info.algorithm,
                user_id: &info.user_id,
                public_key: &info.public_key,
            },
            &secret,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(signing_key_dao::list(&state.pool, repo.id).await?)
}

/// The file at `path` of `repo`'s indexes, once they are up to date.
pub async fn file(
    state: &AppState,
    repo: &Repository,
    path: &str,
) -> Result<Option<RawFile>, IndexError> {
    ensure_current(state, repo).await?;
    Ok(raw_dao::find(&state.pool, repo.id, path).await?)
}

/// What a generation is made of, digested.
fn fingerprint(
    plugin: &Plugin,
    repo: &Repository,
    versions: &str,
    keys: &[SigningKeyRow],
) -> String {
    let mut digest = Sha256::new();
    let mut part = |s: &str| {
        digest.update(s.as_bytes());
        digest.update([0x1f]);
    };
    part(HOST_GENERATION);
    part(plugin.descriptor().version);
    part(&repo.name);
    part(versions);
    for (name, value) in repo.format_options() {
        part(&name);
        part(&value);
    }
    for key in keys {
        part(&key.fingerprint);
    }
    hex::encode(digest.finalize())
}

/// Make `repo`'s index again if what it is made of changed.
pub async fn ensure_current(state: &AppState, repo: &Repository) -> Result<(), IndexError> {
    let plugin = state
        .formats
        .plugin(&repo.format)
        .filter(|plugin| plugin.descriptor().indexes)
        .ok_or_else(|| IndexError::Internal(format!("format {} keeps no indexes", repo.format)))?;
    if repo.kind() != RepoKind::Hosted {
        return Err(IndexError::Internal(
            "only hosted repositories keep indexes".into(),
        ));
    }
    let package_path = plugin.descriptor().assets.package;
    let gate = gate(repo.id);
    let _held = gate.lock().await;
    for _ in 0..3 {
        let keys = keys(state, repo).await?;
        let versions = index_dao::versions_digest(&state.pool, repo.id, package_path).await?;
        let fingerprint = fingerprint(&plugin, repo, &versions, &keys);
        if index_dao::current(&state.pool, repo.id).await?.as_deref() == Some(&fingerprint) {
            return Ok(());
        }
        if generate(state, repo, &plugin, &keys, &versions, &fingerprint).await? {
            return Ok(());
        }
    }
    Err(IndexError::Unavailable(
        "the repository kept changing while its index was made; retry".into(),
    ))
}

/// One file to store.
struct Stored {
    path: String,
    content: Vec<u8>,
    content_type: String,
    immutable: bool,
}

/// Make and store a generation. `false` when the repository changed while
/// it was made (nothing was stored).
async fn generate(
    state: &AppState,
    repo: &Repository,
    plugin: &Arc<Plugin>,
    rows: &[SigningKeyRow],
    versions_digest: &str,
    fingerprint: &str,
) -> Result<bool, IndexError> {
    let started = std::time::Instant::now();
    let descriptor = plugin.descriptor();
    let format = state
        .formats
        .for_repository(repo)
        .map_err(|e| IndexError::Internal(e.to_string()))?;

    let mut keys = Vec::with_capacity(rows.len());
    for row in rows {
        let sealed = signing_key_dao::open(&state.envelope, row).await?;
        keys.push(Key::from_sealed(sealed.expose_secret())?);
    }

    let mut versions =
        index_dao::listed_versions(&state.pool, repo.id, descriptor.assets.package).await?;
    versions.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| format.compare_versions(&a.version, &b.version))
    });
    let (keyring, keyring_armored) = signing::keyring(&keys)?;
    let input = protocol::IndexInput {
        packages: versions
            .into_iter()
            .map(|v| protocol::IndexedPackage {
                id: v.name,
                version: v.version,
                version_original: v.version_original,
                summary: v.manifest_summary.map(|s| s.to_string()),
                size: u64::try_from(v.size).unwrap_or(0),
                sha256: v.sha256,
                sha512: v.sha512_base64,
                published: Some(
                    v.created_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, false),
                ),
            })
            .collect(),
        generated: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        keyring,
        keyring_armored,
    };
    let target = protocol::Repository {
        name: repo.name.clone(),
        kind: protocol::RepositoryKind::Hosted,
        base_url: crate::plugins::repository_url(state, &repo.name),
        inline: false,
        options: repo.format_options(),
    };
    let implementation = plugin.implementation().clone();
    let files = tokio::task::spawn_blocking(move || -> Result<Vec<Stored>, IndexError> {
        let made = implementation
            .index(&target, &input)
            .map_err(|e| IndexError::Internal(format!("the format made no index: {e}")))?;
        sign_and_check(made, &keys)
    })
    .await
    .map_err(|e| IndexError::Internal(format!("index: {e}")))??;

    // The content first, outside the transaction.
    let mut ingested = Vec::with_capacity(files.len());
    for file in &files {
        let staged = state
            .cas
            .stage(&file.content[..], file.content.len() as u64)
            .await
            .map_err(cas_error)?;
        let stored = state.cas.commit(staged).await.map_err(cas_error)?;
        let sha1 = hex::encode(Sha1::digest(&file.content));
        let md5 = hex::encode(md5::Md5::digest(&file.content));
        ingested.push((stored, sha1, md5));
    }

    let grace = state.config.outbox.grace();
    let mut tx = forge_db::begin(&state.pool).await?;
    let current = index_dao::lock(&mut tx, repo.id).await?;
    if current == fingerprint {
        // Another process made it meanwhile.
        return Ok(true);
    }
    // Still made of the repository's packages and keys?
    let versions_now =
        index_dao::versions_digest(&mut *tx, repo.id, descriptor.assets.package).await?;
    let keys_now: Vec<String> = signing_key_dao::list(&mut *tx, repo.id)
        .await?
        .into_iter()
        .map(|k| k.fingerprint)
        .collect();
    let keys_then: Vec<String> = rows.iter().map(|k| k.fingerprint.clone()).collect();
    if versions_now != versions_digest || keys_now != keys_then {
        return Ok(false);
    }
    for (file, (stored, sha1, md5)) in files.iter().zip(&ingested) {
        raw_dao::store(
            &mut tx,
            repo.id,
            &NewRawFile {
                path: &file.path,
                sha256: &stored.sha256,
                size: i64::try_from(stored.size).unwrap_or(i64::MAX),
                content_type: &file.content_type,
                sha512_base64: &stored.sha512_base64,
                sha1,
                md5,
                upstream_etag: None,
                upstream_last_modified: None,
                checked: true,
                immutable: file.immutable,
            },
            stored.ingest_token,
            Redeploy::Allow,
            grace,
        )
        .await?;
    }
    let paths: Vec<String> = files.iter().map(|f| f.path.clone()).collect();
    let pruned = index_dao::prune(&mut tx, repo.id, &paths, KEEP_CONTENT_ADDRESSED, grace).await?;
    index_dao::set(&mut tx, repo.id, fingerprint).await?;
    tx.commit().await?;
    tracing::info!(
        repo = %repo.name,
        files = files.len(),
        pruned,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "index made"
    );
    Ok(true)
}

fn cas_error(e: forge_storage::CasError) -> IndexError {
    if e.is_unavailable() {
        IndexError::Unavailable("object store unavailable".into())
    } else {
        IndexError::Internal(format!("store index: {e}"))
    }
}

/// Check what the plugin made (valid, distinct paths; bounded) and add the
/// signed copies.
fn sign_and_check(made: Vec<protocol::IndexFile>, keys: &[Key]) -> Result<Vec<Stored>, IndexError> {
    let bad = |what: String| IndexError::Internal(format!("the format's index: {what}"));
    let mut out = Vec::with_capacity(made.len() + 2);
    for file in made {
        for copy in &file.signed {
            let content = match copy.signature {
                SignatureKind::Cleartext => {
                    let text = std::str::from_utf8(&file.content).map_err(|_| {
                        bad(format!("{} is signed as text but is not UTF-8", file.path))
                    })?;
                    signing::sign_cleartext(keys, text)?
                }
                SignatureKind::Detached => signing::sign_detached(keys, &file.content)?,
            };
            out.push(Stored {
                path: copy.path.clone(),
                content: content.into_bytes(),
                content_type: match copy.signature {
                    SignatureKind::Cleartext => "text/plain; charset=utf-8".into(),
                    SignatureKind::Detached => "application/pgp-signature".into(),
                },
                immutable: false,
            });
        }
        out.push(Stored {
            path: file.path,
            content: file.content,
            content_type: file.content_type,
            immutable: file.immutable,
        });
    }
    if out.len() > MAX_INDEX_FILES {
        return Err(bad(format!("more than {MAX_INDEX_FILES} files")));
    }
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for file in &out {
        files::validate_path(&file.path).map_err(|e| bad(format!("{:?}: {e}", file.path)))?;
        if !seen.insert(file.path.as_str()) {
            return Err(bad(format!("{:?} twice", file.path)));
        }
        let essence = file.content_type.split(';').next().unwrap_or("").trim();
        let content_type_ok = file.content_type.len() <= 127
            && file
                .content_type
                .chars()
                .all(|c| c.is_ascii_graphic() || c == ' ')
            && essence
                .split_once('/')
                .is_some_and(|(t, s)| !t.is_empty() && !s.is_empty());
        if !content_type_ok {
            return Err(bad(format!(
                "{:?} has the content type {:?}",
                file.path, file.content_type
            )));
        }
        total += file.content.len();
    }
    if total > MAX_INDEX_BYTES {
        return Err(bad(format!("larger than {MAX_INDEX_BYTES} bytes")));
    }
    Ok(out)
}
