//! Deleting what a hosted repository of an images format (Docker) holds: a
//! tag, a manifest, or a whole image. The registry API deletes tags and
//! manifests too (`DELETE /v2/<image>/manifests/<reference>`), with a
//! registry token; this is the administrators' way, which the web UI's image
//! page takes with their session.
//!
//! `DELETE /admin/repositories/{name}/images?image=<image>[&reference=<tag|digest>]`
//! * `reference` a tag: removes the tag. Its manifest stays, pullable by
//!   digest.
//! * `reference` a digest: deletes the manifest with its tags, and what only
//!   it kept ([`taken_along`]): the manifests an index lists that nothing
//!   else lists or tags, and its referrers (signatures, SBOMs,
//!   attestations), as image retention would take them along. A manifest
//!   a push adds while the delete waits for the image's locks stays, with
//!   what it lists.
//! * no `reference`: deletes the image, every manifest and tag of it, in
//!   batches of [`IMAGE_DELETE_BATCH`] manifests, the newest first, each in
//!   a transaction of its own: an image of tens of thousands of manifests
//!   never keeps them all locked, and a pull waits for one batch at most.
//!   Indexes go before the manifests they list, so an interrupted delete
//!   leaves a smaller image whose indexes are whole, and deleting it again
//!   finishes it. A manifest pushed while the delete runs goes too.
//!
//! An empty `reference` (`reference=`, as a script with an unset variable
//! sends it) is refused (**400**): only its absence deletes the whole image.
//! So is a query key other than `image` and `reference` (`tag=`, `digest=`,
//! `ref=`): a misspelt reference is never taken for its absence.
//! A delete that deadlocks with a push is run once more.
//! Answers `{"manifests": <n>, "tags": <n>}`, what was deleted; **404** when
//! nothing matched. Each delete is in the audit log (`forge::audit`, "image
//! delete") with the image and reference, which the admin change log's path
//! does not name. As after a registry delete, the manifests' configs and
//! layers stay linked to the image, pullable by digest, until the registry
//! sweeper finds them unreferenced and not pushed, mounted or confirmed by a
//! pusher for `docker.unreferenced_blob_ttl_seconds`; a read does not
//! prolong that. The blob outbox deletes a blob no image links any more.
//!
//! `GET /admin/repositories/{name}/images/delete-preview?image=<image>[&reference=<tag|digest>]`
//! says what that delete would remove, and deletes nothing ([`preview`]):
//! the web UI's confirmation asks it, since the image page lists at most
//! 1,000 tags and 1,000 manifests and cannot tell (#546). It takes the same
//! query and refuses what the delete refuses.

use std::collections::{HashMap, HashSet};

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::auth::principal::Principal;
use forge_db::model::{RepoKind, Repository};
use forge_db::oci_dao::{self, RetentionManifest, RetentionTag};
use forge_db::repository_dao;
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::images::digest::ContentDigest;
use crate::state::AppState;

/// Unknown keys are refused (**400**): `?image=app&tag=v1` names no
/// `reference`, and must not delete the whole image.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteQuery {
    #[serde(default)]
    image: String,
    /// A tag or a digest; absent: the whole image. Empty is refused.
    #[serde(default)]
    reference: Option<String>,
}

/// What a delete removed.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Deleted {
    pub manifests: usize,
    pub tags: usize,
}

/// What a [`DeleteQuery`] names.
enum Target<'a> {
    Image,
    Tag(&'a str),
    Manifest(ContentDigest),
}

/// The hosted images repository `name` and what `query` deletes of it, or
/// the refusal (**404** no such repository, **400** otherwise).
async fn target<'a>(
    state: &AppState,
    name: &str,
    query: &'a DeleteQuery,
) -> Result<(Repository, Target<'a>), Response> {
    let repo = match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "repository not found").into_response()),
        Err(e) => return Err(db_error(e)),
    };
    let refused = |why: &'static str| Err((StatusCode::BAD_REQUEST, why).into_response());
    if !state.formats.stores_images(&repo.format) {
        return refused("images are deleted from repositories of images (docker)");
    }
    if repo.kind() != RepoKind::Hosted {
        return refused("image delete is only supported for hosted repositories");
    }
    if query.image.is_empty() {
        return refused("image is required");
    }
    let target = match query.reference.as_deref() {
        Some("") => return refused("reference is empty; leave it out to delete the whole image"),
        // A tag never holds a `:`, a digest always does.
        Some(reference) if reference.contains(':') => match ContentDigest::parse(reference) {
            Some(digest) => Target::Manifest(digest),
            None => return refused("reference is neither a tag nor a digest"),
        },
        Some(tag) => Target::Tag(tag),
        None => Target::Image,
    };
    Ok((repo, target))
}

/// `DELETE /admin/repositories/{name}/images?image=<image>[&reference=<tag|digest>]`
pub async fn delete(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(name): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Response {
    let (repo, target) = match target(&state, &name, &query).await {
        Ok(found) => found,
        Err(refusal) => return refusal,
    };
    let grace = state.config.outbox.grace();
    let (result, what) = match &target {
        Target::Manifest(digest) => (
            retrying_a_deadlock(&query.image, || {
                delete_manifest(&state.pool, repo.id, &query.image, digest.as_str(), grace)
            })
            .await,
            "manifest not found",
        ),
        Target::Tag(tag) => (
            delete_tag(&state, repo.id, &query.image, tag).await,
            "tag not found",
        ),
        Target::Image => (
            delete_image(&state.pool, repo.id, &query.image, grace).await,
            "image not found",
        ),
    };
    let response = match result {
        Ok(deleted) if deleted == Deleted::default() => {
            (StatusCode::NOT_FOUND, what).into_response()
        }
        Ok(deleted) => Json(deleted).into_response(),
        Err(e) => db_error(e),
    };
    tracing::info!(
        target: "forge::audit",
        repo = %repo.name,
        image = %query.image,
        reference = query.reference.as_deref().unwrap_or(""),
        status = response.status().as_u16(),
        principal = %principal.audit_label(),
        "image delete"
    );
    response
}

/// The most tags and indexes a [`DeletePreview`] names; it counts them all.
const PREVIEW_NAMES: usize = 50;

/// What a delete would remove, as of now: the delete itself decides again,
/// under the image's lock.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct DeletePreview {
    /// The manifests it deletes, the one asked for included.
    pub manifests: usize,
    /// Of [`Self::manifests`], those that go along because an index that
    /// goes lists them and nothing that stays needs them.
    pub listed: usize,
    /// Of [`Self::manifests`], the referrers (signatures, SBOMs,
    /// attestations) of a manifest that goes.
    pub referrers: usize,
    /// The tags it deletes, by name: at most [`PREVIEW_NAMES`].
    pub tags: Vec<String>,
    /// How many tags it deletes.
    pub tags_total: usize,
    /// The digests of the indexes that list the manifest asked for and
    /// stay, the newest first: at most [`PREVIEW_NAMES`]. Pulling the
    /// manifest's platform through them fails once it is gone.
    pub indexes: Vec<String>,
    /// How many indexes list it and stay.
    pub indexes_total: usize,
}

/// `GET /admin/repositories/{name}/images/delete-preview?image=<image>[&reference=<tag|digest>]`
///
/// What the `DELETE` of the same query would remove, without removing it;
/// **404** when nothing matches, and the delete's refusals.
pub async fn preview(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Response {
    let (repo, target) = match target(&state, &name, &query).await {
        Ok(found) => found,
        Err(refusal) => return refusal,
    };
    let (tags, manifests) =
        match oci_dao::image_for_delete_preview(&state.pool, repo.id, &query.image).await {
            Ok(image) => image,
            Err(e) => return db_error(e),
        };
    let found = match &target {
        Target::Image => (!manifests.is_empty()).then(|| DeletePreview {
            manifests: manifests.len(),
            tags_total: tags.len(),
            tags: tags
                .iter()
                .take(PREVIEW_NAMES)
                .map(|t| t.tag.clone())
                .collect(),
            ..DeletePreview::default()
        }),
        Target::Tag(tag) => tags.iter().any(|t| t.tag == *tag).then(|| DeletePreview {
            tags: vec![(*tag).to_string()],
            tags_total: 1,
            ..DeletePreview::default()
        }),
        Target::Manifest(digest) => manifests
            .iter()
            .find(|m| m.digest == digest.as_str())
            .map(|m| manifest_preview(&manifests, &tags, m.id)),
    };
    match found {
        Some(preview) => Json(preview).into_response(),
        None => {
            let what = match target {
                Target::Image => "image not found",
                Target::Tag(_) => "tag not found",
                Target::Manifest(_) => "manifest not found",
            };
            (StatusCode::NOT_FOUND, what).into_response()
        }
    }
}

/// What deleting the manifest `target` of an image would remove
/// ([`taken_along`]), and the indexes it would leave listing it.
fn manifest_preview(
    manifests: &[RetentionManifest],
    tags: &[RetentionTag],
    target: i64,
) -> DeletePreview {
    // Nothing arrives while a preview waits: it takes no lock.
    let doomed: HashSet<i64> = taken_along(manifests, tags, target, &HashSet::new())
        .into_iter()
        .collect();
    let doomed_digests: HashSet<&str> = manifests
        .iter()
        .filter(|m| doomed.contains(&m.id))
        .map(|m| m.digest.as_str())
        .collect();
    // A manifest goes along as a referrer of one that goes, or else as one
    // an index that goes lists.
    let referrers = manifests
        .iter()
        .filter(|m| m.id != target && doomed.contains(&m.id))
        .filter(|m| {
            m.subject_digest
                .as_deref()
                .is_some_and(|subject| doomed_digests.contains(subject))
        })
        .count();
    // Tags are in name order; what goes along has none.
    let gone: Vec<&RetentionTag> = tags
        .iter()
        .filter(|t| doomed.contains(&t.manifest_id))
        .collect();
    let digest = manifests
        .iter()
        .find(|m| m.id == target)
        .map(|m| m.digest.as_str());
    // Manifests are in id order: the newest index first.
    let indexes: Vec<&RetentionManifest> = manifests
        .iter()
        .rev()
        .filter(|m| !doomed.contains(&m.id))
        .filter(|m| m.children.iter().any(|c| Some(c.as_str()) == digest))
        .collect();
    DeletePreview {
        manifests: doomed.len(),
        listed: doomed.len() - 1 - referrers,
        referrers,
        tags: gone
            .iter()
            .take(PREVIEW_NAMES)
            .map(|t| t.tag.clone())
            .collect(),
        tags_total: gone.len(),
        indexes: indexes
            .iter()
            .take(PREVIEW_NAMES)
            .map(|m| m.digest.clone())
            .collect(),
        indexes_total: indexes.len(),
    }
}

async fn delete_tag(
    state: &AppState,
    repo_id: i64,
    image: &str,
    tag: &str,
) -> sqlx::Result<Deleted> {
    let mut tx = forge_db::begin(&state.pool).await?;
    let deleted = oci_dao::delete_tag(&mut tx, repo_id, image, tag).await?;
    tx.commit().await?;
    Ok(Deleted {
        manifests: 0,
        tags: usize::from(deleted),
    })
}

/// How many manifests deleting a whole image deletes per transaction.
const IMAGE_DELETE_BATCH: usize = 100;

/// Delete the manifest `digest` with what only it kept. The image's
/// manifests and tags are locked first, so a push cannot tag or list a
/// manifest this decided to delete before it is gone.
///
/// The locking statement alone does not show what to decide on: it waits for
/// a push that holds one of the manifests (an index listing it holds it
/// `FOR SHARE`), and its snapshot predates what that push committed
/// meanwhile, the index included (#560). So the image is read a second time,
/// under the locks: whatever lists or tags a manifest the first statement
/// locked had to commit before the lock was granted, and the second read
/// sees it. A manifest only the second read returns arrived in between; what
/// may list or tag it by now is not known, so it stays, and keeps what it
/// lists and what refers to it.
async fn delete_manifest(
    pool: &sqlx::PgPool,
    repo_id: i64,
    image: &str,
    digest: &str,
    grace: chrono::Duration,
) -> sqlx::Result<Deleted> {
    let mut tx = forge_db::begin(pool).await?;
    let (_, before) = oci_dao::lock_image_for_retention(&mut tx, repo_id, image).await?;
    let (tags, manifests) = oci_dao::lock_image_for_retention(&mut tx, repo_id, image).await?;
    let held: HashSet<i64> = before.iter().map(|m| m.id).collect();
    let arrived: HashSet<i64> = manifests
        .iter()
        .map(|m| m.id)
        .filter(|id| !held.contains(id))
        .collect();
    let doomed = match manifests.iter().find(|m| m.digest == digest) {
        Some(target) => taken_along(&manifests, &tags, target.id, &arrived),
        None => Vec::new(),
    };
    let deleted = oci_dao::delete_locked_manifests(&mut tx, &doomed, grace).await?;
    tx.commit().await?;
    Ok(deleted.into())
}

/// Delete every manifest of the image, with its tags: the newest first, a
/// batch per transaction, and then what a push added meanwhile, until none
/// is left.
async fn delete_image(
    pool: &sqlx::PgPool,
    repo_id: i64,
    image: &str,
    grace: chrono::Duration,
) -> sqlx::Result<Deleted> {
    let mut deleted = Deleted::default();
    loop {
        let ids = oci_dao::image_manifest_ids(pool, repo_id, image).await?;
        if ids.is_empty() {
            return Ok(deleted);
        }
        for batch in ids.chunks(IMAGE_DELETE_BATCH) {
            let done = retrying_a_deadlock(image, || delete_batch(pool, batch, grace)).await?;
            deleted.manifests += done.manifests;
            deleted.tags += done.tags;
        }
    }
}

/// Lock and delete one batch of [`delete_image`], in a transaction.
async fn delete_batch(
    pool: &sqlx::PgPool,
    batch: &[i64],
    grace: chrono::Duration,
) -> sqlx::Result<Deleted> {
    let mut tx = forge_db::begin(pool).await?;
    let locked = oci_dao::lock_manifests(&mut tx, batch).await?;
    let done = oci_dao::delete_locked_manifests(&mut tx, &locked, grace).await?;
    tx.commit().await?;
    Ok(done.into())
}

/// Run `transaction`, and once more when it deadlocked (`40P01`). A delete
/// locks the manifests in id order and a push the manifests its index lists
/// in digest order, so the two can wait for each other; Postgres then aborts
/// one side. The delete's transaction rolled back whole, so running it again
/// is safe, as for a repository delete.
async fn retrying_a_deadlock<F, Fut>(image: &str, transaction: F) -> sqlx::Result<Deleted>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = sqlx::Result<Deleted>>,
{
    match transaction().await {
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("40P01") => {
            tracing::warn!(image, "image delete deadlocked; retrying");
            transaction().await
        }
        other => other,
    }
}

impl From<oci_dao::DeletedManifests> for Deleted {
    fn from(deleted: oci_dao::DeletedManifests) -> Self {
        Deleted {
            manifests: deleted.manifests as usize,
            tags: deleted.tags as usize,
        }
    }
}

/// The manifests deleting `target` deletes, `target` first: with it go the
/// manifests reachable from it (the children an index lists, the referrers
/// whose subject it is, and theirs) that nothing kept still needs. A
/// manifest is kept when it has a tag or is not reachable from `target`; a
/// kept manifest keeps its children and its referrers, as in image
/// retention. So is a manifest of `arrived`, one a push added while the
/// delete waited for the image's locks. `target` itself goes whatever lists
/// it.
pub(crate) fn taken_along(
    manifests: &[RetentionManifest],
    tags: &[RetentionTag],
    target: i64,
    arrived: &HashSet<i64>,
) -> Vec<i64> {
    let by_digest: HashMap<&str, &RetentionManifest> =
        manifests.iter().map(|m| (m.digest.as_str(), m)).collect();
    let mut referrers: HashMap<&str, Vec<&RetentionManifest>> = HashMap::new();
    for m in manifests {
        if let Some(subject) = &m.subject_digest {
            referrers.entry(subject.as_str()).or_default().push(m);
        }
    }
    // What `m` refers to, or what refers to it, and stays or goes with it.
    let dependents = |m: &RetentionManifest| -> Vec<i64> {
        let children = m
            .children
            .iter()
            .filter_map(|c| by_digest.get(c.as_str()).map(|c| c.id));
        let referring = referrers
            .get(m.digest.as_str())
            .into_iter()
            .flatten()
            .map(|r| r.id);
        children.chain(referring).collect()
    };
    let by_id: HashMap<i64, &RetentionManifest> = manifests.iter().map(|m| (m.id, m)).collect();

    let mut reachable: Vec<i64> = vec![target];
    let mut seen: HashSet<i64> = HashSet::from([target]);
    let mut i = 0;
    while i < reachable.len() {
        for next in dependents(by_id[&reachable[i]]) {
            if seen.insert(next) {
                reachable.push(next);
            }
        }
        i += 1;
    }

    let tagged: HashSet<i64> = tags.iter().map(|t| t.manifest_id).collect();
    let mut kept: Vec<i64> = manifests
        .iter()
        .map(|m| m.id)
        .filter(|id| {
            *id != target && (!seen.contains(id) || tagged.contains(id) || arrived.contains(id))
        })
        .collect();
    let mut keeping: HashSet<i64> = kept.iter().copied().collect();
    let mut i = 0;
    while i < kept.len() {
        for next in dependents(by_id[&kept[i]]) {
            if next != target && keeping.insert(next) {
                kept.push(next);
            }
        }
        i += 1;
    }
    reachable.retain(|id| !keeping.contains(id));
    reachable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: i64, children: &[i64], subject: Option<i64>) -> RetentionManifest {
        RetentionManifest {
            id,
            image: "app".into(),
            digest: format!("sha256:{id}"),
            created_at: chrono::Utc::now(),
            untagged_since: None,
            last_pulled_at: None,
            subject_digest: subject.map(|s| format!("sha256:{s}")),
            children: children.iter().map(|c| format!("sha256:{c}")).collect(),
        }
    }

    fn tag(name: &str, manifest_id: i64) -> RetentionTag {
        RetentionTag {
            image: "app".into(),
            tag: name.into(),
            manifest_id,
            digest: format!("sha256:{manifest_id}"),
            updated_at: chrono::Utc::now(),
            last_pulled_at: None,
        }
    }

    /// No manifest arrived while the delete waited.
    fn none() -> HashSet<i64> {
        HashSet::new()
    }

    fn sorted(mut ids: Vec<i64>) -> Vec<i64> {
        ids.sort();
        ids
    }

    #[test]
    fn an_image_manifest_goes_alone() {
        let manifests = [manifest(1, &[], None), manifest(2, &[], None)];
        assert_eq!(
            taken_along(&manifests, &[tag("v1", 1)], 1, &none()),
            vec![1]
        );
    }

    #[test]
    fn an_index_takes_its_platform_manifests_and_referrers() {
        // Index 1 lists 2 and 3; 4 signs the index, 5 is an SBOM of 2.
        let manifests = [
            manifest(1, &[2, 3], None),
            manifest(2, &[], None),
            manifest(3, &[], None),
            manifest(4, &[], Some(1)),
            manifest(5, &[], Some(2)),
            manifest(6, &[], None),
        ];
        let doomed = taken_along(&manifests, &[tag("v1", 1), tag("v2", 6)], 1, &none());
        assert_eq!(doomed[0], 1, "the target first");
        assert_eq!(sorted(doomed), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn what_something_else_keeps_stays() {
        // Index 1 and index 7 both list 2; 3 is tagged itself, and so is
        // the signature 4; 8 is a child of the tagged 3 (a nested index).
        let manifests = [
            manifest(1, &[2, 3], None),
            manifest(2, &[], None),
            manifest(3, &[8], None),
            manifest(4, &[], Some(1)),
            manifest(7, &[2], None),
            manifest(8, &[], None),
        ];
        let tags = [tag("v1", 1), tag("v1-arm", 3), tag("sig", 4)];
        assert_eq!(taken_along(&manifests, &tags, 1, &none()), vec![1]);
    }

    #[test]
    fn a_listed_manifest_goes_when_asked_for() {
        // The platform manifest 2 of the tagged index 1 is deleted by
        // itself, with its referrer 3; the index stays.
        let manifests = [
            manifest(1, &[2], None),
            manifest(2, &[], None),
            manifest(3, &[], Some(2)),
        ];
        assert_eq!(
            sorted(taken_along(&manifests, &[tag("v1", 1)], 2, &none())),
            vec![2, 3]
        );
    }

    /// The confirmation's numbers (#546): what goes with an index, split
    /// into the manifests it lists and the referrers, and every tag on it.
    #[test]
    fn a_preview_counts_what_goes_with_every_tag_on_the_manifest() {
        // Index 1 lists 2 and 3 (3 is tagged); 4 signs the index, 5 is an
        // SBOM of 2.
        let manifests = [
            manifest(1, &[2, 3], None),
            manifest(2, &[], None),
            manifest(3, &[], None),
            manifest(4, &[], Some(1)),
            manifest(5, &[], Some(2)),
        ];
        let tags = [tag("1.0", 1), tag("arm", 3), tag("stable", 1)];
        assert_eq!(
            manifest_preview(&manifests, &tags, 1),
            DeletePreview {
                manifests: 4,
                listed: 1,
                referrers: 2,
                tags: vec!["1.0".into(), "stable".into()],
                tags_total: 2,
                indexes: vec![],
                indexes_total: 0,
            }
        );
    }

    /// The indexes that list the manifest and stay are named, the newest
    /// first, whether tagged or not; the names are bounded, the counts not.
    #[test]
    fn a_preview_names_the_indexes_that_list_the_manifest() {
        let manifests = [
            manifest(1, &[2], None),
            manifest(2, &[], None),
            manifest(3, &[2], None),
        ];
        let preview = manifest_preview(&manifests, &[tag("v1-amd64", 2)], 2);
        assert_eq!(preview.manifests, 1);
        assert_eq!(preview.tags, vec!["v1-amd64".to_string()]);
        assert_eq!(preview.indexes, vec!["sha256:3", "sha256:1"]);
        assert_eq!(preview.indexes_total, 2);

        let mut many = vec![manifest(1, &[], None)];
        many.extend((2..200).map(|id| manifest(id, &[1], None)));
        let tags: Vec<RetentionTag> = (0..120).map(|n| tag(&format!("t{n:03}"), 1)).collect();
        let preview = manifest_preview(&many, &tags, 1);
        assert_eq!(preview.tags.len(), PREVIEW_NAMES);
        assert_eq!(preview.tags[0], "t000");
        assert_eq!(preview.tags_total, 120);
        assert_eq!(preview.indexes.len(), PREVIEW_NAMES);
        assert_eq!(preview.indexes[0], "sha256:199");
        assert_eq!(preview.indexes_total, 198);
    }

    #[test]
    fn a_referrer_goes_without_its_subject() {
        let manifests = [manifest(1, &[], None), manifest(2, &[], Some(1))];
        assert_eq!(
            taken_along(&manifests, &[tag("v1", 1)], 2, &none()),
            vec![2]
        );
    }

    #[test]
    fn what_arrived_while_the_delete_waited_stays_with_what_it_keeps() {
        // Index 1 lists 2 and 3, and 4 signs 3. While the delete of 1
        // waited, a push added the index 5, which lists 2, and 6, a
        // signature of 1: both stay, untagged as they are, and 5 keeps 2.
        let manifests = [
            manifest(1, &[2, 3], None),
            manifest(2, &[], None),
            manifest(3, &[], None),
            manifest(4, &[], Some(3)),
            manifest(5, &[2], None),
            manifest(6, &[], Some(1)),
        ];
        let arrived = HashSet::from([5, 6]);
        assert_eq!(
            sorted(taken_along(&manifests, &[tag("v1", 1)], 1, &arrived)),
            vec![1, 3, 4]
        );
        // The manifest asked for goes even when it only just arrived.
        assert_eq!(
            taken_along(&manifests, &[tag("v1", 1)], 6, &arrived),
            vec![6]
        );
    }
}
