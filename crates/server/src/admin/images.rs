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
//!   attestations), as image retention would take them along.
//! * no `reference`: deletes the image, every manifest and tag of it.
//!
//! An empty `reference` (`reference=`, as a script with an unset variable
//! sends it) is refused (**400**): only its absence deletes the whole image.
//! Answers `{"manifests": <n>, "tags": <n>}`, what was deleted; **404** when
//! nothing matched. Each delete is in the audit log (`forge::audit`, "image
//! delete") with the image and reference, which the admin change log's path
//! does not name. As after a registry delete, the manifests' configs and
//! layers stay linked to the image until the registry sweeper finds them
//! unreferenced, and the blob outbox deletes a blob no image links any more.

use std::collections::{HashMap, HashSet};

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::auth::principal::Principal;
use forge_db::model::RepoKind;
use forge_db::oci_dao::{self, RetentionManifest, RetentionTag};
use forge_db::repository_dao;
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::images::digest::ContentDigest;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
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

/// `DELETE /admin/repositories/{name}/images?image=<image>[&reference=<tag|digest>]`
pub async fn delete(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(name): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Response {
    let repo = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return db_error(e),
    };
    if !state.formats.stores_images(&repo.format) {
        return (
            StatusCode::BAD_REQUEST,
            "images are deleted from repositories of images (docker)",
        )
            .into_response();
    }
    if repo.kind() != RepoKind::Hosted {
        return (
            StatusCode::BAD_REQUEST,
            "image delete is only supported for hosted repositories",
        )
            .into_response();
    }
    if query.image.is_empty() {
        return (StatusCode::BAD_REQUEST, "image is required").into_response();
    }
    if query.reference.as_deref() == Some("") {
        return (
            StatusCode::BAD_REQUEST,
            "reference is empty; leave it out to delete the whole image",
        )
            .into_response();
    }
    let grace = state.config.outbox.grace();
    let (result, what) = match query.reference.as_deref() {
        // A tag never holds a `:`, a digest always does.
        Some(reference) if reference.contains(':') => {
            let Some(digest) = ContentDigest::parse(reference) else {
                return (
                    StatusCode::BAD_REQUEST,
                    "reference is neither a tag nor a digest",
                )
                    .into_response();
            };
            (
                delete_manifests(&state, repo.id, &query.image, Some(digest.as_str()), grace).await,
                "manifest not found",
            )
        }
        Some(tag) => (
            delete_tag(&state, repo.id, &query.image, tag).await,
            "tag not found",
        ),
        None => (
            delete_manifests(&state, repo.id, &query.image, None, grace).await,
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

/// Delete the manifest `digest` with what only it kept, or (`None`) every
/// manifest of the image. The image's manifests and tags are locked first,
/// so a push cannot tag or list a manifest this decided to delete before
/// it is gone.
async fn delete_manifests(
    state: &AppState,
    repo_id: i64,
    image: &str,
    digest: Option<&str>,
    grace: chrono::Duration,
) -> sqlx::Result<Deleted> {
    let mut tx = forge_db::begin(&state.pool).await?;
    let (tags, manifests) = oci_dao::lock_image_for_retention(&mut tx, repo_id, image).await?;
    let doomed = match digest {
        None => manifests.iter().map(|m| m.id).collect(),
        Some(digest) => match manifests.iter().find(|m| m.digest == digest) {
            Some(target) => taken_along(&manifests, &tags, target.id),
            None => Vec::new(),
        },
    };
    let ids: HashSet<i64> = doomed.iter().copied().collect();
    let tag_count = tags.iter().filter(|t| ids.contains(&t.manifest_id)).count();
    for id in &doomed {
        oci_dao::delete_locked_manifest(&mut tx, *id, grace).await?;
    }
    tx.commit().await?;
    Ok(Deleted {
        manifests: doomed.len(),
        tags: tag_count,
    })
}

/// The manifests deleting `target` deletes, `target` first: with it go the
/// manifests reachable from it (the children an index lists, the referrers
/// whose subject it is, and theirs) that nothing kept still needs. A
/// manifest is kept when it has a tag or is not reachable from `target`; a
/// kept manifest keeps its children and its referrers, as in image
/// retention. `target` itself goes whatever lists it.
pub(crate) fn taken_along(
    manifests: &[RetentionManifest],
    tags: &[RetentionTag],
    target: i64,
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
        .filter(|id| *id != target && (!seen.contains(id) || tagged.contains(id)))
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

    fn sorted(mut ids: Vec<i64>) -> Vec<i64> {
        ids.sort();
        ids
    }

    #[test]
    fn an_image_manifest_goes_alone() {
        let manifests = [manifest(1, &[], None), manifest(2, &[], None)];
        assert_eq!(taken_along(&manifests, &[tag("v1", 1)], 1), vec![1]);
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
        let doomed = taken_along(&manifests, &[tag("v1", 1), tag("v2", 6)], 1);
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
        assert_eq!(taken_along(&manifests, &tags, 1), vec![1]);
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
            sorted(taken_along(&manifests, &[tag("v1", 1)], 2)),
            vec![2, 3]
        );
    }

    #[test]
    fn a_referrer_goes_without_its_subject() {
        let manifests = [manifest(1, &[], None), manifest(2, &[], Some(1))];
        assert_eq!(taken_along(&manifests, &[tag("v1", 1)], 2), vec![2]);
    }
}
