//! Group repositories: pulls resolve across members by priority.
//!
//! The caller is served only from members it may read itself (reading a
//! group grants nothing on its members), and an offline hosted member is
//! skipped. The dependency-confusion guard of NuGet groups applies to image
//! names: an image under one of the group's `reserved_prefixes` (e.g.
//! `acme/`), or — with `prefer_hosted`, the default — an image an owning
//! member already has, is never served by a proxy member. Owners are the
//! members flagged `owner`, or every hosted member when none is, decided
//! over the whole group whatever the caller may read: a caller without read
//! on the owner gets nothing, never a proxy's image of the same name.
//!
//! A failing member (an unreachable proxy upstream) does not fail the pull
//! while another member answers it.

use std::collections::HashSet;

use forge_core::authz::Level;
use forge_db::model::{RepoKind, Repository};
use forge_db::{oci_dao, repository_dao};

use forge_plugin::api::images::{ManifestInfo, Reference, TagPage};

use super::digest::ContentDigest;
use super::dispatch::Caller;
use super::pull::{BlobHit, ManifestHit};
use super::{Failure, ImgResult, Registry};

/// A leaf member serving a group pull, in priority order.
struct Leaf {
    repo: Repository,
}

/// What a member reached during a group walk is for.
#[derive(Clone, Copy)]
struct Walk {
    /// Its hosted members own images (the group's guard).
    owning: bool,
    /// The caller may read it, through every group above: it may serve.
    serving: bool,
}

impl Registry {
    /// The leaf members (hosted and proxy) that may serve `image` of `group`
    /// to the caller, highest priority first, guard applied.
    async fn serving_members(
        &self,
        caller: &Caller,
        group: &Repository,
        image: &str,
        depth: u32,
    ) -> ImgResult<Vec<Repository>> {
        let mut leaves = Vec::new();
        let mut owners = HashSet::new();
        let mut path = HashSet::from([group.id]);
        self.walk(
            caller,
            group,
            image,
            depth,
            &mut path,
            &mut leaves,
            &mut owners,
            Walk {
                owning: true,
                serving: true,
            },
        )
        .await?;

        let reserved = group
            .reserved_prefixes()
            .iter()
            .any(|p| image.starts_with(p.as_str()));
        let owner_ids: Vec<i64> = owners.iter().copied().collect();
        let restrict = reserved
            || (group.prefer_hosted()
                && !owner_ids.is_empty()
                && !oci_dao::repositories_having_image(&self.inner.pool, &owner_ids, image)
                    .await?
                    .is_empty());
        let mut seen = HashSet::new();
        Ok(leaves
            .into_iter()
            .filter(|leaf| !restrict || owners.contains(&leaf.repo.id))
            .filter(|leaf| seen.insert(leaf.repo.id))
            .map(|leaf| leaf.repo)
            .collect())
    }

    /// Collect the leaves that may serve the caller and the owning hosted
    /// members, over the whole membership graph. Owners are decided without
    /// the caller's grants (as in NuGet groups): a caller who cannot read the
    /// hosted copy of an image must get nothing rather than a proxy's image
    /// of the same name. Grants and offline members only decide what serves.
    #[allow(clippy::too_many_arguments)]
    fn walk<'a>(
        &'a self,
        caller: &'a Caller,
        group: &'a Repository,
        image: &'a str,
        depth: u32,
        path: &'a mut HashSet<i64>,
        leaves: &'a mut Vec<Leaf>,
        owners: &'a mut HashSet<i64>,
        walk: Walk,
    ) -> futures_util::future::BoxFuture<'a, ImgResult<()>> {
        Box::pin(async move {
            if depth >= self.inner.config.max_group_depth.max(1) {
                return Ok(());
            }
            let pool = &self.inner.pool;
            let members = repository_dao::group_members(pool, group.id).await?;
            let flagged: HashSet<i64> = repository_dao::group_owner_ids(pool, group.id)
                .await?
                .into_iter()
                .collect();
            for (member, _priority) in members {
                if !self.serves(&member) || path.contains(&member.id) {
                    continue;
                }
                let serving = walk.serving
                    && self
                        .rbac_allows(&caller.principal, &member, image, Level::Read)
                        .await;
                // Without flags every hosted member owns; with flags only
                // the flagged ones (and what flagged groups own).
                let owning = walk.owning && (flagged.is_empty() || flagged.contains(&member.id));
                match member.kind() {
                    RepoKind::Group => {
                        if !serving && !owning {
                            continue;
                        }
                        path.insert(member.id);
                        self.walk(
                            caller,
                            &member,
                            image,
                            depth + 1,
                            path,
                            leaves,
                            owners,
                            Walk {
                                owning,
                                // An offline nested group serves nothing.
                                serving: serving && member.online,
                            },
                        )
                        .await?;
                        path.remove(&member.id);
                    }
                    RepoKind::Hosted => {
                        if owning {
                            owners.insert(member.id);
                        }
                        if serving && member.online {
                            leaves.push(Leaf { repo: member });
                        }
                    }
                    RepoKind::Proxy => {
                        if serving {
                            leaves.push(Leaf { repo: member });
                        }
                    }
                }
            }
            Ok(())
        })
    }

    pub(crate) async fn group_manifest(
        &self,
        caller: &Caller,
        group: &Repository,
        image: &str,
        reference: &Reference,
        depth: u32,
    ) -> ImgResult<Option<ManifestHit>> {
        let mut failure: Option<Failure> = None;
        for member in self.serving_members(caller, group, image, depth).await? {
            match self
                .manifest_from(caller, &member, image, reference, depth + 1)
                .await
            {
                Ok(Some(hit)) => return Ok(Some(hit)),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(group = %group.name, member = %member.name, error = %e.message(), "registry group: member failed");
                    failure = Some(e);
                }
            }
        }
        failure.map_or(Ok(None), Err)
    }

    pub(crate) async fn group_blob(
        &self,
        caller: &Caller,
        group: &Repository,
        image: &str,
        digest: &ContentDigest,
        depth: u32,
    ) -> ImgResult<Option<BlobHit>> {
        let mut failure: Option<Failure> = None;
        for member in self.serving_members(caller, group, image, depth).await? {
            match self
                .blob_from(caller, &member, image, digest, depth + 1)
                .await
            {
                Ok(Some(hit)) => return Ok(Some(hit)),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(group = %group.name, member = %member.name, error = %e.message(), "registry group: member failed");
                    failure = Some(e);
                }
            }
        }
        failure.map_or(Ok(None), Err)
    }

    pub(crate) async fn group_tags(
        &self,
        caller: &Caller,
        group: &Repository,
        image: &str,
        last: Option<&str>,
        limit: usize,
        depth: u32,
    ) -> ImgResult<Option<TagPage>> {
        let mut known = false;
        let mut failure: Option<Failure> = None;
        let mut tags: Vec<String> = Vec::new();
        // The smallest last tag of a member page that left tags out: the
        // merged page ends there, since the member's next page may hold
        // tags before the other members' later ones.
        let mut cut: Option<String> = None;
        for member in self.serving_members(caller, group, image, depth).await? {
            match self
                .tags_from(caller, &member, image, last, limit, depth + 1)
                .await
            {
                Ok(Some(page)) => {
                    known = true;
                    if let Some(end) = page.tags.last().filter(|_| page.more) {
                        if cut.as_ref().is_none_or(|cut| end < cut) {
                            cut = Some(end.clone());
                        }
                    }
                    tags.extend(page.tags);
                }
                Ok(None) => {}
                Err(e) => failure = Some(e),
            }
        }
        if !known {
            return failure.map_or(Ok(None), Err);
        }
        tags.sort_unstable();
        tags.dedup();
        let mut more = cut.is_some();
        if let Some(cut) = &cut {
            tags.retain(|t| t <= cut);
        }
        if tags.len() > limit {
            tags.truncate(limit);
            more = true;
        }
        Ok(Some(TagPage { tags, more }))
    }

    pub(crate) async fn group_referrers(
        &self,
        caller: &Caller,
        group: &Repository,
        image: &str,
        subject: &ContentDigest,
        depth: u32,
    ) -> ImgResult<Vec<ManifestInfo>> {
        let mut out: Vec<ManifestInfo> = Vec::new();
        let mut seen = HashSet::new();
        for member in self.serving_members(caller, group, image, depth).await? {
            match self
                .referrers_from(caller, &member, image, subject, depth + 1)
                .await
            {
                Ok(found) => {
                    for r in found {
                        if seen.insert(r.digest.clone()) {
                            out.push(r);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(group = %group.name, member = %member.name, error = %e.message(), "registry group: member failed");
                }
            }
        }
        Ok(out)
    }
}
