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

use forge_core::auth::principal::Principal;
use forge_core::authz::{Level, PackageFilter};
use forge_db::model::{RepoKind, Repository};
use forge_db::{oci_dao, repository_dao};

use forge_plugin::api::images::{ManifestInfo, Reference, TagPage};

use super::digest::ContentDigest;
use super::dispatch::Caller;
use super::pull::{BlobHit, ManifestHit};
use super::{Failure, ImgResult, Registry};

/// A group's members as its pulls see them, for every image at once: the
/// leaves (hosted and proxy) the caller may read, highest priority first,
/// each with the content filters on its way (every group's below the top
/// one, and its own), and the owning hosted members (see the module doc).
/// [`Self::serving`] decides an image as [`Registry::serving_members`] does
/// it; the browse API decides a whole listing with it.
pub(crate) struct GroupMembers {
    /// A member reached on several ways is listed for each: its filters may
    /// differ.
    leaves: Vec<(Repository, Vec<PackageFilter>)>,
    owners: HashSet<i64>,
    reserved: Vec<String>,
    prefer_hosted: bool,
}

impl GroupMembers {
    /// The owning hosted members, decided whatever the caller may read.
    pub(crate) fn owner_ids(&self) -> Vec<i64> {
        self.owners.iter().copied().collect()
    }

    /// Whether it matters to an image whether an owner has it
    /// (`prefer_hosted`, with owners): see [`Self::owners_only`].
    pub(crate) fn asks_owners(&self) -> bool {
        self.prefer_hosted && !self.owners.is_empty()
    }

    /// Whether only owners serve `image`: it is under one of the group's
    /// reserved prefixes, or an owner has it (`owned`) and the group
    /// prefers hosted members.
    pub(crate) fn owners_only(&self, image: &str, owned: bool) -> bool {
        self.reserved.iter().any(|p| image.starts_with(p.as_str())) || (owned && self.asks_owners())
    }

    /// The leaves the caller may read, highest priority first, with their
    /// position for [`Self::serves`]; whether one serves an image is
    /// [`Self::serves`]'s to say.
    pub(crate) fn leaves(&self) -> impl Iterator<Item = (usize, &Repository)> {
        self.leaves
            .iter()
            .enumerate()
            .map(|(i, (repo, _))| (i, repo))
    }

    /// Whether the leaf at `position` serves `image` (`owners_only`: see
    /// [`Self::owners_only`]). A member reached on several ways serves it
    /// when one of them does; [`Self::serving`] lists it once.
    pub(crate) fn serves(&self, position: usize, image: &str, owners_only: bool) -> bool {
        let (repo, filters) = &self.leaves[position];
        (!owners_only || self.owners.contains(&repo.id))
            && filters.iter().all(|filter| filter.allows(image))
    }

    /// The leaves serving `image`, highest priority first.
    pub(crate) fn serving(&self, image: &str, owners_only: bool) -> Vec<Repository> {
        let mut seen = HashSet::new();
        self.leaves()
            .filter(|(i, _)| self.serves(*i, image, owners_only))
            .filter(|(_, repo)| seen.insert(repo.id))
            .map(|(_, repo)| repo.clone())
            .collect()
    }
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
    pub(crate) async fn serving_members(
        &self,
        caller: &Caller,
        group: &Repository,
        image: &str,
        depth: u32,
    ) -> ImgResult<Vec<Repository>> {
        let members = self.group_members(&caller.principal, group, depth).await?;
        let owners_only = members.owners_only(image, false)
            || (members.asks_owners()
                && !oci_dao::repositories_having_image(
                    &self.inner.pool,
                    &members.owner_ids(),
                    image,
                )
                .await?
                .is_empty());
        Ok(members.serving(image, owners_only))
    }

    /// `group`'s members as its pulls see them, for every image: see
    /// [`GroupMembers`].
    pub(crate) async fn group_members(
        &self,
        principal: &Principal,
        group: &Repository,
        depth: u32,
    ) -> ImgResult<GroupMembers> {
        let mut members = GroupMembers {
            leaves: Vec::new(),
            owners: HashSet::new(),
            reserved: group.reserved_prefixes(),
            prefer_hosted: group.prefer_hosted(),
        };
        let mut path = HashSet::from([group.id]);
        self.walk(
            principal,
            group,
            depth,
            &mut path,
            &[],
            &mut members,
            Walk {
                owning: true,
                serving: true,
            },
        )
        .await?;
        Ok(members)
    }

    /// Collect the leaves that may serve the caller and the owning hosted
    /// members, over the whole membership graph. Owners are decided without
    /// the caller's grants (as in NuGet groups): a caller who cannot read the
    /// hosted copy of an image must get nothing rather than a proxy's image
    /// of the same name. Grants and offline members only decide what serves;
    /// `filters` are the content filters of the groups on the way, which
    /// decide it per image.
    #[allow(clippy::too_many_arguments)]
    fn walk<'a>(
        &'a self,
        principal: &'a Principal,
        group: &'a Repository,
        depth: u32,
        path: &'a mut HashSet<i64>,
        filters: &'a [PackageFilter],
        members: &'a mut GroupMembers,
        walk: Walk,
    ) -> futures_util::future::BoxFuture<'a, ImgResult<()>> {
        Box::pin(async move {
            if depth >= self.inner.config.max_group_depth.max(1) {
                return Ok(());
            }
            let pool = &self.inner.pool;
            let authz = &self.inner.authz;
            let group_members = repository_dao::group_members(pool, group.id).await?;
            let flagged: HashSet<i64> = repository_dao::group_owner_ids(pool, group.id)
                .await?
                .into_iter()
                .collect();
            for (member, _priority) in group_members {
                if !self.serves(&member) || path.contains(&member.id) {
                    continue;
                }
                let serving = walk.serving && authz.can_read(principal, &member).await;
                // What the caller may read of it, on this way.
                let filters: Vec<PackageFilter> = if serving {
                    let mut way = filters.to_vec();
                    way.push(
                        authz
                            .package_filter_for(principal, &member, Level::Read)
                            .await,
                    );
                    way
                } else {
                    Vec::new()
                };
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
                            principal,
                            &member,
                            depth + 1,
                            path,
                            &filters,
                            members,
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
                            members.owners.insert(member.id);
                        }
                        if serving && member.online {
                            members.leaves.push((member, filters));
                        }
                    }
                    RepoKind::Proxy => {
                        if serving {
                            members.leaves.push((member, filters));
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
