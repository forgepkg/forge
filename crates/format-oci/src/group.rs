//! Group repositories: pulls resolve across members by priority.
//!
//! The caller is served only from members it may read itself (reading a
//! group grants nothing on its members), and an offline hosted member is
//! skipped. The dependency-confusion guard of NuGet groups applies to image
//! names: an image under one of the group's `reserved_prefixes` (e.g.
//! `envisia/`), or — with `prefer_hosted`, the default — an image an owning
//! member already has, is never served by a proxy member. Owners are the
//! members flagged `owner`, or every hosted member when none is.
//!
//! A failing member (an unreachable proxy upstream) does not fail the pull
//! while another member answers it.

use std::collections::HashSet;

use forge_core::authz::Action;
use forge_db::model::{RepoKind, Repository};
use forge_db::{oci_dao, repository_dao};

use crate::digest::Digest;
use crate::error::{OciError, OciResult};
use crate::pull::{BlobHit, ManifestHit, ReferrerDescriptor};
use crate::reference::Reference;
use crate::service::{Caller, Registry};

/// A leaf member serving a group pull, in priority order.
struct Leaf {
    repo: Repository,
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
    ) -> OciResult<Vec<Repository>> {
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
            true,
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
        owning: bool,
    ) -> futures_util::future::BoxFuture<'a, OciResult<()>> {
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
                if !member.is_docker() || path.contains(&member.id) {
                    continue;
                }
                if !self
                    .rbac_allows(&caller.principal, &member, image, Action::Read)
                    .await
                {
                    continue;
                }
                // Without flags every hosted member owns; with flags only
                // the flagged ones (and what flagged groups own).
                let member_owns = owning && (flagged.is_empty() || flagged.contains(&member.id));
                match member.kind() {
                    RepoKind::Group => {
                        if !member.online {
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
                            member_owns,
                        )
                        .await?;
                        path.remove(&member.id);
                    }
                    RepoKind::Hosted => {
                        if member_owns {
                            owners.insert(member.id);
                        }
                        if member.online {
                            leaves.push(Leaf { repo: member });
                        }
                    }
                    RepoKind::Proxy => leaves.push(Leaf { repo: member }),
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
    ) -> OciResult<Option<ManifestHit>> {
        let mut failure: Option<OciError> = None;
        for member in self.serving_members(caller, group, image, depth).await? {
            match self
                .manifest_from(caller, &member, image, reference, depth + 1)
                .await
            {
                Ok(Some(hit)) => return Ok(Some(hit)),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(group = %group.name, member = %member.name, error = %e.message, "registry group: member failed");
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
        digest: &Digest,
        depth: u32,
    ) -> OciResult<Option<BlobHit>> {
        let mut failure: Option<OciError> = None;
        for member in self.serving_members(caller, group, image, depth).await? {
            match self
                .blob_from(caller, &member, image, digest, depth + 1)
                .await
            {
                Ok(Some(hit)) => return Ok(Some(hit)),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(group = %group.name, member = %member.name, error = %e.message, "registry group: member failed");
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
    ) -> OciResult<Option<Vec<String>>> {
        let mut known = false;
        let mut failure: Option<OciError> = None;
        let mut tags: Vec<String> = Vec::new();
        for member in self.serving_members(caller, group, image, depth).await? {
            match self
                .tags_from(caller, &member, image, last, limit, depth + 1)
                .await
            {
                Ok(Some(page)) => {
                    known = true;
                    tags.extend(page);
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
        tags.truncate(limit);
        Ok(Some(tags))
    }

    pub(crate) async fn group_referrers(
        &self,
        caller: &Caller,
        group: &Repository,
        image: &str,
        subject: &Digest,
        depth: u32,
    ) -> OciResult<Vec<ReferrerDescriptor>> {
        let mut out: Vec<ReferrerDescriptor> = Vec::new();
        for member in self.serving_members(caller, group, image, depth).await? {
            match self
                .referrers_from(caller, &member, image, subject, depth + 1)
                .await
            {
                Ok(found) => {
                    for r in found {
                        if !out.iter().any(|seen| seen.digest == r.digest) {
                            out.push(r);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(group = %group.name, member = %member.name, error = %e.message, "registry group: member failed");
                }
            }
        }
        Ok(out)
    }
}
