use std::sync::Arc;

use async_trait::async_trait;
use forge_core::authz::{Action, EffectiveSet, RawEffectiveSet, RawGrant, SelectorPatterns};
use forge_core::repo::{
    NupkgLocation, PackageFilteredReadOps, RegistrationEntry, RepoError, RepoReadOps, SearchHit,
    SearchParams, SearchResult, VersionEntry,
};

#[derive(Clone)]
struct FixtureReads {
    ids: Vec<&'static str>,
}

impl FixtureReads {
    fn versions(id: &str) -> Vec<VersionEntry> {
        vec![VersionEntry {
            original_id: id.to_string(),
            version: "1.0.0".to_string(),
            version_original: "1.0.0".to_string(),
            listed: true,
        }]
    }
}

#[async_trait]
impl RepoReadOps for FixtureReads {
    async fn list_versions(&self, _repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        Ok(Self::versions(id))
    }

    async fn resolve_nupkg(
        &self,
        _repo: &str,
        _id: &str,
        _version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        Ok(Some(NupkgLocation {
            blob_s3_key: "blob".to_string(),
            size: 4,
            content_type: "application/octet-stream".to_string(),
        }))
    }

    async fn resolve_nuspec(
        &self,
        _repo: &str,
        _id: &str,
        _version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        Ok(Some(b"xml".to_vec()))
    }

    async fn registration(
        &self,
        _repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        Ok(vec![RegistrationEntry {
            original_id: id.to_string(),
            version: "1.0.0".to_string(),
            listed: true,
            package_hash_sha512_base64: None,
            nuspec_bytes: None,
            manifest_summary: None,
            published: None,
        }])
    }

    async fn search(&self, _repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        let all: Vec<SearchHit> = self
            .ids
            .iter()
            .map(|id| SearchHit {
                original_id: (*id).to_string(),
                latest_version: "1.0.0".to_string(),
                versions: Self::versions(id),
                ..Default::default()
            })
            .collect();
        let total_hits = all.len();
        let hits = all
            .into_iter()
            .skip(params.skip)
            .take(params.effective_take())
            .collect();
        Ok(SearchResult { total_hits, hits })
    }
}

fn company_filter() -> forge_core::authz::PackageFilter {
    EffectiveSet::build(&RawEffectiveSet {
        is_admin: false,
        grants: vec![RawGrant {
            action: Action::Read.as_str().to_string(),
            repo: Some(1),
            selector: Some(SelectorPatterns {
                includes: vec!["company.*".to_string()],
                excludes: vec!["company.secret*".to_string()],
            }),
        }],
    })
    .unwrap()
    .package_filter(1)
}

#[tokio::test]
async fn identifier_reads_hide_excluded_packages_as_absent() {
    let reads = PackageFilteredReadOps::new(
        Arc::new(FixtureReads {
            ids: vec!["Company.Tools", "Other.Lib"],
        }),
        company_filter(),
    );

    assert!(!reads
        .list_versions("repo", "company.tools")
        .await
        .unwrap()
        .is_empty());
    assert!(reads
        .list_versions("repo", "other.lib")
        .await
        .unwrap()
        .is_empty());
    assert!(reads
        .resolve_nupkg("repo", "company.secret.keys", "1.0.0")
        .await
        .unwrap()
        .is_none());
    assert!(reads
        .resolve_nuspec("repo", "other.lib", "1.0.0")
        .await
        .unwrap()
        .is_none());
    assert!(reads
        .registration("repo", "other.lib")
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn search_filters_before_paging_and_total_count() {
    let reads = PackageFilteredReadOps::new(
        Arc::new(FixtureReads {
            ids: vec!["Other.First", "Company.One", "Company.Two", "Other.Last"],
        }),
        company_filter(),
    );
    let result = reads
        .search(
            "repo",
            &SearchParams {
                q: String::new(),
                skip: 1,
                take: 1,
                prerelease: false,
            },
        )
        .await
        .unwrap();

    assert_eq!(result.total_hits, 2);
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].original_id, "Company.Two");
}
