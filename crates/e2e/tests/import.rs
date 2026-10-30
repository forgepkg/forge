//! E2E: imports through the formats' own protocols, from real sources:
//!
//! * a Nexus Repository 3 OSS container (`sonatype/nexus3`): NuGet through
//!   its hosted repository's v3 feed (`/repository/<name>/index.json`), and
//!   Docker through its connector's catalog, holding more than 100 images,
//!   with a cosign signature and an OCI 1.1 referrer pushed the way
//!   `oras attach` pushes one to a registry without the referrers API (the
//!   referrers tag schema);
//! * a `distribution` registry (`registry:2`): Docker through its catalog;
//! * another Forge: NuGet from a Forge NuGet repository, whose registration
//!   lists each package's SHA-512, so a second run downloads nothing.
//!
//! After an import, bytes and digests are the source's and so are the NuGet
//! publish dates; a second run copies only what was added since. (Resuming
//! a killed import, the conflict policies, the dry run and a source without
//! a search or catalog are covered against a mock source in
//! `crates/server/tests/import.rs`.) Gated behind `forge-e2e`; Nexus takes a
//! minute or two to start.

#![cfg(feature = "forge-e2e")]

use std::time::Duration;

use forge_e2e::{make_nupkg, StackBuilder, TestServer};
use forge_server::import::ImportWorker;
use serde_json::{json, Value};
use sha2::Digest;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const NEXUS_IMAGE: &str = "mirror.gcr.io/sonatype/nexus3";
const NEXUS_TAG: &str = "3.70.1";
/// With `NEXUS_SECURITY_RANDOMPASSWORD=false`, Nexus' admin password.
const ADMIN: (&str, &str) = ("admin", "admin123");

const REGISTRY_IMAGE: &str = "mirror.gcr.io/library/registry";
const REGISTRY_TAG: &str = "2";

/// More images than a catalog page holds (Nexus was reported to stop at
/// 100).
const BULK_IMAGES: usize = 105;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";
const LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256(bytes))
}

// ── Sources ─────────────────────────────────────────────────────────────────

/// A Nexus with its REST API at `url` and its Docker connector at
/// `registry`.
struct Nexus {
    url: String,
    registry: Registry,
    client: reqwest::Client,
}

impl Nexus {
    async fn start() -> (Self, testcontainers::ContainerAsync<GenericImage>) {
        let container = GenericImage::new(NEXUS_IMAGE, NEXUS_TAG)
            .with_exposed_port(8081.tcp())
            .with_exposed_port(8082.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Started Sonatype Nexus"))
            .with_env_var("NEXUS_SECURITY_RANDOMPASSWORD", "false")
            .with_env_var(
                "INSTALL4J_ADD_VM_PARAMS",
                "-Xms512m -Xmx1g -XX:MaxDirectMemorySize=1g",
            )
            .with_startup_timeout(Duration::from_secs(600))
            .start()
            .await
            .expect("start nexus (is Docker running?)");
        let host = container.get_host().await.unwrap();
        let api = container.get_host_port_ipv4(8081).await.unwrap();
        let registry = container.get_host_port_ipv4(8082).await.unwrap();
        let client = reqwest::Client::new();
        let nexus = Nexus {
            url: format!("http://{host}:{api}"),
            registry: Registry {
                url: format!("http://{host}:{registry}"),
                auth: Some(ADMIN),
                client: client.clone(),
            },
            client,
        };
        for _ in 0..300 {
            let up = nexus
                .client
                .get(format!("{}/service/rest/v1/status/writable", nexus.url))
                .send()
                .await
                .is_ok_and(|r| r.status() == 200);
            if up {
                return (nexus, container);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!("nexus never became writable");
    }

    fn api(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}/service/rest/v1/{path}", self.url))
            .basic_auth(ADMIN.0, Some(ADMIN.1))
    }

    async fn seed_repositories(&self) {
        let resp = self
            .api(reqwest::Method::PUT, "security/realms/active")
            .json(&json!(["NexusAuthenticatingRealm", "DockerToken"]))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "realms: {}", resp.status());
        let docker = json!({
            "name": "docker-hosted", "online": true,
            "storage": {"blobStoreName": "default", "strictContentTypeValidation": true, "writePolicy": "allow"},
            "docker": {"v1Enabled": false, "forceBasicAuth": true, "httpPort": 8082},
        });
        let resp = self
            .api(reqwest::Method::POST, "repositories/docker/hosted")
            .json(&docker)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    }

    /// Upload an asset through the components API (`<format>.asset`).
    async fn upload(&self, repository: &str, format: &str, file: &str, bytes: Vec<u8>) {
        let form = reqwest::multipart::Form::new().part(
            format!("{format}.asset"),
            reqwest::multipart::Part::bytes(bytes).file_name(file.to_string()),
        );
        let resp = self
            .api(
                reqwest::Method::POST,
                &format!("components?repository={repository}"),
            )
            .multipart(form)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            204,
            "upload {file}: {}",
            resp.text().await.unwrap()
        );
    }

    /// The service index of the NuGet repository `name`.
    fn feed(&self, name: &str) -> String {
        format!("{}/repository/{name}/index.json", self.url)
    }

    /// GET a document of the NuGet repository `name`'s v3 feed.
    async fn feed_json(&self, name: &str, path: &str) -> Value {
        self.client
            .get(format!("{}/repository/{name}/{path}", self.url))
            .basic_auth(ADMIN.0, Some(ADMIN.1))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// The URL of the resource of `kind` the feed `name` lists.
    async fn resource(&self, name: &str, kind: &str) -> String {
        let index = self.feed_json(name, "index.json").await;
        index["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["@type"].as_str().is_some_and(|t| t.starts_with(kind)))
            .unwrap_or_else(|| panic!("{kind} in {index}"))["@id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// When the feed's registration says `lower` `version` was published.
    async fn published(
        &self,
        name: &str,
        lower: &str,
        version: &str,
    ) -> chrono::DateTime<chrono::FixedOffset> {
        let base = self.resource(name, "RegistrationsBaseUrl").await;
        let url = format!("{}/{lower}/index.json", base.trim_end_matches('/'));
        let registration: Value = self
            .client
            .get(&url)
            .basic_auth(ADMIN.0, Some(ADMIN.1))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let leaves = registration["items"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|page| page["items"].as_array().cloned().unwrap_or_default());
        for leaf in leaves {
            let entry = &leaf["catalogEntry"];
            if entry["version"].as_str() == Some(version) {
                let published = entry["published"].as_str().expect("published");
                return chrono::DateTime::parse_from_rfc3339(published).unwrap();
            }
        }
        panic!("{version} not in {registration}");
    }

    /// Wait until the feed's search finds `n` packages: Nexus indexes an
    /// upload for search a moment after it stored it.
    async fn searchable(&self, name: &str, n: u64) {
        let search = self.resource(name, "SearchQueryService").await;
        for _ in 0..120 {
            let found: Value = self
                .client
                .get(format!(
                    "{search}?q=&take=100&prerelease=true&semVerLevel=2.0.0"
                ))
                .basic_auth(ADMIN.0, Some(ADMIN.1))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if found["totalHits"].as_u64() >= Some(n) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("Nexus' search never found {n} packages in {name}");
    }
}

/// A registry API to push to.
struct Registry {
    url: String,
    auth: Option<(&'static str, &'static str)>,
    client: reqwest::Client,
}

impl Registry {
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let request = self.client.request(method, url);
        match self.auth {
            Some((user, password)) => request.basic_auth(user, Some(password)),
            None => request,
        }
    }

    async fn push_blob(&self, image: &str, bytes: &[u8]) {
        let resp = self
            .request(
                reqwest::Method::POST,
                &format!("{}/v2/{image}/blobs/uploads/", self.url),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202, "start upload");
        let location = resp.headers()["location"].to_str().unwrap().to_string();
        let location = if location.starts_with("http") {
            location
        } else {
            format!("{}{location}", self.url)
        };
        let separator = if location.contains('?') { '&' } else { '?' };
        let resp = self
            .request(
                reqwest::Method::PUT,
                &format!("{location}{separator}digest={}", digest(bytes)),
            )
            .header("content-type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "finish upload");
    }

    async fn push_manifest(&self, image: &str, reference: &str, media_type: &str, bytes: &[u8]) {
        let resp = self
            .request(
                reqwest::Method::PUT,
                &format!("{}/v2/{image}/manifests/{reference}", self.url),
            )
            .header("content-type", media_type)
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            201,
            "manifest {reference}: {}",
            resp.text().await.unwrap()
        );
    }

    /// A one-platform image of `image` with `layer`, pushed under `tag`.
    async fn push_image(&self, image: &str, tag: &str, layer: &[u8]) -> Vec<u8> {
        let config = json!({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}})
            .to_string()
            .into_bytes();
        self.push_blob(image, &config).await;
        self.push_blob(image, layer).await;
        let manifest = json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"mediaType": OCI_CONFIG, "digest": digest(&config), "size": config.len()},
            "layers": [{"mediaType": LAYER, "digest": digest(layer), "size": layer.len()}],
        })
        .to_string()
        .into_bytes();
        self.push_manifest(image, tag, OCI_MANIFEST, &manifest)
            .await;
        manifest
    }

    /// A two-platform image of `image` under `tag`, a cosign signature of
    /// it (`sha256-<digest>.sig`) and an SBOM attached the way `oras attach`
    /// attaches one to a registry without the referrers API: the referrer by
    /// digest, and the index of the subject's referrers under the tag
    /// `sha256-<digest>`. Returns the index, its children's digests, the
    /// signature and the SBOM.
    async fn push_signed_index(
        &self,
        image: &str,
        tag: &str,
    ) -> (Vec<u8>, Vec<String>, Vec<u8>, Vec<u8>) {
        let mut children = Vec::new();
        let mut descriptors = Vec::new();
        for arch in ["amd64", "arm64"] {
            let config = json!({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}})
                .to_string()
                .into_bytes();
            let layer = format!("the {arch} layer of {image}").into_bytes();
            self.push_blob(image, &config).await;
            self.push_blob(image, &layer).await;
            let manifest = json!({
                "schemaVersion": 2, "mediaType": OCI_MANIFEST,
                "config": {"mediaType": OCI_CONFIG, "digest": digest(&config), "size": config.len()},
                "layers": [{"mediaType": LAYER, "digest": digest(&layer), "size": layer.len()}],
            })
            .to_string()
            .into_bytes();
            self.push_manifest(image, &digest(&manifest), OCI_MANIFEST, &manifest)
                .await;
            children.push(digest(&manifest));
            descriptors.push(json!({"mediaType": OCI_MANIFEST, "digest": digest(&manifest), "size": manifest.len(), "platform": {"architecture": arch, "os": "linux"}}));
        }
        let index = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": descriptors})
            .to_string()
            .into_bytes();
        self.push_manifest(image, tag, OCI_INDEX, &index).await;

        let empty = b"{}".to_vec();
        self.push_blob(image, &empty).await;
        let payload = format!("cosign signature payload of {image}").into_bytes();
        self.push_blob(image, &payload).await;
        let signature = json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"mediaType": OCI_EMPTY, "digest": digest(&empty), "size": 2},
            "layers": [{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": digest(&payload), "size": payload.len(),
                        "annotations": {"dev.cosignproject.cosign/signature": "MEUCIQ=="}}],
        })
        .to_string()
        .into_bytes();
        self.push_manifest(
            image,
            &format!("sha256-{}.sig", sha256(&index)),
            OCI_MANIFEST,
            &signature,
        )
        .await;

        let sbom_body =
            format!("{{\"spdxVersion\": \"SPDX-2.3\", \"name\": \"{image}\"}}").into_bytes();
        self.push_blob(image, &sbom_body).await;
        let sbom = json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/spdx+json",
            "config": {"mediaType": OCI_EMPTY, "digest": digest(&empty), "size": 2},
            "layers": [{"mediaType": "application/spdx+json", "digest": digest(&sbom_body), "size": sbom_body.len()}],
            "subject": {"mediaType": OCI_INDEX, "digest": digest(&index), "size": index.len()},
        })
        .to_string()
        .into_bytes();
        self.push_manifest(image, &digest(&sbom), OCI_MANIFEST, &sbom)
            .await;
        let referrers = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [
            {"mediaType": OCI_MANIFEST, "digest": digest(&sbom), "size": sbom.len(), "artifactType": "application/spdx+json"}
        ]})
        .to_string()
        .into_bytes();
        self.push_manifest(
            image,
            &format!("sha256-{}", sha256(&index)),
            OCI_INDEX,
            &referrers,
        )
        .await;
        (index, children, signature, sbom)
    }
}

// ── Forge ───────────────────────────────────────────────────────────────────

async fn admin(
    srv: &TestServer,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    let mut req = srv
        .client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(u, Some(p));
    if let Some(body) = body {
        req = req.json(&body);
    }
    req.send().await.unwrap()
}

/// Start an import into `repo` and run it to its end.
async fn import(srv: &TestServer, repo: &str, body: Value) -> Value {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports"),
        Some(body),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    for _ in 0..1200 {
        ImportWorker::new(srv.state.clone()).tick().await.unwrap();
        let view: Value = admin(
            srv,
            reqwest::Method::GET,
            &format!("/admin/repositories/{repo}/imports/{id}"),
            None,
        )
        .await
        .json()
        .await
        .unwrap();
        if !matches!(view["state"].as_str(), Some("queued" | "running")) {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("import into {repo} did not end");
}

async fn create_repo(srv: &TestServer, body: Value) {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        "/admin/repositories",
        Some(body),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
}

/// The bytes of a Forge download, with the admin's credentials.
async fn download(srv: &TestServer, path: &str) -> Vec<u8> {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}{path}", srv.base_url))
        .basic_auth(u, Some(p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "GET {path}");
    resp.bytes().await.unwrap().to_vec()
}

async fn repository_id(srv: &TestServer, repo: &str) -> i64 {
    forge_db::repository_dao::find_repository_by_name(&srv.pool, repo)
        .await
        .unwrap()
        .unwrap()
        .id
}

/// The image `image` of `repo` holds the signed index `index` with its
/// children, its signature tag, and the SBOM as a referrer.
async fn assert_signed_index(
    srv: &TestServer,
    repo: &str,
    image: &str,
    tag: &str,
    (index, children, signature, sbom): &(Vec<u8>, Vec<String>, Vec<u8>, Vec<u8>),
) {
    let repo_id = repository_id(srv, repo).await;
    let tagged = forge_db::oci_dao::find_tag(&srv.pool, repo_id, image, tag)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{image}:{tag}"));
    assert_eq!(tagged.manifest.digest, digest(index));
    for child in children {
        assert!(
            forge_db::oci_dao::find_manifest(&srv.pool, repo_id, image, child)
                .await
                .unwrap()
                .is_some(),
            "child {child}"
        );
    }
    let sig = forge_db::oci_dao::find_tag(
        &srv.pool,
        repo_id,
        image,
        &format!("sha256-{}.sig", sha256(index)),
    )
    .await
    .unwrap()
    .expect("the signature's tag");
    assert_eq!(sig.manifest.digest, digest(signature));
    let referrers: Vec<String> =
        forge_db::oci_dao::list_referrers(&srv.pool, repo_id, image, &digest(index))
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.digest)
            .collect();
    assert_eq!(referrers, vec![digest(sbom)]);
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_from_a_real_nexus() {
    let (nexus, _container) = Nexus::start().await;
    nexus.seed_repositories().await;

    // NuGet: two packages in the default nuget-hosted repository.
    let core = make_nupkg("Acme.Core", "1.0.0");
    let web = make_nupkg("Acme.Web", "2.1.0");
    nexus
        .upload(
            "nuget-hosted",
            "nuget",
            "acme.core.1.0.0.nupkg",
            core.clone(),
        )
        .await;
    nexus
        .upload("nuget-hosted", "nuget", "acme.web.2.1.0.nupkg", web.clone())
        .await;
    nexus.searchable("nuget-hosted", 2).await;

    // Docker: a signed two-platform image with an SBOM, and more images than
    // a catalog page holds.
    let signed = nexus.registry.push_signed_index("team/app", "1.0").await;
    for i in 0..BULK_IMAGES {
        nexus
            .registry
            .push_image(
                &format!("bulk/img-{i:03}"),
                "1.0",
                format!("layer {i}").as_bytes(),
            )
            .await;
    }

    let srv = StackBuilder::default().start().await;
    create_repo(&srv, json!({"name": "nuget-internal", "kind": "hosted"})).await;
    create_repo(
        &srv,
        json!({"name": "images", "kind": "hosted", "format": "docker"}),
    )
    .await;

    // NuGet: through the feed; the bytes and the publish dates are Nexus'.
    let credentials = |url: String| json!({"url": url, "username": ADMIN.0, "password": ADMIN.1});
    let done = import(
        &srv,
        "nuget-internal",
        credentials(nexus.feed("nuget-hosted")),
    )
    .await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["source_total"], 2, "{done}");
    assert!(
        done["source_server"]
            .as_str()
            .is_some_and(|s| s.starts_with("Nexus/")),
        "{done}"
    );
    assert_eq!(done["progress"]["imported"], 2, "{done}");
    assert_eq!(
        download(
            &srv,
            "/repository/nuget-internal/flat/acme.core/1.0.0/acme.core.1.0.0.nupkg"
        )
        .await,
        core
    );
    assert_eq!(
        download(
            &srv,
            "/repository/nuget-internal/flat/acme.web/2.1.0/acme.web.2.1.0.nupkg"
        )
        .await,
        web
    );
    let published = nexus.published("nuget-hosted", "acme.core", "1.0.0").await;
    let created = sqlx::query_scalar!(
        "SELECT c.created_at FROM component c JOIN repository r ON r.id = c.repository_id WHERE r.name = 'nuget-internal' AND c.name = 'acme.core'"
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(created, published);

    // Docker: through the connector's catalog, every image, the children,
    // the signature tag and the SBOM.
    let done = import(&srv, "images", credentials(nexus.registry.url.clone())).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["failed"], 0, "{done}");
    // Three tags of team/app (1.0, the signature, the referrers tag) and one
    // of each bulk image.
    assert_eq!(
        done["progress"]["imported"],
        3 + BULK_IMAGES as i64,
        "{done}"
    );
    assert_signed_index(&srv, "images", "team/app", "1.0", &signed).await;
    let repo_id = repository_id(&srv, "images").await;
    for i in [0, 99, 100, BULK_IMAGES - 1] {
        let image = format!("bulk/img-{i:03}");
        assert!(
            forge_db::oci_dao::find_tag(&srv.pool, repo_id, &image, "1.0")
                .await
                .unwrap()
                .is_some(),
            "{image}"
        );
    }

    // A second run, in the request form of a Nexus server and repository,
    // copies only what is new in Nexus.
    let next = make_nupkg("Acme.Core", "1.1.0");
    nexus
        .upload(
            "nuget-hosted",
            "nuget",
            "acme.core.1.1.0.nupkg",
            next.clone(),
        )
        .await;
    let mut legacy = credentials(nexus.url.clone());
    legacy["repository"] = json!("nuget-hosted");
    let done = import(&srv, "nuget-internal", legacy).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 1, "{done}");
    assert_eq!(done["progress"]["identical"], 2, "{done}");
    assert_eq!(
        download(
            &srv,
            "/repository/nuget-internal/flat/acme.core/1.1.0/acme.core.1.1.0.nupkg"
        )
        .await,
        next
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_from_a_distribution_registry() {
    let container = GenericImage::new(REGISTRY_IMAGE, REGISTRY_TAG)
        .with_exposed_port(5000.tcp())
        .with_wait_for(WaitFor::message_on_stderr("listening on"))
        .start()
        .await
        .expect("start registry:2 (is Docker running?)");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5000).await.unwrap();
    let registry = Registry {
        url: format!("http://{host}:{port}"),
        auth: None,
        client: reqwest::Client::new(),
    };
    let signed = registry.push_signed_index("team/app", "1.0").await;
    for image in ["team/base", "tools/cli", "tools/lint"] {
        registry.push_image(image, "latest", image.as_bytes()).await;
    }

    let srv = StackBuilder::default().start().await;
    create_repo(
        &srv,
        json!({"name": "images", "kind": "hosted", "format": "docker"}),
    )
    .await;
    let done = import(&srv, "images", json!({"url": registry.url})).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["failed"], 0, "{done}");
    assert_eq!(done["progress"]["imported"], 6, "{done}");
    assert_signed_index(&srv, "images", "team/app", "1.0", &signed).await;

    let done = import(&srv, "images", json!({"url": registry.url})).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["identical"], 6, "{done}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn import_from_another_forge() {
    let srv = StackBuilder::default().start().await;
    create_repo(&srv, json!({"name": "nuget-source", "kind": "hosted"})).await;
    create_repo(&srv, json!({"name": "nuget-copy", "kind": "hosted"})).await;
    let packages = [
        make_nupkg("Acme.Core", "1.0.0"),
        make_nupkg("Acme.Core", "1.1.0-beta.1"),
        make_nupkg("Acme.Web", "2.0.0"),
    ];
    for package in &packages {
        assert_eq!(
            srv.push_nupkg("nuget-source", package.clone())
                .await
                .status(),
            201
        );
    }
    let (user, token) = srv.admin_basic();
    let body = json!({
        "url": format!("{}/repository/nuget-source/index.json", srv.base_url),
        "username": user,
        "password": token,
    });
    let done = import(&srv, "nuget-copy", body.clone()).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 3, "{done}");
    assert_eq!(done["source_total"], 2, "{done}");
    assert_eq!(
        download(
            &srv,
            "/repository/nuget-copy/flat/acme.core/1.1.0-beta.1/acme.core.1.1.0-beta.1.nupkg"
        )
        .await,
        packages[1]
    );

    // Forge lists each package's SHA-512: a second run downloads nothing.
    let downloads = || async {
        sqlx::query_scalar!(
            r#"
            SELECT coalesce(sum(a.download_count), 0)::bigint AS "n!"
            FROM asset a JOIN component c ON c.id = a.component_id
            JOIN repository r ON r.id = c.repository_id
            WHERE r.name = 'nuget-source'
            "#
        )
        .fetch_one(&srv.pool)
        .await
        .unwrap()
    };
    let before = downloads().await;
    let done = import(&srv, "nuget-copy", body).await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["identical"], 3, "{done}");
    assert_eq!(done["progress"]["bytes_copied"], 0, "{done}");
    assert_eq!(downloads().await, before);
}
