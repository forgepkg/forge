//! E2E: importing from a real Nexus Repository 3 OSS container
//! (`sonatype/nexus3`) seeded with NuGet packages, a multi-platform image
//! with a cosign signature and an SBOM. After the import,
//! bytes and digests are Nexus' and so are the publish dates; a second run
//! copies only what was added to Nexus since. (Resuming a killed import, the
//! conflict policies and the dry run are covered against a mock Nexus in
//! `crates/server/tests/nexus_import.rs`.) Gated behind `forge-e2e`; Nexus
//! takes a minute or two to start.

#![cfg(feature = "forge-e2e")]

use std::time::Duration;

use forge_e2e::{make_nupkg, StackBuilder, TestServer};
use forge_server::nexus_import::ImportWorker;
use serde_json::{json, Value};
use sha2::Digest;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const NEXUS_IMAGE: &str = "mirror.gcr.io/sonatype/nexus3";
const NEXUS_TAG: &str = "3.70.1";
/// With `NEXUS_SECURITY_RANDOMPASSWORD=false`, Nexus' admin password.
const ADMIN: (&str, &str) = ("admin", "admin123");

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256(bytes))
}

/// A Nexus with its REST API at `url` and its Docker connector at
/// `registry`.
struct Nexus {
    url: String,
    registry: String,
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
        let nexus = Nexus {
            url: format!("http://{host}:{api}"),
            registry: format!("http://{host}:{registry}"),
            client: reqwest::Client::new(),
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

    /// The components of `repository`, `(name, version)` → asset.
    async fn components(&self, repository: &str) -> Vec<Value> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut path = format!("components?repository={repository}");
            if let Some(t) = &token {
                path.push_str(&format!("&continuationToken={t}"));
            }
            let page: Value = self
                .api(reqwest::Method::GET, &path)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            out.extend(page["items"].as_array().unwrap().iter().cloned());
            match page["continuationToken"].as_str() {
                Some(t) => token = Some(t.to_string()),
                None => return out,
            }
        }
    }

    /// Push a blob to the Docker connector.
    async fn push_blob(&self, image: &str, bytes: &[u8]) {
        let resp = self
            .client
            .post(format!("{}/v2/{image}/blobs/uploads/", self.registry))
            .basic_auth(ADMIN.0, Some(ADMIN.1))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202, "start upload");
        let location = resp.headers()["location"].to_str().unwrap().to_string();
        let location = if location.starts_with("http") {
            location
        } else {
            format!("{}{location}", self.registry)
        };
        let separator = if location.contains('?') { '&' } else { '?' };
        let resp = self
            .client
            .put(format!("{location}{separator}digest={}", digest(bytes)))
            .basic_auth(ADMIN.0, Some(ADMIN.1))
            .header("content-type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "finish upload");
    }

    async fn push_manifest(&self, image: &str, reference: &str, media_type: &str, bytes: &[u8]) {
        let resp = self
            .client
            .put(format!(
                "{}/v2/{image}/manifests/{reference}",
                self.registry
            ))
            .basic_auth(ADMIN.0, Some(ADMIN.1))
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
}

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

/// Start an import of `source` into `repo` and run it to its end.
async fn import(srv: &TestServer, nexus: &Nexus, repo: &str, source: &str) -> Value {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        &format!("/admin/repositories/{repo}/imports"),
        Some(json!({"url": nexus.url, "repository": source, "username": ADMIN.0, "password": ADMIN.1})),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    for _ in 0..600 {
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

    // Docker: a two-platform image, its cosign signature (a tag) and an
    // SBOM pushed by digest (a referrer Nexus lists as an asset only).
    let image = "team/app";
    let mut children = Vec::new();
    for arch in ["amd64", "arm64"] {
        let config = json!({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}).to_string().into_bytes();
        let layer = format!("the {arch} layer").into_bytes();
        nexus.push_blob(image, &config).await;
        nexus.push_blob(image, &layer).await;
        let manifest = json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(&config), "size": config.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest(&layer), "size": layer.len()}],
        })
        .to_string()
        .into_bytes();
        nexus
            .push_manifest(image, &digest(&manifest), OCI_MANIFEST, &manifest)
            .await;
        children.push(json!({"mediaType": OCI_MANIFEST, "digest": digest(&manifest), "size": manifest.len(), "platform": {"architecture": arch, "os": "linux"}}));
    }
    let index = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": children})
        .to_string()
        .into_bytes();
    nexus.push_manifest(image, "1.0", OCI_INDEX, &index).await;
    let empty = b"{}".to_vec();
    nexus.push_blob(image, &empty).await;
    let payload = b"cosign signature payload".to_vec();
    nexus.push_blob(image, &payload).await;
    let subject = json!({"mediaType": OCI_INDEX, "digest": digest(&index), "size": index.len()});
    let signature = json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(&empty), "size": 2},
        "layers": [{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": digest(&payload), "size": payload.len(),
                    "annotations": {"dev.cosignproject.cosign/signature": "MEUCIQ=="}}],
        "subject": subject,
    })
    .to_string()
    .into_bytes();
    let sig_tag = format!("sha256-{}.sig", sha256(&index));
    nexus
        .push_manifest(image, &sig_tag, OCI_MANIFEST, &signature)
        .await;
    let sbom = json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/spdx+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(&empty), "size": 2},
        "layers": [{"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(&empty), "size": 2}],
        "subject": subject,
    })
    .to_string()
    .into_bytes();
    nexus
        .push_manifest(image, &digest(&sbom), OCI_MANIFEST, &sbom)
        .await;

    let srv = StackBuilder::default().start().await;
    create_repo(&srv, json!({"name": "nuget-internal", "kind": "hosted"})).await;
    create_repo(
        &srv,
        json!({"name": "images", "kind": "hosted", "format": "docker"}),
    )
    .await;

    // NuGet: the bytes and the publish dates are Nexus'.
    let done = import(&srv, &nexus, "nuget-internal", "nuget-hosted").await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 2, "{done}");
    assert_eq!(
        download(
            &srv,
            "/v3/nuget-internal/flat/acme.core/1.0.0/acme.core.1.0.0.nupkg"
        )
        .await,
        core
    );
    assert_eq!(
        download(
            &srv,
            "/v3/nuget-internal/flat/acme.web/2.1.0/acme.web.2.1.0.nupkg"
        )
        .await,
        web
    );
    let listed = nexus.components("nuget-hosted").await;
    let core_listed = listed.iter().find(|c| c["name"] == "Acme.Core").unwrap();
    let published = chrono::DateTime::parse_from_rfc3339(
        core_listed["assets"][0]["blobCreated"].as_str().unwrap(),
    )
    .unwrap();
    let created = sqlx::query_scalar!(
        "SELECT c.created_at FROM component c JOIN repository r ON r.id = c.repository_id WHERE r.name = 'nuget-internal' AND c.name = 'acme.core'"
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(created, published);

    // Docker: digests, the children, the signature tag and both referrers.
    let done = import(&srv, &nexus, "images", "docker-hosted").await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["failed"], 0, "{done}");
    let repo_id = forge_db::repository_dao::find_repository_by_name(&srv.pool, "images")
        .await
        .unwrap()
        .unwrap()
        .id;
    let tagged = forge_db::oci_dao::find_tag(&srv.pool, repo_id, image, "1.0")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tagged.manifest.digest, digest(&index));
    for child in &children {
        let d = child["digest"].as_str().unwrap();
        assert!(
            forge_db::oci_dao::find_manifest(&srv.pool, repo_id, image, d)
                .await
                .unwrap()
                .is_some(),
            "child {d}"
        );
    }
    let sig = forge_db::oci_dao::find_tag(&srv.pool, repo_id, image, &sig_tag)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sig.manifest.digest, digest(&signature));
    let mut referrers: Vec<String> =
        forge_db::oci_dao::list_referrers(&srv.pool, repo_id, image, &digest(&index))
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.digest)
            .collect();
    referrers.sort();
    let mut expected = vec![digest(&signature), digest(&sbom)];
    expected.sort();
    assert_eq!(referrers, expected);

    // A second run copies only what is new in Nexus.
    let next = make_nupkg("Acme.Core", "1.1.0");
    nexus
        .upload(
            "nuget-hosted",
            "nuget",
            "acme.core.1.1.0.nupkg",
            next.clone(),
        )
        .await;
    let done = import(&srv, &nexus, "nuget-internal", "nuget-hosted").await;
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["progress"]["imported"], 1, "{done}");
    assert_eq!(done["progress"]["identical"], 2, "{done}");
    assert_eq!(
        download(
            &srv,
            "/v3/nuget-internal/flat/acme.core/1.1.0/acme.core.1.1.0.nupkg"
        )
        .await,
        next
    );
}
