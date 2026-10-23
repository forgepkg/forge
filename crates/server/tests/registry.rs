//! Integration tests of the Docker / OCI registry (`/v2`): the token
//! service, hosted push/pull, tags, referrers and deletes, authorization,
//! groups, proxies against a mock upstream registry, admin validation, blob
//! GC and image retention. Requires Docker (Postgres + versitygw via the
//! shared harness), or `FORGE_TEST_DATABASE_URL` / `FORGE_TEST_S3_ENDPOINT`.
//!
//! The full distribution-spec conformance suite and the real `docker` CLI
//! run in CI against a live server (`.github/scripts/oci-conformance.sh`).

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use common::{unique, TestServer};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use serde_json::{json, Value};
use sha2::Digest as _;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// An image config naming a platform, and a manifest over it.
fn image(config: &[u8], layers: &[&[u8]]) -> Vec<u8> {
    json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": sha(config), "size": config.len()},
        "layers": layers.iter().map(|l| json!({"mediaType": LAYER, "digest": sha(l), "size": l.len()})).collect::<Vec<_>>(),
    })
    .to_string()
    .into_bytes()
}

fn config(arch: &str) -> Vec<u8> {
    json!({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}})
        .to_string()
        .into_bytes()
}

// ── Test client ─────────────────────────────────────────────────────────────

/// A registry client following Docker's token flow.
struct Oci {
    base: String,
    client: reqwest::Client,
    creds: Option<(String, String)>,
}

impl Oci {
    fn new(srv: &TestServer, creds: Option<(String, String)>) -> Self {
        Oci {
            base: srv.base_url.clone(),
            client: srv.client(),
            creds,
        }
    }

    /// A registry token for `scopes`.
    async fn token(&self, scopes: &[String]) -> String {
        let mut req = self
            .client
            .get(format!("{}/v2/token", self.base))
            .query(&[("service", "test.local")]);
        for scope in scopes {
            req = req.query(&[("scope", scope)]);
        }
        if let Some((u, p)) = &self.creds {
            req = req.basic_auth(u, Some(p));
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), 200, "token request");
        let body: Value = resp.json().await.unwrap();
        body["token"].as_str().unwrap().to_string()
    }

    async fn bearer(&self, name: &str, actions: &str) -> String {
        format!(
            "Bearer {}",
            self.token(&[format!("repository:{name}:{actions}")]).await
        )
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        actions: &str,
        name: &str,
    ) -> reqwest::RequestBuilder {
        let auth = self.bearer(name, actions).await;
        self.client
            .request(method, format!("{}{path}", self.base))
            .header(AUTHORIZATION, auth)
    }

    /// Push a blob in one request (`POST …?digest=`); returns its digest.
    async fn push_blob(&self, name: &str, bytes: &[u8]) -> String {
        let digest = sha(bytes);
        let resp = self
            .request(
                Method::POST,
                &format!("/v2/{name}/blobs/uploads/"),
                "pull,push",
                name,
            )
            .await
            .query(&[("digest", &digest)])
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "monolithic blob push");
        assert_eq!(resp.headers()["docker-content-digest"], digest.as_str());
        digest
    }

    /// Push a blob in chunks (`POST`, `PATCH`…, `PUT ?digest=`).
    async fn push_blob_chunked(&self, name: &str, chunks: &[&[u8]]) -> String {
        let all: Vec<u8> = chunks.concat();
        let digest = sha(&all);
        let auth = self.bearer(name, "pull,push").await;
        let resp = self
            .client
            .post(format!("{}/v2/{name}/blobs/uploads/", self.base))
            .header(AUTHORIZATION, &auth)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202);
        let mut location = resp.headers()[LOCATION].to_str().unwrap().to_string();
        let mut offset = 0usize;
        for chunk in chunks {
            let resp = self
                .client
                .patch(format!("{}{location}", self.base))
                .header(AUTHORIZATION, &auth)
                .header(
                    "content-range",
                    format!("{}-{}", offset, offset + chunk.len() - 1),
                )
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(chunk.to_vec())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 202, "chunk");
            offset += chunk.len();
            assert_eq!(
                resp.headers()["range"],
                format!("0-{}", offset - 1).as_str()
            );
            location = resp.headers()[LOCATION].to_str().unwrap().to_string();
        }
        let resp = self
            .client
            .put(format!("{}{location}", self.base))
            .header(AUTHORIZATION, &auth)
            .query(&[("digest", &digest)])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "chunked upload finish");
        digest
    }

    async fn put_manifest(
        &self,
        name: &str,
        reference: &str,
        media_type: &str,
        body: &[u8],
    ) -> reqwest::Response {
        self.request(
            Method::PUT,
            &format!("/v2/{name}/manifests/{reference}"),
            "pull,push",
            name,
        )
        .await
        .header(CONTENT_TYPE, media_type)
        .body(body.to_vec())
        .send()
        .await
        .unwrap()
    }

    /// Push a single-platform image (`arch`) with one layer under `tag`;
    /// returns the manifest digest.
    async fn push_image(&self, name: &str, tag: &str, arch: &str, layer: &[u8]) -> String {
        let cfg = config(arch);
        self.push_blob(name, &cfg).await;
        self.push_blob(name, layer).await;
        let manifest = image(&cfg, &[layer]);
        let resp = self.put_manifest(name, tag, OCI_MANIFEST, &manifest).await;
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
        sha(&manifest)
    }

    async fn get(&self, name: &str, path: &str) -> reqwest::Response {
        self.request(Method::GET, &format!("/v2/{name}/{path}"), "pull", name)
            .await
            .send()
            .await
            .unwrap()
    }

    async fn head(&self, name: &str, path: &str) -> reqwest::Response {
        self.request(Method::HEAD, &format!("/v2/{name}/{path}"), "pull", name)
            .await
            .send()
            .await
            .unwrap()
    }

    async fn delete(&self, name: &str, path: &str) -> reqwest::Response {
        self.request(
            Method::DELETE,
            &format!("/v2/{name}/{path}"),
            "delete",
            name,
        )
        .await
        .send()
        .await
        .unwrap()
    }
}

// ── Admin helpers ───────────────────────────────────────────────────────────

async fn admin_post(srv: &TestServer, path: &str, body: Value) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    srv.client()
        .post(format!("{}{path}", srv.base_url))
        .basic_auth(u, Some(p))
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn admin_put(srv: &TestServer, path: &str, body: Value) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    srv.client()
        .put(format!("{}{path}", srv.base_url))
        .basic_auth(u, Some(p))
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn create_repo(srv: &TestServer, body: Value) -> Value {
    let resp = admin_post(srv, "/admin/repositories", body).await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    resp.json().await.unwrap()
}

/// A docker repository name unique to this test binary run (and across
/// runs against one external database).
fn repo_name(prefix: &str) -> String {
    format!("{prefix}-{}-{}", std::process::id(), unique())
}

/// A user and an API token for it.
async fn user_with_token(srv: &TestServer) -> (String, String, i64) {
    let username = format!("dev{}x{}", std::process::id(), unique());
    let resp = admin_post(
        srv,
        "/admin/users",
        json!({"username": username, "password": "pw-pw-pw-pw", "is_admin": false}),
    )
    .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    let token: Value = admin_post(
        srv,
        &format!("/admin/users/{id}/tokens"),
        json!({"name": "t"}),
    )
    .await
    .json()
    .await
    .unwrap();
    (username, token["token"].as_str().unwrap().to_string(), id)
}

/// Grant `actions` on `repo` to the user (through a fresh role).
async fn grant(srv: &TestServer, user_id: i64, repo: &str, actions: &[&str]) {
    let role: Value = admin_post(
        srv,
        "/admin/roles",
        json!({"name": format!("role{}x{}", std::process::id(), unique())}),
    )
    .await
    .json()
    .await
    .unwrap();
    let role_id = role["id"].as_i64().unwrap();
    for action in actions {
        let resp = admin_put(
            srv,
            &format!("/admin/roles/{role_id}/grants"),
            json!({"repository": repo, "action": action}),
        )
        .await;
        assert!(resp.status().is_success(), "grant: {}", resp.status());
    }
    let resp = admin_put(
        srv,
        &format!("/admin/users/{user_id}/roles"),
        json!({"role_id": role_id}),
    )
    .await;
    assert!(resp.status().is_success(), "assign: {}", resp.status());
}

async fn admin_oci(srv: &TestServer) -> Oci {
    let token = srv.admin_token().await;
    Oci::new(srv, Some((srv.admin_user.clone().unwrap(), token)))
}

// ── Token service ───────────────────────────────────────────────────────────

#[tokio::test]
async fn version_check_challenges_and_tokens_authenticate() {
    let srv = common::start().await;
    let client = srv.client();

    let resp = client
        .get(format!("{}/v2/", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.headers()["docker-distribution-api-version"],
        "registry/2.0"
    );
    let challenge = resp.headers()[WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        challenge.starts_with("Bearer realm=\"http://test.local/v2/token\""),
        "{challenge}"
    );
    assert!(challenge.contains("service=\"test.local\""), "{challenge}");

    // `docker login`: Basic with an API token gets a token; the token signs in.
    let oci = admin_oci(&srv).await;
    let token = oci.token(&[]).await;
    let resp = client
        .get(format!("{}/v2/", srv.base_url))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Wrong credentials: 401 with the registry's challenge.
    let resp = client
        .get(format!("{}/v2/token", srv.base_url))
        .query(&[("account", "nobody"), ("service", "test.local")])
        .basic_auth("nobody", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key(WWW_AUTHENTICATE));
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["errors"][0]["code"], "UNAUTHORIZED");

    // `account` without credentials: a login that must fail.
    let resp = client
        .get(format!("{}/v2/token", srv.base_url))
        .query(&[("account", "admin")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // A tampered token is refused with an invalid_token challenge.
    let resp = client
        .get(format!("{}/v2/", srv.base_url))
        .header(AUTHORIZATION, format!("Bearer {}x", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers()[WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .contains("invalid_token"));

    // A registry token is no credential for the rest of the API.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// One token request names at most `MAX_SCOPES` repositories, so an
/// anonymous caller cannot make it run thousands of lookups; a repository
/// named again is one scope, with its actions merged (#200).
#[tokio::test]
async fn token_requests_name_a_bounded_number_of_repositories() {
    use base64::Engine;
    let srv = common::start().await;
    let max = forge_oci::token::MAX_SCOPES;
    let request = |scopes: Vec<String>| {
        let mut req = srv
            .client()
            .get(format!("{}/v2/token", srv.base_url))
            .query(&[("service", "test.local")]);
        for scope in scopes {
            req = req.query(&[("scope", scope)]);
        }
        req.send()
    };
    let distinct = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| format!("repository:team/app{i}:pull"))
            .collect()
    };

    let resp = request(distinct(max + 1)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["errors"][0]["code"], "UNSUPPORTED", "{body}");
    // Space-separated in one value counts the same.
    let resp = request(vec![distinct(max + 1).join(" ")]).await.unwrap();
    assert_eq!(resp.status(), 400);

    assert_eq!(request(distinct(max)).await.unwrap().status(), 200);

    // The same repository a thousand times is one scope.
    let mut repeated = vec!["repository:team/app:push".to_string(); 1000];
    repeated.push("repository:team/app:pull,bogus".into());
    let resp = request(repeated).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let jwt = body["token"].as_str().unwrap();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt.split('.').nth(1).unwrap())
        .unwrap();
    let claims: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(claims["access"].as_array().unwrap().len(), 1, "{claims}");
    assert_eq!(claims["access"][0]["name"], "team/app");
}

#[tokio::test]
async fn tokens_grant_only_what_rbac_allows() {
    let srv = common::start().await;
    let repo = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let (user, secret, user_id) = user_with_token(&srv).await;
    grant(&srv, user_id, &repo, &["read"]).await;

    let decode = |jwt: &str| -> Value {
        use base64::Engine;
        let payload = jwt.split('.').nth(1).unwrap();
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap()
    };
    let reader = Oci::new(&srv, Some((user.clone(), secret.clone())));
    let jwt = reader
        .token(&[
            format!("repository:{repo}/app:pull,push,delete"),
            "repository:unknown-repo/app:pull".to_string(),
        ])
        .await;
    let claims = decode(&jwt);
    assert_eq!(claims["access"][0]["actions"], json!(["pull"]));
    assert_eq!(claims["access"][1]["actions"], json!([]));

    // A push with that token: the permission is missing, not just the
    // scope, so the answer is DENIED.
    let resp = reader
        .put_manifest(
            &format!("{repo}/app"),
            "1",
            OCI_MANIFEST,
            &image(b"{}", &[]),
        )
        .await;
    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["errors"][0]["code"],
        "DENIED"
    );

    // Without credentials: a challenge naming the scope.
    let resp = srv
        .client()
        .get(format!("{}/v2/{repo}/app/tags/list", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let challenge = resp.headers()[WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        challenge.contains(&format!("scope=\"repository:{repo}/app:pull\"")),
        "{challenge}"
    );

    // A browser session never pushes, even an admin's.
    let session = srv
        .login(srv.admin_user.as_deref().unwrap(), "adminpw")
        .await;
    let resp = session
        .apply(
            srv.client()
                .post(format!("{}/v2/{repo}/app/blobs/uploads/", srv.base_url)),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ── Hosted repositories ─────────────────────────────────────────────────────

#[tokio::test]
async fn hosted_push_pull_tags_and_deletes() {
    let srv = common::start().await;
    let repo = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/team/app");

    let cfg = config("arm64");
    oci.push_blob(&name, &cfg).await;
    let layer: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let layer_digest = oci
        .push_blob_chunked(
            &name,
            &[&layer[..40_000], &layer[40_000..90_000], &layer[90_000..]],
        )
        .await;
    assert_eq!(layer_digest, sha(&layer));

    // A manifest naming a blob the image does not have is refused.
    let missing = image(&cfg, &[b"not pushed"]);
    let resp = oci
        .put_manifest(&name, "broken", OCI_MANIFEST, &missing)
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["errors"][0]["code"],
        "MANIFEST_BLOB_UNKNOWN"
    );

    let manifest = image(&cfg, &[&layer]);
    let digest = sha(&manifest);
    let resp = oci
        .put_manifest(&name, "1.0", OCI_MANIFEST, &manifest)
        .await;
    assert_eq!(resp.status(), 201);
    assert_eq!(resp.headers()["docker-content-digest"], digest.as_str());
    assert_eq!(
        resp.headers()[LOCATION],
        format!("/v2/{name}/manifests/{digest}").as_str()
    );
    for tag in ["1.1", "2.0", "latest"] {
        assert_eq!(
            oci.put_manifest(&name, tag, OCI_MANIFEST, &manifest)
                .await
                .status(),
            201
        );
    }

    // Pull by tag and by digest.
    for reference in ["1.0", digest.as_str()] {
        let resp = oci.get(&name, &format!("manifests/{reference}")).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()[CONTENT_TYPE], OCI_MANIFEST);
        assert_eq!(resp.headers()["docker-content-digest"], digest.as_str());
        assert_eq!(resp.bytes().await.unwrap().as_ref(), manifest.as_slice());
    }
    // A blob, whole and by range.
    let resp = oci.get(&name, &format!("blobs/{layer_digest}")).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), layer.as_slice());
    let resp = oci
        .request(
            Method::GET,
            &format!("/v2/{name}/blobs/{layer_digest}"),
            "pull",
            &name,
        )
        .await
        .header("range", "bytes=10-19")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.headers()["content-range"],
        format!("bytes 10-19/{}", layer.len()).as_str()
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &layer[10..20]);

    // Tag listing with pagination.
    let resp = oci.get(&name, "tags/list?n=2").await;
    assert_eq!(resp.status(), 200);
    let link = resp.headers()["link"].to_str().unwrap().to_string();
    assert_eq!(
        link,
        format!("</v2/{name}/tags/list?n=2&last=1.1>; rel=\"next\"")
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({"name": name, "tags": ["1.0", "1.1"]}));
    let body: Value = oci
        .get(&name, "tags/list?n=2&last=1.1")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["tags"], json!(["2.0", "latest"]));

    // The platform was read from the config for display.
    let summary: Value = sqlx::query_scalar("SELECT summary FROM oci_manifest WHERE digest = $1")
        .bind(&digest)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(summary["platform"], "linux/arm64");

    // Deleting a tag leaves the manifest; a referenced blob cannot go.
    assert_eq!(oci.delete(&name, "manifests/1.0").await.status(), 202);
    assert_eq!(oci.get(&name, "manifests/1.0").await.status(), 404);
    assert_eq!(
        oci.get(&name, &format!("manifests/{digest}"))
            .await
            .status(),
        200
    );
    assert_eq!(
        oci.delete(&name, &format!("blobs/{layer_digest}"))
            .await
            .status(),
        409
    );
    // Deleting the manifest removes every tag; then the blob may go.
    assert_eq!(
        oci.delete(&name, &format!("manifests/{digest}"))
            .await
            .status(),
        202
    );
    assert_eq!(oci.get(&name, "manifests/latest").await.status(), 404);
    assert_eq!(
        oci.delete(&name, &format!("blobs/{layer_digest}"))
            .await
            .status(),
        202
    );
    assert_eq!(
        oci.get(&name, &format!("blobs/{layer_digest}"))
            .await
            .status(),
        404
    );
}

/// A hosted docker repository's upload limit bounds every blob pushed to
/// it, in one request or in chunks.
#[tokio::test]
async fn the_repository_upload_limit_bounds_blob_pushes() {
    let srv = common::start().await;
    let repo = repo_name("small");
    let view = create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker", "max_upload_bytes": 1024}),
    )
    .await;
    assert_eq!(view["max_upload_bytes"], 1024);
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/app");

    oci.push_blob(&name, &[1u8; 512]).await;
    let big = vec![2u8; 2048];
    let resp = oci
        .request(
            Method::POST,
            &format!("/v2/{name}/blobs/uploads/"),
            "pull,push",
            &name,
        )
        .await
        .query(&[("digest", sha(&big))])
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(big.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["errors"][0]["code"], "SIZE_INVALID");

    // In chunks: the second chunk takes the blob past the limit.
    let auth = oci.bearer(&name, "pull,push").await;
    let resp = oci
        .client
        .post(format!("{}/v2/{name}/blobs/uploads/", oci.base))
        .header(AUTHORIZATION, &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let location = resp.headers()[LOCATION].to_str().unwrap().to_string();
    let resp = oci
        .client
        .patch(format!("{}{location}", oci.base))
        .header(AUTHORIZATION, &auth)
        .header("content-range", "0-599")
        .body(vec![3u8; 600])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let location = resp.headers()[LOCATION].to_str().unwrap().to_string();
    let resp = oci
        .client
        .patch(format!("{}{location}", oci.base))
        .header(AUTHORIZATION, &auth)
        .header("content-range", "600-1199")
        .body(vec![3u8; 600])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

/// With the local blob cache, a blob pushed in several chunks is cached
/// once, assembled, without its chunks; one streamed in a single `PATCH`,
/// as docker, podman and containerd push a layer, is written through.
#[tokio::test]
async fn chunked_uploads_cache_the_blob_not_its_chunks() {
    let dir = tempfile::tempdir().unwrap();
    // A fixed size, and no free space to keep: the cache fills however full
    // the test machine's disk is.
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", unique()), "adminpw".into())),
            plugins_block: Some(format!(
                "[blob_cache]\npath = {:?}\nmax_bytes = 1048576\nmin_free_bytes = 0\n",
                dir.path().join("cache").display().to_string()
            )),
            ..Default::default()
        },
    )
    .await;
    let cache = srv
        .state
        .blob_store
        .cache()
        .expect("the blob cache")
        .clone();
    let cached = |digest: &str| cache.contains(digest.trim_start_matches("sha256:"));
    let eventually_cached = |digest: String| {
        let cache = cache.clone();
        async move {
            for _ in 0..200 {
                if cache.contains(digest.trim_start_matches("sha256:")) {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            false
        }
    };
    let repo = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/app");

    let chunks: Vec<Vec<u8>> = (0..3)
        .map(|i| format!("chunk {i} of a layer {}", unique()).into_bytes())
        .collect();
    let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    let digest = oci.push_blob_chunked(&name, &refs).await;
    assert!(
        eventually_cached(digest.clone()).await,
        "the assembled blob"
    );
    for chunk in &chunks {
        assert!(!cached(&sha(chunk)), "a chunk stays out of the cache");
    }

    let layer = format!("a layer in one chunk {}", unique()).into_bytes();
    let digest = oci.push_blob_chunked(&name, &[&layer]).await;
    assert!(
        eventually_cached(digest).await,
        "a single chunk is the blob"
    );
}

#[tokio::test]
async fn bad_digests_and_out_of_order_chunks_are_refused() {
    let srv = common::start().await;
    let repo = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/app");

    let resp = oci
        .request(
            Method::POST,
            &format!("/v2/{name}/blobs/uploads/"),
            "pull,push",
            &name,
        )
        .await
        .query(&[("digest", sha(b"something else"))])
        .body(b"content".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["errors"][0]["code"],
        "DIGEST_INVALID"
    );

    let manifest = image(b"{}", &[]);
    let resp = oci
        .put_manifest(&name, &sha(b"not the manifest"), OCI_MANIFEST, &manifest)
        .await;
    assert_eq!(resp.status(), 400);

    // A chunk that does not continue the upload: 416 with the current range.
    let auth = oci.bearer(&name, "pull,push").await;
    let resp = srv
        .client()
        .post(format!("{}/v2/{name}/blobs/uploads/", srv.base_url))
        .header(AUTHORIZATION, &auth)
        .send()
        .await
        .unwrap();
    let location = resp.headers()[LOCATION].to_str().unwrap().to_string();
    let resp = srv
        .client()
        .patch(format!("{}{location}", srv.base_url))
        .header(AUTHORIZATION, &auth)
        .header("content-range", "5-9")
        .body(b"12345".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers()["range"], "0-0");
    // The session survives and can be cancelled.
    let resp = srv
        .client()
        .delete(format!("{}{location}", srv.base_url))
        .header(AUTHORIZATION, &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = srv
        .client()
        .get(format!("{}{location}", srv.base_url))
        .header(AUTHORIZATION, &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn immutable_tags_refuse_moving_a_tag_but_latest_may_move() {
    let srv = common::start().await;
    let repo = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker", "immutable_tags": true, "latest_mutable": true}),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/app");
    oci.push_image(&name, "1.0", "amd64", b"layer one").await;
    oci.push_image(&name, "latest", "amd64", b"layer one").await;

    let cfg = config("amd64");
    oci.push_blob(&name, b"layer two").await;
    let other = image(&cfg, &[b"layer two"]);
    let resp = oci.put_manifest(&name, "1.0", OCI_MANIFEST, &other).await;
    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["errors"][0]["code"],
        "DENIED"
    );
    // Re-pushing the same manifest under the tag is fine; `latest` moves.
    assert_eq!(
        oci.put_manifest(&name, "1.0", OCI_MANIFEST, &image(&cfg, &[b"layer one"]))
            .await
            .status(),
        201
    );
    assert_eq!(
        oci.put_manifest(&name, "latest", OCI_MANIFEST, &other)
            .await
            .status(),
        201
    );
    let resp = oci.get(&name, "manifests/latest").await;
    assert_eq!(
        resp.headers()["docker-content-digest"],
        sha(&other).as_str()
    );
}

#[tokio::test]
async fn multi_arch_index_and_referrers() {
    let srv = common::start().await;
    let repo = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/multi");

    let amd = oci
        .push_image(&name, "amd64-only", "amd64", b"amd layer")
        .await;
    let arm = oci
        .push_image(&name, "arm64-only", "arm64", b"arm layer")
        .await;
    let index = json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [
            {"mediaType": OCI_MANIFEST, "digest": amd, "size": 1, "platform": {"architecture": "amd64", "os": "linux"}},
            {"mediaType": OCI_MANIFEST, "digest": arm, "size": 1, "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}},
        ]
    })
    .to_string()
    .into_bytes();
    let resp = oci.put_manifest(&name, "1.0", OCI_INDEX, &index).await;
    assert_eq!(resp.status(), 201);
    let index_digest = sha(&index);

    // An index naming a manifest the image lacks is refused.
    let bad = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [
        {"mediaType": OCI_MANIFEST, "digest": sha(b"nope"), "size": 1}
    ]})
    .to_string()
    .into_bytes();
    assert_eq!(
        oci.put_manifest(&name, "bad", OCI_INDEX, &bad)
            .await
            .status(),
        400
    );

    // A signature-like artifact referring to the index.
    let empty_cfg = b"{}";
    let sig = json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": "application/vnd.dev.cosign.artifact.sig.v1+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": sha(empty_cfg), "size": 2},
        "layers": [],
        "subject": {"mediaType": OCI_INDEX, "digest": index_digest, "size": index.len()},
        "annotations": {"dev.cosignproject.cosign/signature": "MEUCIQ"}
    })
    .to_string()
    .into_bytes();
    // The empty config need not have been uploaded.
    let resp = oci
        .put_manifest(&name, &sha(&sig), OCI_MANIFEST, &sig)
        .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let resp = oci
        .put_manifest(&name, &sha(&sig), OCI_MANIFEST, &sig)
        .await;
    assert_eq!(resp.headers()["oci-subject"], index_digest.as_str());

    let resp = oci.get(&name, &format!("referrers/{index_digest}")).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()[CONTENT_TYPE], OCI_INDEX);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(body["manifests"][0]["digest"], sha(&sig));
    assert_eq!(
        body["manifests"][0]["artifactType"],
        "application/vnd.dev.cosign.artifact.sig.v1+json"
    );
    assert_eq!(
        body["manifests"][0]["annotations"]["dev.cosignproject.cosign/signature"],
        "MEUCIQ"
    );
    let filtered = oci
        .get(
            &name,
            &format!("referrers/{index_digest}?artifactType=application/other"),
        )
        .await;
    assert_eq!(filtered.headers()["oci-filters-applied"], "artifactType");
    assert_eq!(
        filtered.json::<Value>().await.unwrap()["manifests"],
        json!([])
    );

    // The browse API shows the index with its platforms.
    let session = srv
        .login(srv.admin_user.as_deref().unwrap(), "adminpw")
        .await;
    let detail: Value = session
        .apply(
            srv.client()
                .get(format!("{}/browse/images/{repo}/multi", srv.base_url)),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tag = detail["tags"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tag"] == "1.0")
        .unwrap();
    assert_eq!(tag["platforms"], json!(["linux/amd64", "linux/arm64/v8"]));
    assert_eq!(detail["pull_name"], format!("test.local/{repo}/multi"));
}

#[tokio::test]
async fn cross_repository_mount_needs_read_on_the_source() {
    let srv = common::start().await;
    let a = repo_name("dock");
    let b = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": a, "kind": "hosted", "format": "docker"}),
    )
    .await;
    create_repo(
        &srv,
        json!({"name": b, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let admin = admin_oci(&srv).await;
    let digest = admin.push_blob(&format!("{a}/src"), b"shared layer").await;

    // A user who may push to b but not read a cannot mount from a.
    let (user, secret, user_id) = user_with_token(&srv).await;
    grant(&srv, user_id, &b, &["read", "write"]).await;
    let dev = Oci::new(&srv, Some((user, secret)));
    let target = format!("{b}/dst");
    let token = dev
        .token(&[
            format!("repository:{target}:pull,push"),
            format!("repository:{a}/src:pull"),
        ])
        .await;
    let mount = |token: String| {
        let client = srv.client();
        let url = format!("{}/v2/{target}/blobs/uploads/", srv.base_url);
        let digest = digest.clone();
        let from = format!("{a}/src");
        async move {
            client
                .post(url)
                .query(&[("mount", digest.as_str()), ("from", from.as_str())])
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .send()
                .await
                .unwrap()
        }
    };
    assert_eq!(mount(token).await.status(), 202, "falls back to an upload");

    // The admin can.
    let token = admin
        .token(&[
            format!("repository:{target}:pull,push"),
            format!("repository:{a}/src:pull"),
        ])
        .await;
    let resp = mount(token).await;
    assert_eq!(resp.status(), 201);
    assert_eq!(
        admin
            .get(&target, &format!("blobs/{digest}"))
            .await
            .status(),
        200
    );
    // One blob, one reference per image that links it.
    let refs: i64 = sqlx::query_scalar("SELECT ref_count FROM blob WHERE sha256 = $1")
        .bind(digest.trim_start_matches("sha256:"))
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert!(refs >= 2, "{refs}");

    // An offline source serves nothing, mounts included.
    let digest = admin.push_blob(&format!("{a}/src"), b"another layer").await;
    let resp = admin_put(
        &srv,
        &format!("/admin/repositories/{a}"),
        json!({"online": false}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let token = admin
        .token(&[
            format!("repository:{target}:pull,push"),
            format!("repository:{a}/src:pull"),
        ])
        .await;
    let resp = srv
        .client()
        .post(format!("{}/v2/{target}/blobs/uploads/", srv.base_url))
        .query(&[("mount", digest.as_str()), ("from", &format!("{a}/src"))])
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "falls back to an upload");
}

#[tokio::test]
async fn host_based_routing_serves_a_repository_at_the_root() {
    let srv = common::start().await;
    let repo = repo_name("dock");
    let host = format!("{repo}.registry.test");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker", "host": host}),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let digest = oci
        .push_image(&format!("{repo}/app"), "1", "amd64", b"hb layer")
        .await;

    // On its own host the image has its short name, and tokens are issued
    // for that host.
    let token: Value = srv
        .client()
        .get(format!("{}/v2/token", srv.base_url))
        .header(header::HOST, &host)
        .query(&[("scope", "repository:app:pull")])
        .basic_auth(
            srv.admin_user.clone().unwrap(),
            Some(oci.creds.as_ref().unwrap().1.clone()),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = srv
        .client()
        .get(format!("{}/v2/app/manifests/1", srv.base_url))
        .header(header::HOST, &host)
        .header(
            AUTHORIZATION,
            format!("Bearer {}", token["token"].as_str().unwrap()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["docker-content-digest"], digest.as_str());
    // The challenge on that host points at that host's realm.
    let resp = srv
        .client()
        .get(format!("{}/v2/", srv.base_url))
        .header(header::HOST, &host)
        .send()
        .await
        .unwrap();
    let challenge = resp.headers()[WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        challenge.contains(&format!("realm=\"http://{host}/v2/token\"")),
        "{challenge}"
    );
}

// ── Groups ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn groups_resolve_by_priority_and_push_to_the_writable_member() {
    let srv = common::start().await;
    let high = repo_name("dock");
    let low = repo_name("dock");
    let group = repo_name("group");
    for r in [&high, &low] {
        create_repo(
            &srv,
            json!({"name": r, "kind": "hosted", "format": "docker"}),
        )
        .await;
    }
    create_repo(
        &srv,
        json!({"name": group, "kind": "group", "format": "docker", "writable_member": low}),
    )
    .await;
    for (member, priority) in [(&high, 10), (&low, 5)] {
        let resp = admin_post(
            &srv,
            &format!("/admin/repositories/{group}/members"),
            json!({"member": member, "priority": priority}),
        )
        .await;
        assert_eq!(resp.status(), 201);
    }
    let oci = admin_oci(&srv).await;
    let from_high = oci
        .push_image(&format!("{high}/app"), "1", "amd64", b"high")
        .await;
    oci.push_image(&format!("{low}/app"), "1", "amd64", b"low")
        .await;
    let only_low = oci
        .push_image(&format!("{low}/app"), "2", "amd64", b"low two")
        .await;

    let via = format!("{group}/app");
    let resp = oci.get(&via, "manifests/1").await;
    assert_eq!(resp.headers()["docker-content-digest"], from_high.as_str());
    let resp = oci.get(&via, "manifests/2").await;
    assert_eq!(resp.headers()["docker-content-digest"], only_low.as_str());
    let body: Value = oci.get(&via, "tags/list").await.json().await.unwrap();
    assert_eq!(body["tags"], json!(["1", "2"]));

    // A push to the group lands in the writable member.
    let pushed = oci
        .push_image(&via, "3", "amd64", b"pushed via group")
        .await;
    let resp = oci.get(&format!("{low}/app"), "manifests/3").await;
    assert_eq!(resp.headers()["docker-content-digest"], pushed.as_str());
    assert_eq!(
        oci.get(&format!("{high}/app"), "manifests/3")
            .await
            .status(),
        404
    );

    // A NuGet repository cannot join a docker group.
    let nuget = repo_name("nuget");
    create_repo(&srv, json!({"name": nuget, "kind": "hosted"})).await;
    let resp = admin_post(
        &srv,
        &format!("/admin/repositories/{group}/members"),
        json!({"member": nuget, "priority": 1}),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

/// A docker group names its writable member by id (#219): renaming the
/// member keeps group pushes going to it, and a repository created later
/// under its old name does not become the push target.
#[tokio::test]
async fn a_group_keeps_its_writable_member_through_a_rename() {
    let srv = common::start().await;
    let member = repo_name("dock");
    let renamed = repo_name("dock");
    let group = repo_name("group");
    create_repo(
        &srv,
        json!({"name": member, "kind": "hosted", "format": "docker"}),
    )
    .await;
    create_repo(
        &srv,
        json!({"name": group, "kind": "group", "format": "docker", "writable_member": member}),
    )
    .await;
    let resp = admin_post(
        &srv,
        &format!("/admin/repositories/{group}/members"),
        json!({"member": member, "priority": 5}),
    )
    .await;
    assert_eq!(resp.status(), 201);

    let resp = admin_put(
        &srv,
        &format!("/admin/repositories/{member}"),
        json!({"name": renamed}),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let (u, p) = srv.admin_basic();
    let shown: Value = srv
        .client()
        .get(format!("{}/admin/repositories/{group}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(shown["writable_member"], renamed.as_str(), "{shown}");

    // A new repository under the old name, in the group too.
    create_repo(
        &srv,
        json!({"name": member, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let resp = admin_post(
        &srv,
        &format!("/admin/repositories/{group}/members"),
        json!({"member": member, "priority": 10}),
    )
    .await;
    assert_eq!(resp.status(), 201);

    let oci = admin_oci(&srv).await;
    let pushed = oci
        .push_image(&format!("{group}/app"), "1", "amd64", b"pushed via group")
        .await;
    let resp = oci.get(&format!("{renamed}/app"), "manifests/1").await;
    assert_eq!(resp.headers()["docker-content-digest"], pushed.as_str());
    assert_eq!(
        oci.get(&format!("{member}/app"), "manifests/1")
            .await
            .status(),
        404
    );
}

// ── Proxies ─────────────────────────────────────────────────────────────────

/// A minimal upstream registry: Docker token auth, fixed content, and
/// switches to go down or serve corrupted content.
#[derive(Default)]
struct MockRegistry {
    manifests: Mutex<HashMap<String, (String, Vec<u8>)>>,
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    down: AtomicBool,
    corrupt: AtomicBool,
    /// Redirect authorized blob GETs to this base URL.
    redirect_blobs: Mutex<Option<String>>,
    /// Answer every blob `HEAD` with 200, whether the blob exists or not.
    lie_on_head: AtomicBool,
    manifest_gets: AtomicUsize,
    blob_gets: AtomicUsize,
    token_requests: AtomicUsize,
    base: Mutex<String>,
    /// Tag lists: at most this many tags per page, with a `Link` to the
    /// next one.
    tag_page: Mutex<Option<usize>>,
    /// Tag lists: answer an `n` above this with 400.
    max_tags_n: Mutex<Option<usize>>,
    /// The query of every tag list request.
    tag_queries: Mutex<Vec<String>>,
    /// Hold every manifest `GET` this long before answering.
    manifest_delay: Mutex<std::time::Duration>,
}

impl MockRegistry {
    async fn start() -> Arc<Self> {
        let mock = Arc::new(MockRegistry::default());
        let state = mock.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let state = state.clone();
            async move { state.serve(req).await }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        *mock.base.lock().unwrap() = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        mock
    }

    fn base(&self) -> String {
        self.base.lock().unwrap().clone()
    }

    fn put(&self, name: &str, tag: &str, media_type: &str, body: &[u8]) {
        let mut m = self.manifests.lock().unwrap();
        m.insert(format!("{name}:{tag}"), (media_type.into(), body.to_vec()));
        m.insert(
            format!("{name}:{}", sha(body)),
            (media_type.into(), body.to_vec()),
        );
    }

    fn put_blob(&self, body: &[u8]) {
        self.blobs.lock().unwrap().insert(sha(body), body.to_vec());
    }

    async fn serve(&self, req: axum::extract::Request) -> Response {
        let path = req.uri().path().to_string();
        if path == "/token" {
            self.token_requests.fetch_add(1, Ordering::SeqCst);
            let ok = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                == Some("Basic dXBzdHJlYW06c2VjcmV0"); // upstream:secret
            if !ok {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            return axum::Json(json!({"token": "good-token", "expires_in": 300})).into_response();
        }
        if self.down.load(Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let authorized = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            == Some("Bearer good-token");
        if !authorized {
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_str(&format!(
                    "Bearer realm=\"{}/token\",service=\"mock\"",
                    self.base()
                ))
                .unwrap(),
            );
            return resp;
        }
        let head = req.method() == Method::HEAD;
        match forge_oci::path::parse(&path) {
            Some(forge_oci::path::Endpoint::Manifest { name, reference }) => {
                let found = self
                    .manifests
                    .lock()
                    .unwrap()
                    .get(&format!("{name}:{reference}"))
                    .cloned();
                let Some((media_type, mut body)) = found else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if !head {
                    self.manifest_gets.fetch_add(1, Ordering::SeqCst);
                    let delay = *self.manifest_delay.lock().unwrap();
                    tokio::time::sleep(delay).await;
                }
                let digest = sha(&body);
                if self.corrupt.load(Ordering::SeqCst) {
                    body.push(b' ');
                }
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, media_type.parse().unwrap());
                headers.insert("docker-content-digest", digest.parse().unwrap());
                (
                    headers,
                    if head {
                        Body::empty()
                    } else {
                        Body::from(body)
                    },
                )
                    .into_response()
            }
            Some(forge_oci::path::Endpoint::Blob { digest, .. }) => {
                if head && self.lie_on_head.load(Ordering::SeqCst) {
                    return StatusCode::OK.into_response();
                }
                let Some(mut body) = self.blobs.lock().unwrap().get(&digest).cloned() else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if head {
                    return StatusCode::OK.into_response();
                }
                if let Some(to) = self.redirect_blobs.lock().unwrap().clone() {
                    let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
                    resp.headers_mut().insert(
                        header::LOCATION,
                        HeaderValue::from_str(&format!("{to}{path}")).unwrap(),
                    );
                    return resp;
                }
                self.blob_gets.fetch_add(1, Ordering::SeqCst);
                if self.corrupt.load(Ordering::SeqCst) {
                    body.push(0);
                }
                body.into_response()
            }
            Some(forge_oci::path::Endpoint::TagsList { name }) => {
                let query = req.uri().query().unwrap_or_default().to_string();
                self.tag_queries.lock().unwrap().push(query.clone());
                let mut n: Option<usize> = None;
                let mut last: Option<String> = None;
                for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                    match key.as_ref() {
                        "n" => n = value.parse().ok(),
                        "last" => last = Some(value.into_owned()),
                        _ => {}
                    }
                }
                if n.zip(*self.max_tags_n.lock().unwrap())
                    .is_some_and(|(n, max)| n > max)
                {
                    return StatusCode::BAD_REQUEST.into_response();
                }
                let mut tags: Vec<String> = self
                    .manifests
                    .lock()
                    .unwrap()
                    .keys()
                    .filter_map(|k| k.strip_prefix(&format!("{name}:")).map(str::to_string))
                    .filter(|t| !t.starts_with("sha256:"))
                    .filter(|t| last.as_ref().is_none_or(|l| t > l))
                    .collect();
                tags.sort();
                let page = match (n, *self.tag_page.lock().unwrap()) {
                    (Some(n), Some(cap)) => Some(n.min(cap)),
                    (n, cap) => n.or(cap),
                };
                let mut resp_headers = HeaderMap::new();
                if let Some(page) = page.filter(|&page| tags.len() > page) {
                    tags.truncate(page);
                    let next = format!(
                        "</v2/{name}/tags/list?n={page}&last={}>; rel=\"next\"",
                        tags.last().unwrap()
                    );
                    resp_headers.insert(header::LINK, next.parse().unwrap());
                }
                (
                    resp_headers,
                    axum::Json(json!({"name": name, "tags": tags})),
                )
                    .into_response()
            }
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }
}

/// A proxy's tag list follows the upstream's own pages (`Link:
/// rel="next"`) to fill the client's page, and passes on that there are
/// more; an upstream that refuses a large `n` is asked without one (#216).
#[tokio::test]
async fn proxy_tag_lists_follow_the_upstream_pages() {
    let srv = common::start().await;
    let mock = MockRegistry::start().await;
    let manifest = image(&config("amd64"), &[b"paged layer"]);
    for i in 0..7 {
        mock.put("team/paged", &format!("t{i}"), OCI_MANIFEST, &manifest);
    }
    *mock.tag_page.lock().unwrap() = Some(3);
    *mock.max_tags_n.lock().unwrap() = Some(1000);
    let proxy = repo_name("proxy");
    create_repo(
        &srv,
        json!({
            "name": proxy, "kind": "proxy", "format": "docker", "remote_url": mock.base(),
            "upstream_username": "upstream", "upstream_password": "secret",
        }),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let name = format!("{proxy}/team/paged");

    let resp = oci.get(&name, "tags/list?n=5").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["link"],
        format!("</v2/{name}/tags/list?n=5&last=t4>; rel=\"next\"").as_str()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tags"], json!(["t0", "t1", "t2", "t3", "t4"]));
    let resp = oci.get(&name, "tags/list?n=5&last=t4").await;
    assert!(resp.headers().get("link").is_none());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tags"], json!(["t5", "t6"]));

    // Without `n`: Forge's default page is more than this upstream allows.
    mock.tag_queries.lock().unwrap().clear();
    let resp = oci.get(&name, "tags/list").await;
    assert!(resp.headers().get("link").is_none());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["tags"],
        json!(["t0", "t1", "t2", "t3", "t4", "t5", "t6"])
    );
    assert_eq!(
        *mock.tag_queries.lock().unwrap(),
        ["n=10001", "", "n=3&last=t2", "n=3&last=t5"]
    );
}

/// An upstream that pages in steps too small to fill a page within the
/// pages a proxy follows: the proxy passes on that there are more, and a
/// group holding it ends its page at the proxy's last tag, so the next
/// page lists what the proxy left out before any later tag of another
/// member (#216).
#[tokio::test]
async fn group_tag_lists_end_where_a_member_left_tags_out() {
    let srv = common::start().await;
    let mock = MockRegistry::start().await;
    let manifest = image(&config("amd64"), &[b"many layer"]);
    for i in 0..12 {
        mock.put("team/many", &format!("t{i:02}"), OCI_MANIFEST, &manifest);
    }
    *mock.tag_page.lock().unwrap() = Some(1);
    let proxy = repo_name("proxy");
    create_repo(
        &srv,
        json!({
            "name": proxy, "kind": "proxy", "format": "docker", "remote_url": mock.base(),
            "upstream_username": "upstream", "upstream_password": "secret",
        }),
    )
    .await;
    let hosted = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": hosted, "kind": "hosted", "format": "docker"}),
    )
    .await;
    // Served from both members (with `prefer_hosted`, the hosted image
    // would hide the proxy's).
    let group = repo_name("group");
    create_repo(
        &srv,
        json!({"name": group, "kind": "group", "format": "docker", "prefer_hosted": false}),
    )
    .await;
    for (member, priority) in [(&hosted, 2), (&proxy, 1)] {
        let resp = admin_post(
            &srv,
            &format!("/admin/repositories/{group}/members"),
            json!({"member": member, "priority": priority}),
        )
        .await;
        assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    }
    let oci = admin_oci(&srv).await;
    oci.push_image(
        &format!("{hosted}/team/many"),
        "zz",
        "amd64",
        b"hosted many",
    )
    .await;

    let first_ten: Vec<String> = (0..10).map(|i| format!("t{i:02}")).collect();
    let resp = oci.get(&format!("{proxy}/team/many"), "tags/list").await;
    assert_eq!(
        resp.headers()["link"],
        format!("</v2/{proxy}/team/many/tags/list?n=10000&last=t09>; rel=\"next\"").as_str()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tags"], json!(first_ten));

    let name = format!("{group}/team/many");
    let resp = oci.get(&name, "tags/list").await;
    assert_eq!(
        resp.headers()["link"],
        format!("</v2/{name}/tags/list?n=10000&last=t09>; rel=\"next\"").as_str()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["tags"],
        json!(first_ten),
        "zz waits for the proxy's rest"
    );
    let resp = oci.get(&name, "tags/list?n=10000&last=t09").await;
    assert!(resp.headers().get("link").is_none());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tags"], json!(["t10", "t11", "zz"]));
}

/// A docker proxy repointed while it fetches from its previous upstream
/// caches nothing of that fetch: the repoint purges the cache, and what the
/// previous upstream served must not land in it after the purge (#217).
#[tokio::test]
async fn a_fetch_from_the_previous_upstream_is_not_cached_after_a_repoint() {
    let srv = common::start().await;
    let old = MockRegistry::start().await;
    let new = MockRegistry::start().await;
    let cfg = config("amd64");
    let manifest = image(&cfg, &[b"previous upstream layer"]);
    old.put("library/base", "1.0", OCI_MANIFEST, &manifest);
    *old.manifest_delay.lock().unwrap() = std::time::Duration::from_secs(2);
    let proxy = repo_name("proxy");
    let created = create_repo(
        &srv,
        json!({
            "name": proxy, "kind": "proxy", "format": "docker", "remote_url": old.base(),
            "upstream_username": "upstream", "upstream_password": "secret",
        }),
    )
    .await;
    let repo_id = created["id"].as_i64().unwrap();
    let oci = Arc::new(admin_oci(&srv).await);
    let name = format!("{proxy}/library/base");

    let pull = tokio::spawn({
        let oci = oci.clone();
        let name = name.clone();
        async move { oci.get(&name, "manifests/1.0").await.status() }
    });
    for _ in 0..200 {
        if old.manifest_gets.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        old.manifest_gets.load(Ordering::SeqCst),
        1,
        "the fetch is under way"
    );
    let resp = admin_put(
        &srv,
        &format!("/admin/repositories/{proxy}"),
        json!({"remote_url": new.base()}),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    assert_eq!(pull.await.unwrap(), 503, "asked to retry");
    let rows: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM oci_tag WHERE repository_id = $1), \
                (SELECT count(*) FROM oci_manifest WHERE repository_id = $1)",
    )
    .bind(repo_id)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(rows, (0, 0), "no tag or manifest of the previous upstream");
}

#[tokio::test]
async fn proxies_cache_verify_and_serve_stale_tags() {
    let srv = common::start().await;
    let mock = MockRegistry::start().await;
    let cfg = config("amd64");
    let layer = b"upstream layer".to_vec();
    let manifest = image(&cfg, &[&layer]);
    mock.put("library/base", "1.0", OCI_MANIFEST, &manifest);
    mock.put_blob(&cfg);
    mock.put_blob(&layer);

    let proxy = repo_name("proxy");
    create_repo(
        &srv,
        json!({
            "name": proxy, "kind": "proxy", "format": "docker", "remote_url": mock.base(),
            "upstream_username": "upstream", "upstream_password": "secret",
            "metadata_ttl_seconds": 0
        }),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let name = format!("{proxy}/library/base");

    let resp = oci.get(&name, "manifests/1.0").await;
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let digest = sha(&manifest);
    let resp = oci.get(&name, "manifests/1.0").await;
    assert_eq!(resp.headers()["docker-content-digest"], digest.as_str());
    assert_eq!(
        oci.get(&name, &format!("blobs/{}", sha(&layer)))
            .await
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        layer.as_slice()
    );
    assert_eq!(
        oci.get(&name, &format!("blobs/{}", sha(&cfg)))
            .await
            .status(),
        200
    );
    assert!(
        mock.token_requests.load(Ordering::SeqCst) >= 1,
        "upstream token flow used"
    );

    // Blobs are served from the cache; tags re-validate (TTL 0) with HEAD.
    let gets_before = mock.blob_gets.load(Ordering::SeqCst);
    let manifest_gets_before = mock.manifest_gets.load(Ordering::SeqCst);
    assert_eq!(
        oci.get(&name, &format!("blobs/{}", sha(&layer)))
            .await
            .status(),
        200
    );
    assert_eq!(oci.get(&name, "manifests/1.0").await.status(), 200);
    assert_eq!(mock.blob_gets.load(Ordering::SeqCst), gets_before);
    assert_eq!(
        mock.manifest_gets.load(Ordering::SeqCst),
        manifest_gets_before,
        "HEAD only"
    );
    // The platform arrived with the config blob.
    let summary: Value = sqlx::query_scalar(
        "SELECT summary FROM oci_manifest m JOIN repository r ON r.id = m.repository_id WHERE r.name = $1",
    )
    .bind(&proxy)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(summary["platform"], "linux/amd64");

    // Upstream down: the cached tag is served; an uncached one is 503.
    mock.down.store(true, Ordering::SeqCst);
    let resp = oci.get(&name, "manifests/1.0").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["docker-content-digest"], digest.as_str());
    assert_eq!(oci.get(&name, "manifests/2.0").await.status(), 503);
    mock.down.store(false, Ordering::SeqCst);

    // The upstream moves the tag: the proxy follows.
    let cfg2 = config("arm64");
    let manifest2 = image(&cfg2, &[&layer]);
    mock.put("library/base", "1.0", OCI_MANIFEST, &manifest2);
    mock.put_blob(&cfg2);
    let resp = oci.get(&name, "manifests/1.0").await;
    assert_eq!(
        resp.headers()["docker-content-digest"],
        sha(&manifest2).as_str()
    );

    // Content that does not match its digest is never cached or served.
    mock.put("library/other", "1", OCI_MANIFEST, &manifest);
    mock.corrupt.store(true, Ordering::SeqCst);
    let other = format!("{proxy}/library/other");
    assert_eq!(oci.get(&other, "manifests/1").await.status(), 503);
    let fresh_layer = b"never cached".to_vec();
    mock.put_blob(&fresh_layer);
    assert_eq!(
        oci.get(&name, &format!("blobs/{}", sha(&fresh_layer)))
            .await
            .status(),
        503
    );
    mock.corrupt.store(false, Ordering::SeqCst);
    assert_eq!(oci.get(&other, "manifests/1").await.status(), 200);

    // Unknown upstream content is a 404, and the tag list is the upstream's.
    assert_eq!(oci.get(&name, "manifests/nope").await.status(), 404);
    let body: Value = oci.get(&name, "tags/list").await.json().await.unwrap();
    assert_eq!(body["tags"], json!(["1.0"]));

    // A proxy is read-only.
    let resp = oci
        .request(
            Method::POST,
            &format!("/v2/{name}/blobs/uploads/"),
            "pull,push",
            &name,
        )
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);

    // An offline proxy serves its cache only.
    let resp = admin_put(
        &srv,
        &format!("/admin/repositories/{proxy}"),
        json!({"online": false}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(oci.get(&name, "manifests/1.0").await.status(), 200);
    assert_eq!(
        oci.get(&format!("{proxy}/library/never"), "manifests/1")
            .await
            .status(),
        404
    );
}

/// A host that challenges every request, naming its own token realm, and
/// counts the token requests it gets.
async fn challenging_host() -> (String, Arc<AtomicUsize>) {
    let tokens = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (count, realm) = (tokens.clone(), format!("{base}/token"));
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let (count, realm) = (count.clone(), realm.clone());
        async move {
            if req.uri().path() == "/token" {
                count.fetch_add(1, Ordering::SeqCst);
                return axum::Json(json!({"token": "foreign"})).into_response();
            }
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_str(&format!("Bearer realm=\"{realm}\",service=\"x\"")).unwrap(),
            );
            resp
        }
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, tokens)
}

#[tokio::test]
async fn a_challenge_from_a_redirect_hop_is_not_followed() {
    let srv = common::start().await;
    let mock = MockRegistry::start().await;
    let cfg = config("amd64");
    let layer = b"redirected layer".to_vec();
    let manifest = image(&cfg, &[&layer]);
    mock.put("library/base", "1", OCI_MANIFEST, &manifest);
    mock.put_blob(&layer);
    let proxy = repo_name("proxy");
    create_repo(
        &srv,
        json!({
            "name": proxy, "kind": "proxy", "format": "docker", "remote_url": mock.base(),
            "upstream_username": "upstream", "upstream_password": "secret"
        }),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let name = format!("{proxy}/library/base");
    // The upstream's own token is cached for the image.
    assert_eq!(oci.get(&name, "manifests/1").await.status(), 200);

    // The upstream redirects the blob to a host that challenges in turn:
    // the proxy's credentials never go to the realm that host names.
    let (host, token_requests) = challenging_host().await;
    *mock.redirect_blobs.lock().unwrap() = Some(host);
    let resp = oci.get(&name, &format!("blobs/{}", sha(&layer))).await;
    assert_ne!(resp.status(), 200);
    assert_eq!(token_requests.load(Ordering::SeqCst), 0);
}

/// An administrator's cache invalidation re-validates a proxy's tags and
/// forgets the upstream's "not found" answers before their TTLs run out.
#[tokio::test]
async fn invalidating_a_proxy_cache_asks_the_upstream_again() {
    let srv = common::start().await;
    let mock = MockRegistry::start().await;
    let cfg = config("amd64");
    let layer = b"invalidated layer".to_vec();
    let manifest = image(&cfg, &[&layer]);
    mock.put("library/base", "1.0", OCI_MANIFEST, &manifest);
    mock.put("library/other", "1.0", OCI_MANIFEST, &manifest);
    mock.put_blob(&cfg);
    mock.put_blob(&layer);

    let proxy = repo_name("proxy");
    create_repo(
        &srv,
        json!({
            "name": proxy, "kind": "proxy", "format": "docker", "remote_url": mock.base(),
            "upstream_username": "upstream", "upstream_password": "secret",
            "metadata_ttl_seconds": 3600, "not_found_ttl_seconds": 3600
        }),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let (base, other) = (
        format!("{proxy}/library/base"),
        format!("{proxy}/library/other"),
    );
    assert_eq!(oci.get(&base, "manifests/1.0").await.status(), 200);
    assert_eq!(oci.get(&other, "manifests/1.0").await.status(), 200);
    assert_eq!(oci.get(&base, "manifests/2.0").await.status(), 404);

    // The upstream moves `1.0` and publishes `2.0`: within the TTLs the
    // proxy still answers from its cache.
    let cfg2 = config("arm64");
    let manifest2 = image(&cfg2, &[&layer]);
    mock.put("library/base", "1.0", OCI_MANIFEST, &manifest2);
    mock.put("library/base", "2.0", OCI_MANIFEST, &manifest2);
    mock.put_blob(&cfg2);
    let resp = oci.get(&base, "manifests/1.0").await;
    assert_eq!(
        resp.headers()["docker-content-digest"],
        sha(&manifest).as_str()
    );
    assert_eq!(oci.get(&base, "manifests/2.0").await.status(), 404);

    let invalidate = format!("/admin/repositories/{proxy}/proxy-cache/invalidate");
    let resp = admin_post(&srv, &invalidate, json!({"package": "library/base"})).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tags_expired"], 1, "{body}");

    let resp = oci.get(&base, "manifests/1.0").await;
    assert_eq!(
        resp.headers()["docker-content-digest"],
        sha(&manifest2).as_str()
    );
    assert_eq!(oci.get(&base, "manifests/2.0").await.status(), 200);

    // Without a package: every tag.
    let resp = admin_post(&srv, &invalidate, json!({})).await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tags_expired"], 3, "{body}");
    let resp = admin_post(&srv, &invalidate, json!({"package": "Not A Name"})).await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn a_proxy_links_only_blobs_its_own_upstream_served() {
    let srv = common::start().await;
    let oci = admin_oci(&srv).await;

    // A private image in a hosted repository.
    let hosted = repo_name("private");
    create_repo(
        &srv,
        json!({"name": hosted, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let secret = b"private layer bytes".to_vec();
    oci.push_image(&format!("{hosted}/team/app"), "1", "amd64", &secret)
        .await;

    let mock = MockRegistry::start().await;
    let shared = b"layer shared upstream".to_vec();
    mock.put_blob(&shared);
    let proxy = repo_name("proxy");
    create_repo(
        &srv,
        json!({
            "name": proxy, "kind": "proxy", "format": "docker", "remote_url": mock.base(),
            "upstream_username": "upstream", "upstream_password": "secret"
        }),
    )
    .await;

    // An upstream that claims every blob gets nothing Forge holds for
    // another repository: the blob is fetched (and is not there).
    mock.lie_on_head.store(true, Ordering::SeqCst);
    let resp = oci
        .get(&format!("{proxy}/x"), &format!("blobs/{}", sha(&secret)))
        .await;
    assert_eq!(resp.status(), 404);
    let linked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oci_blob_link l JOIN repository r ON r.id = l.repository_id \
         WHERE r.name = $1",
    )
    .bind(&proxy)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(linked, 0, "nothing linked into the proxy");
    mock.lie_on_head.store(false, Ordering::SeqCst);

    // A layer this proxy already fetched is linked into another of its
    // images without a second download.
    let path = format!("blobs/{}", sha(&shared));
    let resp = oci.get(&format!("{proxy}/library/a"), &path).await;
    assert_eq!(resp.bytes().await.unwrap().as_ref(), shared.as_slice());
    let gets = mock.blob_gets.load(Ordering::SeqCst);
    let resp = oci.get(&format!("{proxy}/library/b"), &path).await;
    assert_eq!(resp.bytes().await.unwrap().as_ref(), shared.as_slice());
    assert_eq!(
        mock.blob_gets.load(Ordering::SeqCst),
        gets,
        "linked, not fetched"
    );
}

#[tokio::test]
async fn group_guard_keeps_reserved_namespaces_off_proxies() {
    let srv = common::start().await;
    let mock = MockRegistry::start().await;
    let cfg = config("amd64");
    let manifest = image(&cfg, &[b"public"]);
    for name in ["envisia/app", "public/app"] {
        mock.put(name, "1", OCI_MANIFEST, &manifest);
    }
    mock.put_blob(&cfg);
    mock.put_blob(b"public");

    let hosted = repo_name("dock");
    let proxy = repo_name("proxy");
    let group = repo_name("group");
    create_repo(
        &srv,
        json!({"name": hosted, "kind": "hosted", "format": "docker"}),
    )
    .await;
    create_repo(
        &srv,
        json!({"name": proxy, "kind": "proxy", "format": "docker", "remote_url": mock.base(),
               "upstream_username": "upstream", "upstream_password": "secret"}),
    )
    .await;
    create_repo(
        &srv,
        json!({"name": group, "kind": "group", "format": "docker", "reserved_prefixes": ["envisia/"]}),
    )
    .await;
    for (member, priority) in [(&hosted, 10), (&proxy, 5)] {
        admin_post(
            &srv,
            &format!("/admin/repositories/{group}/members"),
            json!({"member": member, "priority": priority}),
        )
        .await;
    }
    let oci = admin_oci(&srv).await;
    // A reserved namespace is never served by the proxy member.
    assert_eq!(
        oci.get(&format!("{group}/envisia/app"), "manifests/1")
            .await
            .status(),
        404
    );
    assert_eq!(
        oci.get(&format!("{group}/public/app"), "manifests/1")
            .await
            .status(),
        200
    );
    // prefer_hosted: once a hosted member has an image, the proxy is not asked.
    let ours = oci
        .push_image(&format!("{hosted}/public/app"), "2", "amd64", b"ours")
        .await;
    assert_eq!(
        oci.get(&format!("{group}/public/app"), "manifests/1")
            .await
            .status(),
        404
    );
    let resp = oci.get(&format!("{group}/public/app"), "manifests/2").await;
    assert_eq!(resp.headers()["docker-content-digest"], ours.as_str());

    // The guard holds for a caller who cannot read the hosted member: it gets
    // nothing, never the proxy's image of the same name.
    let (user, token, uid) = user_with_token(&srv).await;
    grant(&srv, uid, &group, &["read"]).await;
    grant(&srv, uid, &proxy, &["read"]).await;
    let dev = Oci::new(&srv, Some((user, token)));
    assert_eq!(
        dev.get(&format!("{group}/public/app"), "manifests/1")
            .await
            .status(),
        404
    );
    mock.put("other/app", "1", OCI_MANIFEST, &manifest);
    assert_eq!(
        dev.get(&format!("{group}/other/app"), "manifests/1")
            .await
            .status(),
        200,
        "what no owner has still comes from the proxy"
    );
}

// ── Admin API ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_validates_docker_repositories() {
    let srv = common::start().await;
    let bad = |body: Value| {
        let srv = &srv;
        async move { admin_post(srv, "/admin/repositories", body).await.status() }
    };
    let n = format!("{}x{}", std::process::id(), unique());
    assert_eq!(
        bad(json!({"name": format!("Upper{n}"), "kind": "hosted", "format": "docker"})).await,
        400
    );
    assert_eq!(
        bad(json!({"name": format!("x{n}"), "kind": "hosted", "format": "npm"})).await,
        400
    );
    assert_eq!(
        bad(json!({"name": format!("nu{n}"), "kind": "hosted", "immutable_tags": true})).await,
        400
    );
    assert_eq!(bad(json!({"name": format!("p{n}"), "kind": "proxy", "format": "docker", "remote_url": "https://ghcr.io", "immutable_tags": true})).await, 400);
    assert_eq!(bad(json!({"name": format!("h{n}"), "kind": "hosted", "format": "docker", "host": "no_dots"})).await, 400);
    assert_eq!(bad(json!({"name": format!("h{n}"), "kind": "hosted", "format": "docker", "allow_redeploy": true})).await, 400);
    assert_eq!(bad(json!({"name": format!("g{n}"), "kind": "group", "format": "docker", "writable_member": "does-not-exist"})).await, 400);

    // A host serves one repository.
    let host = format!("d{n}.example.com");
    create_repo(
        &srv,
        json!({"name": format!("a{n}"), "kind": "hosted", "format": "docker", "host": host}),
    )
    .await;
    let resp = admin_post(&srv, "/admin/repositories", json!({"name": format!("b{n}"), "kind": "hosted", "format": "docker", "host": host.to_uppercase()})).await;
    assert_eq!(resp.status(), 409);

    // A docker repository is not a NuGet feed.
    let resp = srv
        .client()
        .get(format!("{}/v3/a{n}/index.json", srv.base_url))
        .basic_auth(
            srv.admin_user.clone().unwrap(),
            Some(srv.admin_scoped_token.clone().unwrap()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    // Nor a format-plugin repository: docker has its own mount.
    let resp = srv
        .client()
        .get(format!("{}/repository/a{n}/index.yaml", srv.base_url))
        .basic_auth(
            srv.admin_user.clone().unwrap(),
            Some(srv.admin_scoped_token.clone().unwrap()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // The admin API lists docker as a built-in format with all three kinds.
    let (u, p) = srv.admin_basic();
    let formats: Value = srv
        .client()
        .get(format!("{}/admin/formats", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let docker = formats
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "docker")
        .expect("docker is listed");
    assert_eq!(docker["builtin"], true);
    assert_eq!(docker["kinds"], json!(["hosted", "proxy", "group"]));
    assert_eq!(docker["mount"], "/v2");

    // A hosted repository with images is not deleted; a proxy is purged.
    let repo = format!("a{n}");
    let oci = admin_oci(&srv).await;
    oci.push_image(&format!("{repo}/app"), "1", "amd64", b"kept")
        .await;
    let resp = srv
        .client()
        .delete(format!("{}/admin/repositories/{repo}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

// ── GC and retention ────────────────────────────────────────────────────────

async fn ref_count(srv: &TestServer, digest: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT ref_count FROM blob WHERE sha256 = $1")
        .bind(digest.trim_start_matches("sha256:"))
        .fetch_optional(&srv.pool)
        .await
        .unwrap()
}

/// A client confirming a blob it is about to name in a manifest records the
/// use of its link, so the sweeper does not release it first (#218): a push
/// of a blob the image already has, a mount of it, and a `HEAD` of it,
/// recorded every tenth of `docker.unreferenced_blob_ttl_seconds` (six
/// minutes for the smallest TTL, an hour) instead of hourly.
#[tokio::test]
async fn confirming_a_blob_records_the_use_of_its_link() {
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", unique()), "adminpw".into())),
            plugins_block: Some("[docker]\nunreferenced_blob_ttl_seconds = 3600\n".into()),
            ..Default::default()
        },
    )
    .await;
    let repo = repo_name("dock");
    let created = create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let repo_id = created["id"].as_i64().unwrap();
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/app");
    let layer = format!("confirmed layer {}", unique()).into_bytes();
    let digest = oci.push_blob(&name, &layer).await;
    let unused_for = |minutes: i32| {
        let pool = srv.pool.clone();
        let digest = digest.clone();
        async move {
            sqlx::query(
                "UPDATE oci_blob_link SET last_used_at = now() - make_interval(mins => $1) \
                 WHERE repository_id = $2 AND digest = $3",
            )
            .bind(minutes)
            .bind(repo_id)
            .bind(digest)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    let used_recently = || {
        let pool = srv.pool.clone();
        let digest = digest.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT last_used_at > now() - interval '1 minute' FROM oci_blob_link \
                 WHERE repository_id = $1 AND digest = $2",
            )
            .bind(repo_id)
            .bind(digest)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };

    unused_for(59).await;
    oci.push_blob(&name, &layer).await;
    assert!(used_recently().await, "pushed again");

    unused_for(59).await;
    let resp = oci
        .request(
            Method::POST,
            &format!("/v2/{name}/blobs/uploads/"),
            "pull,push",
            &name,
        )
        .await
        .query(&[("mount", &digest)])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert!(used_recently().await, "mounted");

    unused_for(7).await;
    assert_eq!(
        oci.head(&name, &format!("blobs/{digest}")).await.status(),
        200
    );
    assert!(used_recently().await, "a HEAD after a tenth of the TTL");

    unused_for(2).await;
    assert_eq!(
        oci.head(&name, &format!("blobs/{digest}")).await.status(),
        200
    );
    assert!(!used_recently().await, "not recorded on every request");
}

#[tokio::test]
async fn deleting_an_image_never_frees_a_layer_another_image_uses() {
    // Sweeps with zero TTLs release every unreferenced link of the database,
    // so this test has one of its own.
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", unique()), "adminpw".into())),
            ..Default::default()
        },
    )
    .await;
    let repo = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let oci = admin_oci(&srv).await;
    let shared: Vec<u8> = format!("shared layer {}", unique()).into_bytes();
    let a = oci
        .push_image(&format!("{repo}/a"), "1", "amd64", &shared)
        .await;
    let b = oci
        .push_image(&format!("{repo}/b"), "1", "amd64", &shared)
        .await;
    let layer = sha(&shared);
    assert_eq!(ref_count(&srv, &layer).await, Some(2), "one link per image");

    let sweep = || {
        forge_oci::gc::sweep_once(
            &srv.pool,
            chrono::Duration::zero(),
            chrono::Duration::zero(),
            chrono::Duration::zero(),
        )
    };
    assert_eq!(
        oci.delete(&format!("{repo}/a"), &format!("manifests/{a}"))
            .await
            .status(),
        202
    );
    sweep().await.unwrap();
    assert_eq!(
        ref_count(&srv, &layer).await,
        Some(1),
        "image a's link released"
    );
    assert_eq!(
        oci.get(&format!("{repo}/b"), &format!("blobs/{layer}"))
            .await
            .status(),
        200
    );
    assert_eq!(
        oci.get(&format!("{repo}/a"), &format!("blobs/{layer}"))
            .await
            .status(),
        404
    );

    assert_eq!(
        oci.delete(&format!("{repo}/b"), &format!("manifests/{b}"))
            .await
            .status(),
        202
    );
    sweep().await.unwrap();
    assert_eq!(ref_count(&srv, &layer).await, Some(0));
    let queued: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM blob_outbox WHERE sha256 = $1 AND processed_at IS NULL)",
    )
    .bind(layer.trim_start_matches("sha256:"))
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert!(queued, "the last reference queued the blob for deletion");

    // Abandoned uploads release their chunks.
    let name = format!("{repo}/c");
    let auth = oci.bearer(&name, "pull,push").await;
    let resp = srv
        .client()
        .post(format!("{}/v2/{name}/blobs/uploads/", srv.base_url))
        .header(AUTHORIZATION, &auth)
        .send()
        .await
        .unwrap();
    let location = resp.headers()[LOCATION].to_str().unwrap().to_string();
    let chunk = format!("abandoned {}", unique()).into_bytes();
    srv.client()
        .patch(format!("{}{location}", srv.base_url))
        .header(AUTHORIZATION, &auth)
        .body(chunk.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(ref_count(&srv, &sha(&chunk)).await, Some(1));
    let summary = sweep().await.unwrap();
    assert!(summary.uploads >= 1);
    assert_eq!(ref_count(&srv, &sha(&chunk)).await, Some(0));
}

#[tokio::test]
async fn retention_keeps_newest_tags_and_drops_old_untagged_manifests() {
    let srv = common::start().await;
    let repo = repo_name("dock");
    let created = create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let repo_id = created["id"].as_i64().unwrap();
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/app");
    let mut digests = Vec::new();
    for i in 0..4 {
        digests.push(
            oci.push_image(
                &name,
                &format!("v{i}"),
                "amd64",
                format!("layer {i}").as_bytes(),
            )
            .await,
        );
    }
    // Push times in order, a day apart; v0's manifest lost its tag long ago.
    for (i, tag) in ["v0", "v1", "v2", "v3"].iter().enumerate() {
        sqlx::query("UPDATE oci_tag SET updated_at = now() - make_interval(days => $1) WHERE repository_id = $2 AND tag = $3")
            .bind(10 - i as i32)
            .bind(repo_id)
            .bind(tag)
            .execute(&srv.pool)
            .await
            .unwrap();
    }
    assert_eq!(oci.delete(&name, "manifests/v0").await.status(), 202);
    sqlx::query(
        "UPDATE oci_manifest SET untagged_since = now() - interval '30 days' WHERE digest = $1",
    )
    .bind(&digests[0])
    .execute(&srv.pool)
    .await
    .unwrap();

    let policy = json!({"version": 1, "rules": [
        {"id": "keep-2", "keep_last_n_tags": 2},
        {"id": "untagged", "delete_untagged_after_days": 7}
    ]});
    let resp = admin_put(
        &srv,
        &format!("/admin/repositories/{repo}/retention"),
        json!({"policy": policy}),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    // A NuGet-shaped rule is refused for a docker repository.
    let resp = admin_put(
        &srv,
        &format!("/admin/repositories/{repo}/retention"),
        json!({"policy": {"version": 1, "rules": [{"id": "x", "action": "hard_delete", "criteria": {"keep_last_n": 1}}]}}),
    )
    .await;
    assert_eq!(resp.status(), 422);

    let preview: Value = admin_post(
        &srv,
        &format!("/admin/repositories/{repo}/retention/preview"),
        json!({}),
    )
    .await
    .json()
    .await
    .unwrap();
    let tags: Vec<&str> = preview["image_decisions"]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, vec!["v1"]);
    assert_eq!(
        preview["image_decisions"]["manifests"][0]["digest"],
        digests[0].as_str()
    );

    let resp = admin_post(
        &srv,
        &format!("/admin/repositories/{repo}/retention/run"),
        json!({}),
    )
    .await;
    assert_eq!(resp.status(), 202);
    let worker = forge_core::retention::RetentionWorker::new(
        srv.pool.clone(),
        srv.state.formats.get("nuget").expect("NuGet is built in"),
        Arc::new(forge_core::repo::NoopCacheInvalidator),
        forge_core::retention::RetentionConfig::default(),
    );
    let summary = worker.tick_repo(repo_id).await.unwrap().expect("a run");
    assert_eq!(summary.deleted, 2, "{summary:?}");
    assert_eq!(oci.get(&name, "manifests/v1").await.status(), 404);
    assert_eq!(
        oci.get(&name, &format!("manifests/{}", digests[1]))
            .await
            .status(),
        200,
        "untagged just now"
    );
    assert_eq!(
        oci.get(&name, &format!("manifests/{}", digests[0]))
            .await
            .status(),
        404
    );
    for tag in ["v2", "v3"] {
        assert_eq!(
            oci.get(&name, &format!("manifests/{tag}")).await.status(),
            200
        );
    }
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM retention_audit WHERE repository_id = $1 ORDER BY id",
    )
    .bind(repo_id)
    .fetch_all(&srv.pool)
    .await
    .unwrap();
    assert_eq!(audit, vec!["delete_tag", "delete_manifest"]);
}

/// Claim `repo_id`'s retention run and evaluate its image policy as the
/// worker does, stopping before the apply step so a test can change state
/// in between.
async fn claim_image_run(
    srv: &TestServer,
    repo: &str,
    repo_id: i64,
) -> (
    forge_db::retention_dao::ClaimedRepo,
    uuid::Uuid,
    forge_core::retention::images::ImageRetentionPolicy,
    forge_core::retention::images::ImageDecisions,
    chrono::DateTime<chrono::Utc>,
) {
    let resp = admin_post(
        srv,
        &format!("/admin/repositories/{repo}/retention/run"),
        json!({}),
    )
    .await;
    assert_eq!(resp.status(), 202);
    let mut tx = srv.pool.begin().await.unwrap();
    let (claimed, run_id) = forge_db::retention_dao::claim_next_due_repo(
        &mut tx,
        chrono::Utc::now(),
        chrono::Duration::seconds(300),
        Some(repo_id),
    )
    .await
    .unwrap()
    .expect("due");
    tx.commit().await.unwrap();
    let policy: forge_core::retention::images::ImageRetentionPolicy =
        serde_json::from_value(claimed.policy.clone()).unwrap();
    let now = forge_db::db_now(&srv.pool).await.unwrap();
    let (decisions, _) =
        forge_core::retention::images::evaluate_repository(&srv.pool, repo_id, now, &policy)
            .await
            .unwrap();
    (claimed, run_id, policy, decisions, now)
}

async fn apply_image_run(
    srv: &TestServer,
    claimed: &forge_db::retention_dao::ClaimedRepo,
    run_id: uuid::Uuid,
    policy: &forge_core::retention::images::ImageRetentionPolicy,
    decisions: &forge_core::retention::images::ImageDecisions,
    evaluated_at: chrono::DateTime<chrono::Utc>,
) -> forge_db::retention_dao::RunSummary {
    let fence = forge_core::retention::images::ImageRunFence {
        stored_policy: &claimed.policy,
        policy,
        evaluated_at,
    };
    forge_core::retention::images::apply_images(
        &srv.pool,
        claimed.repository_id,
        run_id,
        decisions,
        chrono::Duration::seconds(60),
        false,
        Some(&fence),
    )
    .await
    .unwrap()
}

/// An image retention run stops applying once its policy changes (here: to
/// dry run) or it loses its lease, as a package retention run does (#215).
#[tokio::test]
async fn image_retention_stops_when_its_policy_changes_or_its_lease_is_lost() {
    let srv = common::start().await;
    let oci = admin_oci(&srv).await;
    let policy = json!({"version": 1, "rules": [{"id": "keep-1", "keep_last_n_tags": 1}]});
    for lose_lease in [false, true] {
        let repo = repo_name("dock");
        let created = create_repo(
            &srv,
            json!({"name": repo, "kind": "hosted", "format": "docker"}),
        )
        .await;
        let repo_id = created["id"].as_i64().unwrap();
        let name = format!("{repo}/app");
        for i in 0..4 {
            oci.push_image(
                &name,
                &format!("v{i}"),
                "amd64",
                format!("layer {repo} {i}").as_bytes(),
            )
            .await;
            sqlx::query("UPDATE oci_tag SET updated_at = now() - make_interval(days => $1) WHERE repository_id = $2 AND tag = $3")
                .bind(10 - i)
                .bind(repo_id)
                .bind(format!("v{i}"))
                .execute(&srv.pool)
                .await
                .unwrap();
        }
        let resp = admin_put(
            &srv,
            &format!("/admin/repositories/{repo}/retention"),
            json!({"policy": policy}),
        )
        .await;
        assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
        let (claimed, run_id, parsed, decisions, now) = claim_image_run(&srv, &repo, repo_id).await;
        assert_eq!(decisions.tags.len(), 3);

        if lose_lease {
            sqlx::query("UPDATE retention_run SET current_run_id = gen_random_uuid() WHERE repository_id = $1")
                .bind(repo_id)
                .execute(&srv.pool)
                .await
                .unwrap();
        } else {
            let mut dry_run = policy.clone();
            dry_run["dry_run_only"] = json!(true);
            forge_db::retention_dao::write_policy(&srv.pool, repo_id, Some(&dry_run))
                .await
                .unwrap();
        }

        let summary = apply_image_run(&srv, &claimed, run_id, &parsed, &decisions, now).await;
        assert_eq!(
            (summary.deleted, summary.skipped),
            (0, 3),
            "lose_lease={lose_lease}"
        );
        for i in 0..4 {
            assert_eq!(
                oci.get(&name, &format!("manifests/v{i}")).await.status(),
                200,
                "lose_lease={lose_lease}"
            );
        }
    }
}

/// Image retention re-evaluates an image under its lock before applying
/// what it decided for it (#215): a tag newer ones deleted since now keeps,
/// a tag pulled since, and a referrer whose subject was tagged again are
/// skipped; the rest is applied.
#[tokio::test]
async fn image_retention_re_evaluates_each_image_under_its_lock() {
    let srv = common::start().await;
    let oci = admin_oci(&srv).await;
    let repo = repo_name("dock");
    let created = create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let repo_id = created["id"].as_i64().unwrap();
    let pushed_days_ago = |image: &'static str, tag: String, days: i32| {
        let pool = srv.pool.clone();
        async move {
            sqlx::query("UPDATE oci_tag SET updated_at = now() - make_interval(days => $1) WHERE repository_id = $2 AND image = $3 AND tag = $4")
                .bind(days)
                .bind(repo_id)
                .bind(image)
                .bind(tag)
                .execute(&pool)
                .await
                .unwrap();
        }
    };

    // `keep`: five tags, the two newest kept.
    let keep = format!("{repo}/keep");
    for i in 0..5 {
        oci.push_image(
            &keep,
            &format!("k{i}"),
            "amd64",
            format!("keep {repo} {i}").as_bytes(),
        )
        .await;
        pushed_days_ago("keep", format!("k{i}"), 10 - i).await;
    }
    // `pulled`: a tag pushed long ago and never pulled.
    let pulled = format!("{repo}/pulled");
    oci.push_image(&pulled, "p0", "amd64", format!("pulled {repo}").as_bytes())
        .await;
    pushed_days_ago("pulled", "p0".into(), 60).await;
    // `signed`: an image and its signature, both untagged for a month.
    let signed = format!("{repo}/signed");
    let layer = format!("signed {repo}").into_bytes();
    let subject = oci.push_image(&signed, "s", "amd64", &layer).await;
    let subject_manifest = image(&config("amd64"), &[&layer]);
    let empty_cfg = b"{}";
    let sig = json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": "application/vnd.dev.cosign.artifact.sig.v1+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": sha(empty_cfg), "size": 2},
        "layers": [],
        "subject": {"mediaType": OCI_MANIFEST, "digest": subject, "size": subject_manifest.len()},
    })
    .to_string()
    .into_bytes();
    let resp = oci
        .put_manifest(&signed, &sha(&sig), OCI_MANIFEST, &sig)
        .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    assert_eq!(oci.delete(&signed, "manifests/s").await.status(), 202);
    sqlx::query("UPDATE oci_manifest SET untagged_since = now() - interval '30 days' WHERE repository_id = $1 AND image = 'signed'")
        .bind(repo_id)
        .execute(&srv.pool)
        .await
        .unwrap();

    let policy = json!({"version": 1, "rules": [
        {"id": "keep-2", "image_prefix": "keep", "keep_last_n_tags": 2},
        {"id": "unpulled", "image_prefix": "pulled", "tag_not_pulled_for_days": 30},
        {"id": "untagged", "image_prefix": "signed", "delete_untagged_after_days": 7}
    ]});
    let resp = admin_put(
        &srv,
        &format!("/admin/repositories/{repo}/retention"),
        json!({"policy": policy}),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let (claimed, run_id, parsed, decisions, now) = claim_image_run(&srv, &repo, repo_id).await;
    let mut tags: Vec<&str> = decisions.tags.iter().map(|t| t.tag.as_str()).collect();
    tags.sort_unstable();
    assert_eq!(tags, ["k0", "k1", "k2", "p0"]);
    let mut manifests: Vec<&str> = decisions
        .manifests
        .iter()
        .map(|m| m.digest.as_str())
        .collect();
    manifests.sort_unstable();
    let sig_digest = sha(&sig);
    let mut doomed = vec![subject.as_str(), sig_digest.as_str()];
    doomed.sort_unstable();
    assert_eq!(manifests, doomed);

    // Meanwhile: the newest `keep` tag is deleted, `p0` is pulled, and the
    // signed image is tagged again.
    assert_eq!(oci.delete(&keep, "manifests/k4").await.status(), 202);
    assert_eq!(oci.get(&pulled, "manifests/p0").await.status(), 200);
    let resp = oci
        .put_manifest(&signed, "again", OCI_MANIFEST, &subject_manifest)
        .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    let summary = apply_image_run(&srv, &claimed, run_id, &parsed, &decisions, now).await;
    assert_eq!((summary.deleted, summary.skipped), (2, 4), "{summary:?}");
    for (tag, status) in [("k0", 404), ("k1", 404), ("k2", 200), ("k3", 200)] {
        assert_eq!(
            oci.get(&keep, &format!("manifests/{tag}")).await.status(),
            status,
            "{tag}"
        );
    }
    assert_eq!(oci.get(&pulled, "manifests/p0").await.status(), 200);
    for digest in [&subject, &sig_digest] {
        assert_eq!(
            oci.get(&signed, &format!("manifests/{digest}"))
                .await
                .status(),
            200,
            "{digest}"
        );
    }
}

/// A tag that clients only resolve with a HEAD, as containerd does while it
/// holds the digest, counts as pulled for `tag_not_pulled_for_days` (#197).
#[tokio::test]
async fn a_manifest_head_counts_as_a_pull_for_retention() {
    let srv = common::start().await;
    let repo = repo_name("dock");
    let created = create_repo(
        &srv,
        json!({"name": repo, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let repo_id = created["id"].as_i64().unwrap();
    let oci = admin_oci(&srv).await;
    let name = format!("{repo}/app");
    for tag in ["resolved", "idle"] {
        oci.push_image(&name, tag, "amd64", format!("layer {tag}").as_bytes())
            .await;
    }
    // Both pushed and last pulled long ago.
    sqlx::query(
        "UPDATE oci_tag SET updated_at = now() - interval '60 days' WHERE repository_id = $1",
    )
    .bind(repo_id)
    .execute(&srv.pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE oci_manifest SET last_pulled_at = now() - interval '60 days' \
         WHERE repository_id = $1",
    )
    .bind(repo_id)
    .execute(&srv.pool)
    .await
    .unwrap();

    let resp = oci.head(&name, "manifests/resolved").await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("docker-content-digest"));

    let resp = admin_put(
        &srv,
        &format!("/admin/repositories/{repo}/retention"),
        json!({"policy": {"version": 1, "rules": [
            {"id": "stale", "tag_not_pulled_for_days": 30}
        ]}}),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let preview: Value = admin_post(
        &srv,
        &format!("/admin/repositories/{repo}/retention/preview"),
        json!({}),
    )
    .await
    .json()
    .await
    .unwrap();
    let tags: Vec<&str> = preview["image_decisions"]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, vec!["idle"], "{preview}");
}

#[tokio::test]
async fn anonymous_pulls_where_the_repository_allows_them() {
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", unique()), "adminpw".into())),
            anonymous_mode: "all".into(),
            ..Default::default()
        },
    )
    .await;
    let open = repo_name("dock");
    let closed = repo_name("dock");
    create_repo(
        &srv,
        json!({"name": open, "kind": "hosted", "format": "docker", "anonymous_read": true}),
    )
    .await;
    create_repo(
        &srv,
        json!({"name": closed, "kind": "hosted", "format": "docker"}),
    )
    .await;
    let admin = admin_oci(&srv).await;
    let digest = admin
        .push_image(&format!("{open}/app"), "1", "amd64", b"public layer")
        .await;
    admin
        .push_image(&format!("{closed}/app"), "1", "amd64", b"private layer")
        .await;

    // `docker pull` without login: challenge, anonymous token, pull.
    let anonymous = Oci::new(&srv, None);
    let resp = anonymous.get(&format!("{open}/app"), "manifests/1").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["docker-content-digest"], digest.as_str());
    // The anonymous token grants nothing on a closed repository, and never
    // a push.
    let resp = anonymous.get(&format!("{closed}/app"), "manifests/1").await;
    assert_eq!(resp.status(), 401);
    let resp = anonymous
        .put_manifest(
            &format!("{open}/app"),
            "2",
            OCI_MANIFEST,
            &image(b"{}", &[]),
        )
        .await;
    assert_eq!(resp.status(), 401);
}
