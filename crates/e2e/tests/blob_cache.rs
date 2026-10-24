//! E2E: the local blob cache (`[blob_cache]`, issue #46) in front of a real
//! S3 (versitygw) reached through an [`S3Gate`], which counts S3 requests and
//! simulates an outage. Gated behind `forge-e2e`.
//!
//! * A second download of a package does not reach S3; a Range request is
//!   served from the cached file.
//! * With S3 stopped: cached packages restore, uncached ones fail fast with
//!   503, pushes and first-time proxy downloads answer 503, `/readyz` stays
//!   200 and reports `degraded`, an instance restarted on its persistent
//!   cache starts and serves, and once S3 returns everything recovers
//!   without a restart.
//! * The docker registry answers the same 503s while S3 is down: uncached
//!   blob and manifest pulls, pushes, and the finish of a chunked upload.

#![cfg(feature = "forge-e2e")]

use std::time::{Duration, Instant};

use forge_e2e::{
    make_nupkg, AnonMode, MockUpstream, S3Gate, StackBuilder, TestServer, UpstreamPackage,
};
use serde_json::Value;

/// A hosted repository everyone may read.
async fn public_repo(srv: &TestServer, name: &str) {
    let resp = srv
        .create_repo(serde_json::json!({"name": name, "kind": "hosted", "anonymous_read": true}))
        .await;
    assert_eq!(resp.status(), 201, "create repo");
    srv.grant_anonymous_read(name).await;
}

/// GET a package's `.nupkg` anonymously, optionally with a `Range`.
async fn download(
    srv: &TestServer,
    repo: &str,
    id: &str,
    version: &str,
    range: Option<&str>,
) -> reqwest::Response {
    let url = format!(
        "{}/repository/{repo}/flat/{id}/{version}/{id}.{version}.nupkg",
        srv.base_url
    );
    let mut request = srv.client().get(url);
    if let Some(range) = range {
        request = request.header("range", range);
    }
    request.send().await.unwrap()
}

async fn download_bytes(srv: &TestServer, repo: &str, id: &str, version: &str) -> Vec<u8> {
    let resp = download(srv, repo, id, version, None).await;
    assert_eq!(resp.status(), 200, "download {id} {version}");
    resp.bytes().await.unwrap().to_vec()
}

async fn readyz(srv: &TestServer) -> (u16, Value) {
    let resp = srv
        .client()
        .get(format!("{}/readyz", srv.base_url))
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.json().await.unwrap())
}

/// Copy the bootstrap admin's credentials from `from` (servers over the same
/// database share them).
fn share_admin(from: &TestServer, to: &mut TestServer) {
    to.admin_user = from.admin_user.clone();
    to.admin_pass = from.admin_pass.clone();
    to.admin_scoped_token = from.admin_scoped_token.clone();
    to.admin_token = from.admin_token.clone();
}

#[tokio::test]
async fn a_second_download_does_not_reach_s3() {
    let gate = S3Gate::start().await;
    let cache = tempfile::tempdir().unwrap();
    let srv = StackBuilder::default()
        .anon(AnonMode::All)
        .s3_endpoint(gate.endpoint())
        .blob_cache(cache.path(), None)
        .start()
        .await;
    let repo = "cached";
    public_repo(&srv, repo).await;
    let bytes = make_nupkg("Cached.Lib", "1.0.0");
    assert_eq!(srv.push_nupkg(repo, bytes.clone()).await.status(), 201);

    // Written through on push: even the first download stays local.
    let before = gate.blob_gets();
    assert_eq!(
        download_bytes(&srv, repo, "cached.lib", "1.0.0").await,
        bytes
    );
    assert_eq!(
        download_bytes(&srv, repo, "cached.lib", "1.0.0").await,
        bytes
    );
    assert_eq!(
        gate.blob_gets(),
        before,
        "no S3 GET for written-through blobs"
    );

    // An instance with a cache of its own reads S3 once, then never again.
    let peer_cache = tempfile::tempdir().unwrap();
    let mut peer = StackBuilder::default()
        .no_bootstrap_admin()
        .anon(AnonMode::All)
        .s3_endpoint(gate.endpoint())
        .blob_cache(peer_cache.path(), None)
        .start_on(&srv.db_url)
        .await;
    share_admin(&srv, &mut peer);
    let before = gate.blob_gets();
    assert_eq!(
        download_bytes(&peer, repo, "cached.lib", "1.0.0").await,
        bytes
    );
    assert_eq!(
        gate.blob_gets(),
        before + 1,
        "the first download filled the cache"
    );
    assert_eq!(
        download_bytes(&peer, repo, "cached.lib", "1.0.0").await,
        bytes
    );
    assert_eq!(
        gate.blob_gets(),
        before + 1,
        "the second one did not reach S3"
    );

    // A Range request is served from the cached file.
    let resp = download(&peer, repo, "cached.lib", "1.0.0", Some("bytes=10-19")).await;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
    assert_eq!(
        resp.headers()["content-range"],
        format!("bytes 10-19/{}", bytes.len()).as_str()
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &bytes[10..20]);
    let resp = download(&peer, repo, "cached.lib", "1.0.0", Some("bytes=999999-")).await;
    assert_eq!(resp.status(), 416);
    assert_eq!(gate.blob_gets(), before + 1);

    // The statistics say the same.
    let (u, p) = peer.admin_basic();
    let stats: Value = peer
        .client()
        .get(format!("{}/admin/blob-cache", peer.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats["enabled"], true, "{stats}");
    assert_eq!(stats["fills"], 1, "{stats}");
    assert_eq!(stats["misses"], 1, "{stats}");
    assert_eq!(stats["hits"], 2, "{stats}");
    assert_eq!(stats["limit_auto"], true, "{stats}");
}

#[tokio::test]
async fn cached_packages_keep_resolving_while_s3_is_down() {
    let gate = S3Gate::start().await;
    let cache = tempfile::tempdir().unwrap();
    let builder = || {
        StackBuilder::default()
            .anon(AnonMode::All)
            .s3_endpoint(gate.endpoint())
            .blob_cache(cache.path(), None)
    };
    let srv = builder().start().await;
    let repo = "outage";
    public_repo(&srv, repo).await;
    let cached = make_nupkg("Cached.Lib", "1.0.0");
    assert_eq!(srv.push_nupkg(repo, cached.clone()).await.status(), 201);

    // A package this instance has not cached: pushed through one without a
    // cache.
    let uncached = make_nupkg("Uncached.Lib", "1.0.0");
    {
        let mut other = StackBuilder::default()
            .no_bootstrap_admin()
            .anon(AnonMode::All)
            .start_on(&srv.db_url)
            .await;
        share_admin(&srv, &mut other);
        assert_eq!(other.push_nupkg(repo, uncached.clone()).await.status(), 201);
    }

    // A proxy with one package downloaded (and so cached) and one not.
    let upstream = MockUpstream::start(vec![
        UpstreamPackage::single("proxied.one", "1.0.0", make_nupkg("Proxied.One", "1.0.0")),
        UpstreamPackage::single("proxied.two", "1.0.0", make_nupkg("Proxied.Two", "1.0.0")),
    ])
    .await;
    let resp = srv
        .create_repo(serde_json::json!({
            "name": "proxy",
            "kind": "proxy",
            "remote_url": upstream.index_url(),
            "package_delay_seconds": 0,
            "anonymous_read": true,
        }))
        .await;
    assert_eq!(resp.status(), 201, "create proxy");
    srv.grant_anonymous_read("proxy").await;
    download_bytes(&srv, "proxy", "proxied.one", "1.0.0").await;

    // ── S3 goes down ──
    gate.set_down(true);

    assert_eq!(
        download_bytes(&srv, repo, "cached.lib", "1.0.0").await,
        cached,
        "a cached package restores"
    );
    let nuspec = srv
        .client()
        .get(format!(
            "{}/repository/{repo}/flat/cached.lib/1.0.0/cached.lib.nuspec",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(nuspec.status(), 200, "its manifest too");
    download_bytes(&srv, "proxy", "proxied.one", "1.0.0").await;

    // An uncached one answers 503 + Retry-After; once S3 is known to be down,
    // at once.
    for _ in 0..2 {
        let resp = download(&srv, repo, "uncached.lib", "1.0.0", None).await;
        assert_eq!(resp.status(), 503);
        assert!(resp.headers().contains_key("retry-after"));
    }
    let started = Instant::now();
    let resp = download(&srv, repo, "uncached.lib", "1.0.0", None).await;
    assert_eq!(resp.status(), 503);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "fails fast: {:?}",
        started.elapsed()
    );

    // Writes still need S3.
    let resp = srv
        .push_nupkg(repo, make_nupkg("During.Outage", "1.0.0"))
        .await;
    assert_eq!(resp.status(), 503, "push during the outage");
    assert!(resp.headers().contains_key("retry-after"));
    let resp = download(&srv, "proxy", "proxied.two", "1.0.0", None).await;
    assert_eq!(resp.status(), 503, "first-time proxy download");

    // Still ready: the instance serves what it has.
    let (status, body) = readyz(&srv).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "degraded", "{body}");
    assert_eq!(body["checks"]["object_store"], "degraded", "{body}");
    assert_eq!(body["checks"]["database"], true, "{body}");

    // ── Restart on the persistent cache while S3 is still down ──
    let db_url = srv.db_url.clone();
    let admin = (
        srv.admin_user.clone(),
        srv.admin_pass.clone(),
        srv.admin_scoped_token.clone(),
        srv.admin_token.clone(),
    );
    drop(srv);
    let mut srv = builder().no_bootstrap_admin().start_on(&db_url).await;
    (
        srv.admin_user,
        srv.admin_pass,
        srv.admin_scoped_token,
        srv.admin_token,
    ) = admin;
    assert_eq!(
        download_bytes(&srv, repo, "cached.lib", "1.0.0").await,
        cached,
        "the restarted instance serves its cache"
    );
    assert_eq!(
        download(&srv, repo, "uncached.lib", "1.0.0", None)
            .await
            .status(),
        503
    );
    let (status, body) = readyz(&srv).await;
    assert_eq!(
        (status, &body["status"]),
        (200, &Value::from("degraded")),
        "{body}"
    );

    // ── S3 is back: everything recovers without a restart ──
    gate.set_down(false);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (status, body) = readyz(&srv).await;
        if status == 200 && body["status"] == "ok" {
            assert_eq!(body["checks"]["object_store"], true, "{body}");
            break;
        }
        assert!(Instant::now() < deadline, "never recovered: {body}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        download_bytes(&srv, repo, "uncached.lib", "1.0.0").await,
        uncached
    );
    let resp = srv
        .push_nupkg(repo, make_nupkg("After.Outage", "1.0.0"))
        .await;
    assert_eq!(resp.status(), 201, "pushes work again");
    download_bytes(&srv, "proxy", "proxied.two", "1.0.0").await;
}

/// A registry token for `actions` on `image`, as the admin.
async fn registry_token(srv: &TestServer, image: &str, actions: &str) -> String {
    let (user, password) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/v2/token?scope=repository:{image}:{actions}",
            srv.base_url
        ))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "registry token");
    resp.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string()
}

fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// `POST /v2/<image>/blobs/uploads/?digest=` with the whole blob.
async fn push_blob(srv: &TestServer, token: &str, image: &str, bytes: &[u8]) -> reqwest::Response {
    srv.client()
        .post(format!(
            "{}/v2/{image}/blobs/uploads/?digest={}",
            srv.base_url,
            digest(bytes)
        ))
        .bearer_auth(token)
        .header("content-type", "application/octet-stream")
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap()
}

/// A 503 with `Retry-After`, the registry's `UNAVAILABLE`.
async fn assert_unavailable(resp: reqwest::Response, what: &str) {
    assert_eq!(resp.status(), 503, "{what}");
    assert!(resp.headers().contains_key("retry-after"), "{what}");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["errors"][0]["code"], "UNAVAILABLE", "{what}: {body}");
}

#[tokio::test]
async fn the_registry_answers_503_while_s3_is_down() {
    let gate = S3Gate::start().await;
    let cache = tempfile::tempdir().unwrap();
    let srv = StackBuilder::default()
        .s3_endpoint(gate.endpoint())
        .blob_cache(cache.path(), None)
        .start()
        .await;
    let resp = srv
        .create_repo(serde_json::json!({"name": "images", "kind": "hosted", "format": "docker"}))
        .await;
    assert_eq!(resp.status(), 201, "create docker repo");
    let image = "images/app";

    // An image this instance has not cached: pushed through one without a
    // cache.
    let layer = b"a layer this instance never read".to_vec();
    let config =
        br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#
            .to_vec();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(&config), "size": config.len()},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest(&layer), "size": layer.len()}],
    })
    .to_string()
    .into_bytes();
    {
        let mut other = StackBuilder::default()
            .no_bootstrap_admin()
            .start_on(&srv.db_url)
            .await;
        share_admin(&srv, &mut other);
        let token = registry_token(&other, image, "pull,push").await;
        for blob in [&config, &layer] {
            assert_eq!(push_blob(&other, &token, image, blob).await.status(), 201);
        }
        let resp = other
            .client()
            .put(format!("{}/v2/{image}/manifests/1", other.base_url))
            .bearer_auth(&token)
            .header("content-type", "application/vnd.oci.image.manifest.v1+json")
            .body(manifest.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "push the manifest");
    }

    // A chunked upload whose chunks reached S3 before the outage.
    let token = registry_token(&srv, image, "pull,push").await;
    let resp = srv
        .client()
        .post(format!("{}/v2/{image}/blobs/uploads/", srv.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let mut location = resp.headers()["location"].to_str().unwrap().to_string();
    let chunks: [&[u8]; 2] = [b"first chunk, ", b"second chunk"];
    let mut offset = 0;
    for chunk in chunks {
        let resp = srv
            .client()
            .patch(format!("{}{location}", srv.base_url))
            .bearer_auth(&token)
            .header(
                "content-range",
                format!("{}-{}", offset, offset + chunk.len() - 1),
            )
            .header("content-type", "application/octet-stream")
            .body(chunk.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202, "chunk");
        offset += chunk.len();
        location = resp.headers()["location"].to_str().unwrap().to_string();
    }

    // ── S3 goes down ──
    gate.set_down(true);

    let get = |path: String| {
        let (srv, token) = (&srv, &token);
        async move {
            srv.client()
                .get(format!("{}/v2/{image}/{path}", srv.base_url))
                .bearer_auth(token)
                .header("accept", "application/vnd.oci.image.manifest.v1+json")
                .send()
                .await
                .unwrap()
        }
    };
    assert_unavailable(get(format!("blobs/{}", digest(&layer))).await, "blob pull").await;
    assert_unavailable(get("manifests/1".into()).await, "manifest pull").await;
    assert_unavailable(
        push_blob(&srv, &token, image, b"a layer pushed during the outage").await,
        "blob push",
    )
    .await;
    let resp = srv
        .client()
        .put(format!(
            "{}{location}{}digest={}",
            srv.base_url,
            if location.contains('?') { '&' } else { '?' },
            digest(&chunks.concat())
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_unavailable(resp, "chunked upload finish").await;
}
