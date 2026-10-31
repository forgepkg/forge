//! E2E: the device login (RFC 8628) through an OIDC realm, then `docker
//! login` with the token it minted and a `docker pull`.
//!
//! Drives the **real** forge server over HTTP against a real Postgres
//! testcontainer and the in-process mock OIDC IdP (`MockOidc`), as
//! `docker-credential-forge` and its user would:
//!
//! 1. the client starts a device login (`POST /auth/device/code`) and polls
//!    (`authorization_pending`);
//! 2. the user opens the verification URI with the code filled in, signs in
//!    at the IdP, and comes back to `/device?code=…` with the code kept;
//! 3. the user's session looks the code up and approves it;
//! 4. the client's next poll collects the token, once;
//! 5. the real Docker CLI logs in with it (a fresh `DOCKER_CONFIG`) and pulls
//!    an image of a repository that allows no anonymous reads.
//!
//! The Docker steps are skipped (the test passes trivially after step 4) when
//! no Docker CLI and daemon are available. Requires Docker for Postgres.

#![cfg(feature = "forge-e2e")]

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use forge_e2e::{MockOidc, StackBuilder, TestServer};
use serde_json::{json, Value};

const CLIENT_ID: &str = "forge-e2e-client";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_CLIENT: &str = "docker-credential-forge";

/// A reqwest client that does NOT follow redirects (so we can read the 302s).
fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

/// The `[oidc]` block of the stack (the legacy seed of an OIDC realm, which
/// provisions accounts on their first sign-in).
fn oidc_block(issuer: &str, public_base_url: &str) -> String {
    format!(
        r#"
[oidc]
issuer = "{issuer}"
client_id = "{CLIENT_ID}"
client_secret = "shh-secret"
redirect_url = "{public_base_url}/auth/oidc/callback"
allow_private_issuer = true
"#,
    )
}

fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// A tar archive holding the one file `name` with `content`: an image layer.
fn tar_with(name: &str, content: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut tar = header.to_vec();
    tar.extend_from_slice(content);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
    tar.extend_from_slice(&[0u8; 1024]);
    tar
}

/// The architecture of this host as images name it.
fn image_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

/// Push `image:tag` (one uncompressed layer holding `hello.txt`) as the admin
/// through the registry API.
async fn push_image(srv: &TestServer, image: &str, tag: &str) {
    let (user, password) = srv.admin_basic();
    let token: Value = srv
        .client()
        .get(format!(
            "{}/v2/token?scope=repository:{image}:pull,push",
            srv.base_url
        ))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token["token"].as_str().expect("registry token");
    let layer = tar_with("hello.txt", b"signed in with a device code\n");
    let config = json!({
        "architecture": image_arch(),
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [digest(&layer)]},
    })
    .to_string()
    .into_bytes();
    for blob in [&config, &layer] {
        let resp = srv
            .client()
            .post(format!(
                "{}/v2/{image}/blobs/uploads/?digest={}",
                srv.base_url,
                digest(blob)
            ))
            .bearer_auth(token)
            .header("content-type", "application/octet-stream")
            .body(blob.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "push a blob");
    }
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": digest(&config),
            "size": config.len(),
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": digest(&layer),
            "size": layer.len(),
        }],
    })
    .to_string();
    let resp = srv
        .client()
        .put(format!("{}/v2/{image}/manifests/{tag}", srv.base_url))
        .bearer_auth(token)
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(manifest)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "push the manifest");
}

/// `POST` a form to `path`: the status and the JSON answer.
async fn post_form(srv: &TestServer, path: &str, form: &[(&str, &str)]) -> (u16, Value) {
    let resp = srv
        .client()
        .post(format!("{}{path}", srv.base_url))
        .form(form)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.expect("an OAuth JSON answer"))
}

async fn poll(srv: &TestServer, device_code: &str) -> (u16, Value) {
    post_form(
        srv,
        "/auth/device/token",
        &[
            ("grant_type", GRANT),
            ("client_id", DEVICE_CLIENT),
            ("device_code", device_code),
        ],
    )
    .await
}

/// Whether a Docker CLI with a reachable daemon is on PATH.
fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `docker <args>` with its configuration in `config` (and `stdin`), on a
/// blocking thread so the in-process server keeps answering the daemon.
async fn docker(config: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let config = config.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let stdin = stdin.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new("docker")
            .env("DOCKER_CONFIG", &config)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn docker");
        let mut input = child.stdin.take().expect("stdin");
        if let Some(stdin) = stdin {
            input.write_all(stdin.as_bytes()).expect("write stdin");
        }
        drop(input);
        child.wait_with_output().expect("docker output")
    })
    .await
    .expect("join docker")
}

fn describe(what: &str, out: &Output) -> String {
    format!(
        "{what}: {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_through_oidc_then_docker_login_and_pull() {
    let idp = MockOidc::start(CLIENT_ID).await;
    let issuer = idp.issuer().to_string();
    let srv = StackBuilder::default()
        .bootstrap_admin("root@example.com", "rootpw")
        .with_oidc(move |base| oidc_block(&issuer, base))
        .start()
        .await;

    // A repository that allows no anonymous reads, holding an image.
    let resp = srv
        .create_repo(json!({"name": "device-docker", "kind": "hosted", "format": "docker"}))
        .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    push_image(&srv, "device-docker/hello", "1").await;

    // 1. The client starts the device login and polls.
    let (status, started) = post_form(
        &srv,
        "/auth/device/code",
        &[
            ("client_id", DEVICE_CLIENT),
            ("scope", "read repository:device-docker"),
        ],
    )
    .await;
    assert_eq!(status, 200, "{started}");
    let device_code = started["device_code"].as_str().unwrap().to_string();
    let user_code = started["user_code"].as_str().unwrap().to_string();
    let complete = started["verification_uri_complete"].as_str().unwrap();
    assert_eq!(
        complete,
        format!("{}/device?code={user_code}", srv.base_url)
    );
    let (status, pending) = poll(&srv, &device_code).await;
    assert_eq!(
        (status, pending["error"].as_str()),
        (400, Some("authorization_pending"))
    );

    // 2. The user opens the link: the web UI's login gate sends them to the
    //    IdP with the page as the target, and back there signed in.
    let target = format!("/device?code={user_code}");
    let redirect_to: String = url::form_urlencoded::byte_serialize(target.as_bytes()).collect();
    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/login?redirect_to={redirect_to}",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302, "login redirects to the IdP");
    let authorize = resp.headers()["location"].to_str().unwrap().to_string();
    let state = url::Url::parse(&authorize)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("state");
    let nonce: String = sqlx::query_scalar("SELECT nonce FROM oidc_flow WHERE state = $1")
        .bind(&state)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    idp.set_next_id_token(idp.id_claims("sub-dana", "dana@example.com", &nonce, json!([])))
        .await;
    let resp = no_redirect_client()
        .get(format!(
            "{}/auth/oidc/callback?code=mock-code&state={state}",
            srv.base_url
        ))
        .header(
            "cookie",
            format!(
                "forge_oidc_flow={}",
                forge_core::oidc::browser_binding(&state)
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers()["location"].to_str().unwrap(),
        target,
        "the sign-in keeps the code"
    );
    let cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("forge_session="))
        .expect("session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let me: Value = srv
        .client()
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["username"], "dana@example.com");
    let csrf = me["csrf_token"].as_str().unwrap().to_string();
    // The provisioned account may use every repository (the built-in
    // writer role); the token's scope narrows that to reading one.
    let writer = srv.role_id("writer").await;
    let resp = srv
        .assign_role(me["user_id"].as_i64().unwrap(), writer)
        .await;
    assert!(resp.status().is_success(), "{}", resp.status());

    // 3. The page looks the code up and the user approves it.
    let shown: Value = srv
        .client()
        .post(format!("{}/auth/device/lookup", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({"user_code": user_code}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(shown["client_name"], "Docker credential helper");
    assert_eq!(
        shown["scope"],
        json!({"level": "read", "repositories": ["device-docker"]})
    );
    let resp = srv
        .client()
        .post(format!("{}/auth/device/decide", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({"user_code": user_code, "approve": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 4. The client's next poll collects the token, once.
    let (status, token) = poll(&srv, &device_code).await;
    assert_eq!(status, 200, "{token}");
    assert_eq!(token["username"], "dana@example.com");
    let secret = token["access_token"].as_str().unwrap().to_string();
    let (status, again) = poll(&srv, &device_code).await;
    assert_eq!(
        (status, again["error"].as_str()),
        (400, Some("expired_token"))
    );

    // 5. The Docker CLI logs in with the token and pulls.
    if !docker_available() {
        eprintln!("no Docker CLI and daemon; skipping docker login and pull");
        return;
    }
    let registry = srv.base_url.trim_start_matches("http://").to_string();
    let reference = format!("{registry}/device-docker/hello:1");
    let config = tempfile::tempdir().unwrap();
    // Without credentials the repository is closed.
    let out = docker(config.path(), &["pull", &reference], None).await;
    assert!(
        !out.status.success(),
        "{}",
        describe("anonymous pull", &out)
    );
    let out = docker(
        config.path(),
        &[
            "login",
            &registry,
            "--username",
            "dana@example.com",
            "--password-stdin",
        ],
        Some(&secret),
    )
    .await;
    assert!(out.status.success(), "{}", describe("docker login", &out));
    let out = docker(config.path(), &["pull", &reference], None).await;
    let pulled = out.status.success();
    let report = describe("docker pull", &out);
    let inspected = docker(
        config.path(),
        &["image", "inspect", "--format", "{{.Id}}", &reference],
        None,
    )
    .await;
    // Leave the daemon as it was.
    let _ = docker(config.path(), &["image", "rm", "--force", &reference], None).await;
    let _ = docker(config.path(), &["logout", &registry], None).await;
    assert!(pulled, "{report}");
    assert!(
        inspected.status.success(),
        "{}",
        describe("docker image inspect", &inspected)
    );
}
