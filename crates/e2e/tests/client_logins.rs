//! E2E: a client's native login against Forge, as against Nexus (#39), with
//! the **real** Docker CLI.
//!
//! Drives the forge server over HTTP against a real Postgres testcontainer
//! and the in-process mock HTTP Basic upstream (`MockBasicUpstream`, a Nexus
//! stand-in) behind a credential-forwarding realm. The local realm accepts
//! no passwords from clients, its default:
//!
//! 1. the registry's token service (`/v2/token`, what `docker login` and
//!    `helm registry login` ask) issues a token for the forwarded user's
//!    upstream password, refuses a local user's password like a wrong one
//!    without asking the upstream, and issues one for that user's API token;
//! 2. curl downloads from a raw repository with the upstream password, not
//!    with the local password, and with the local user's API token as the
//!    Basic password or a Bearer token;
//! 3. `docker login` with the upstream password, then a `docker push` and a
//!    `docker pull` of an image `docker import` made;
//! 4. `docker login` with the local user's password fails, and with their API
//!    token (a token from the web UI's **Your tokens**) it works and pulls.
//!
//! The curl and Docker steps are skipped (the test passes without them) when
//! curl, or a Docker CLI and daemon, are not available. Requires Docker for
//! Postgres.

#![cfg(feature = "forge-e2e")]

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use forge_e2e::{MockBasicUpstream, StackBuilder, TestServer};
use serde_json::{json, Value};

/// The upstream's account, Forge's account of the forwarding realm (a UPN
/// with that local part), and the password only the upstream knows.
const UP_NAME: &str = "nexus-bob";
const UP_USER: &str = "nexus-bob@example.com";
const UP_PASS: &str = "upstream-only-pw";

/// A local account and its Forge password.
const LOCAL_USER: &str = "carol@example.com";
const LOCAL_PASS: &str = "carols-local-pw";

/// The realm the stack imports the `[auth.upstream_basic]` block into.
const REALM: &str = "upstream-basic";

/// The hosted docker repository of the test.
const REPO: &str = "logins-docker";

/// The hosted raw repository of the test, and the file in it.
const RAW: &str = "logins-raw";
const RAW_FILE: &str = "tools/hello.txt";
const RAW_CONTENT: &str = "downloaded with curl\n";

/// An admin API request with the bootstrap admin's admin-scoped token.
fn admin(srv: &TestServer, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
    let (user, token) = srv.admin_basic();
    srv.client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(user, Some(token))
}

/// Have the local realm accept no passwords from clients (the stack opens
/// it for the other tests), through the admin API, which also drops the
/// server's cached realms.
async fn close_local_client_passwords(srv: &TestServer) {
    let realms: Value = admin(srv, reqwest::Method::GET, "/admin/realms")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let local = realms
        .as_array()
        .and_then(|realms| realms.iter().find(|r| r["kind"] == "local"))
        .and_then(|r| r["id"].as_i64())
        .unwrap_or_else(|| panic!("no local realm: {realms}"));
    let resp = admin(
        srv,
        reqwest::Method::PATCH,
        &format!("/admin/realms/{local}"),
    )
    .json(&json!({"config": {"accept_client_passwords": false}}))
    .send()
    .await
    .unwrap();
    assert!(
        resp.status().is_success(),
        "close the local realm: {}",
        resp.text().await.unwrap()
    );
}

/// `GET /v2/token` for pushing and pulling the test's repository, with
/// Basic `user` / `secret`, as `docker login` and a push ask it.
async fn registry_token(srv: &TestServer, user: &str, secret: &str) -> reqwest::StatusCode {
    srv.client()
        .get(format!(
            "{}/v2/token?service=forge&scope=repository:{REPO}/hello:pull,push",
            srv.base_url
        ))
        .basic_auth(user, Some(secret))
        .send()
        .await
        .unwrap()
        .status()
}

/// A tar archive holding the one file `name` with `content`: the root
/// filesystem `docker import` makes an image of.
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

/// Whether curl is on PATH.
fn curl_available() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `curl <args> <url>`: the HTTP status and the body, on a blocking thread
/// so the in-process server keeps answering.
async fn curl(args: &[&str], url: &str) -> (String, String) {
    let mut args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    args.extend([
        "-sS".into(),
        "-w".into(),
        "\n%{http_code}".into(),
        url.into(),
    ]);
    let out = tokio::task::spawn_blocking(move || {
        Command::new("curl").args(&args).output().expect("run curl")
    })
    .await
    .expect("join curl");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, status) = stdout.rsplit_once('\n').unwrap_or(("", &stdout));
    (
        status.to_string(),
        format!("{body}{}", String::from_utf8_lossy(&out.stderr)),
    )
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
async fn docker(config: &Path, args: &[&str], stdin: Option<Vec<u8>>) -> Output {
    let config = config.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
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
            input.write_all(&stdin).expect("write stdin");
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

/// `docker login <registry>` as `user` with `secret` on stdin.
async fn docker_login(config: &Path, registry: &str, user: &str, secret: &str) -> Output {
    docker(
        config,
        &["login", registry, "--username", user, "--password-stdin"],
        Some(secret.as_bytes().to_vec()),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarded_user_logs_docker_in_with_the_upstream_password() {
    let mock = MockBasicUpstream::start(vec![(UP_NAME, UP_PASS, vec![])]).await;
    let block = mock.upstream_basic_block(&["local-password", "upstream-basic"], 300, 60, &[], "");
    let srv = StackBuilder::default()
        .bootstrap_admin("root@example.com", "rootpw")
        .with_upstream_basic(block)
        .start()
        .await;
    close_local_client_passwords(&srv).await;

    // The forwarded account (created by an administrator: the realm creates
    // none) and a local one, both writers, and the repository.
    let resp = admin(&srv, reqwest::Method::POST, "/admin/users")
        .json(&json!({"username": UP_USER, "realm": REALM, "role": "writer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let local_id = srv.create_user(LOCAL_USER, LOCAL_PASS).await;
    let writer = srv.role_id("writer").await;
    let resp = srv.assign_role(local_id, writer).await;
    assert!(resp.status().is_success(), "{}", resp.status());
    let local_token = srv.issue_token(local_id, None).await;
    let resp = srv
        .create_repo(json!({"name": REPO, "kind": "hosted", "format": "docker"}))
        .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let resp = srv
        .create_repo(json!({"name": RAW, "kind": "hosted", "format": "raw"}))
        .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        &format!("/repository/{RAW}/{RAW_FILE}"),
    )
    .body(RAW_CONTENT)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    // 1. The token service: the upstream password works, a local password
    //    is refused without asking the upstream, the local API token works.
    assert_eq!(registry_token(&srv, UP_USER, UP_PASS).await, 200);
    assert_eq!(registry_token(&srv, UP_USER, "not-the-password").await, 401);
    let asked = mock.hits();
    assert_eq!(registry_token(&srv, LOCAL_USER, LOCAL_PASS).await, 401);
    assert_eq!(
        mock.hits(),
        asked,
        "a local account's password is never forwarded"
    );
    assert_eq!(registry_token(&srv, LOCAL_USER, &local_token).await, 200);

    // 2. curl against a raw repository, as against Nexus' raw repositories:
    //    the upstream password downloads, the closed local realm's password
    //    does not, and the local user's API token does, as the Basic
    //    password or as a Bearer token.
    if curl_available() {
        let url = format!("{}/repository/{RAW}/{RAW_FILE}", srv.base_url);
        let upstream_password = format!("{UP_USER}:{UP_PASS}");
        let local_password = format!("{LOCAL_USER}:{LOCAL_PASS}");
        let local_basic_token = format!("{LOCAL_USER}:{local_token}");
        let bearer = format!("Authorization: Bearer {local_token}");
        for (what, args, expected) in [
            (
                "upstream password",
                vec!["-u", upstream_password.as_str()],
                "200",
            ),
            ("local password", vec!["-u", local_password.as_str()], "401"),
            (
                "local API token",
                vec!["-u", local_basic_token.as_str()],
                "200",
            ),
            ("Bearer API token", vec!["-H", bearer.as_str()], "200"),
        ] {
            let (status, body) = curl(&args, &url).await;
            assert_eq!(status, expected, "curl with the {what}: {body}");
            if expected == "200" {
                assert_eq!(body, RAW_CONTENT, "curl with the {what}");
            }
        }
    } else {
        eprintln!("no curl; skipping the raw downloads");
    }

    if !docker_available() {
        eprintln!("no Docker CLI and daemon; skipping docker login, push and pull");
        return;
    }
    let registry = srv.base_url.trim_start_matches("http://").to_string();
    let reference = format!("{registry}/{REPO}/hello:1");

    // 3. `docker login` with the upstream password, then push and pull.
    let forwarded = tempfile::tempdir().unwrap();
    let out = docker_login(forwarded.path(), &registry, UP_USER, UP_PASS).await;
    assert!(
        out.status.success(),
        "{}",
        describe("docker login (upstream password)", &out)
    );
    let out = docker(
        forwarded.path(),
        &["import", "-", &reference],
        Some(tar_with("hello.txt", b"pushed with an upstream password\n")),
    )
    .await;
    assert!(out.status.success(), "{}", describe("docker import", &out));
    let pushed = docker(forwarded.path(), &["push", &reference], None).await;
    let _ = docker(
        forwarded.path(),
        &["image", "rm", "--force", &reference],
        None,
    )
    .await;
    assert!(
        pushed.status.success(),
        "{}",
        describe("docker push", &pushed)
    );
    let pulled = docker(forwarded.path(), &["pull", &reference], None).await;
    let _ = docker(
        forwarded.path(),
        &["image", "rm", "--force", &reference],
        None,
    )
    .await;
    let _ = docker(forwarded.path(), &["logout", &registry], None).await;
    assert!(
        pulled.status.success(),
        "{}",
        describe("docker pull", &pulled)
    );

    // 4. The local user: their password is refused, their API token works.
    let local = tempfile::tempdir().unwrap();
    let out = docker_login(local.path(), &registry, LOCAL_USER, LOCAL_PASS).await;
    assert!(
        !out.status.success(),
        "{}",
        describe("docker login (closed local realm's password)", &out)
    );
    let out = docker_login(local.path(), &registry, LOCAL_USER, &local_token).await;
    assert!(
        out.status.success(),
        "{}",
        describe("docker login (API token)", &out)
    );
    let pulled = docker(local.path(), &["pull", &reference], None).await;
    let _ = docker(local.path(), &["image", "rm", "--force", &reference], None).await;
    let _ = docker(local.path(), &["logout", &registry], None).await;
    assert!(
        pulled.status.success(),
        "{}",
        describe("docker pull (API token)", &pulled)
    );
}
