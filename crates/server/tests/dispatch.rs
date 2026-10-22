//! E2E: repository dispatch + authorization + hosted publish/read round-trip
//! through the full HTTP stack. Requires Docker.

mod common;

use common::ServerOpts;
use serde_json::Value;

fn session_cookie(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("set-cookie")
        .expect("login sets session cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// Unknown repository → 404 from the dispatcher.
#[tokio::test]
async fn unknown_repo_is_404() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}/v3/does-not-exist/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// A repository name that does not exist answers exactly like one the caller
/// may not read — 401 anonymously, 403 signed in, same body — on the feed and
/// in the browse API, so names cannot be enumerated. (A global admin, who can
/// list them anyway, still gets 404: [`unknown_repo_is_404`].)
#[tokio::test]
async fn unknown_repo_answers_like_a_denied_one() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let private = format!("private{}", common::unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": private, "kind": "hosted", "anonymous_read": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let user = forge_db::user_dao::insert_user(
        &srv.pool,
        forge_db::user_dao::NewUser::local(
            format!("nogrants{}", common::unique()),
            "$argon2id$unused".into(),
            false,
            true,
        ),
    )
    .await
    .unwrap();
    let session = srv.session_for(user.id).await;

    let answer = |path: String, signed_in: bool| {
        let mut req = client.get(format!("{}{path}", srv.base_url));
        if signed_in {
            req = session.apply(req);
        }
        async move {
            let resp = req.send().await.unwrap();
            (resp.status().as_u16(), resp.text().await.unwrap())
        }
    };
    let unknown = format!("absent{}", common::unique());
    for (path, signed_in, status) in [
        ("/v3/{}/index.json", false, 401),
        ("/v3/{}/index.json", true, 403),
        ("/browse/packages/{}/Foo", true, 403),
    ] {
        let denied = answer(path.replace("{}", &private), signed_in).await;
        let missing = answer(path.replace("{}", &unknown), signed_in).await;
        assert_eq!(denied.0, status, "{path} on a private repository");
        assert_eq!(missing, denied, "{path}: unknown answers like denied");
    }
}

/// Every `/v3` response — also the ones the dispatcher answers itself before
/// the per-repository router runs — is a sandboxed, script-free download, so
/// publisher-controlled feed content can never execute on the admin origin.
#[tokio::test]
async fn feed_responses_are_sandboxed_downloads() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("hosted{}", common::unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    for (path, authenticated) in [
        ("/v3/does-not-exist/index.json".to_string(), true),
        (format!("/v3/{repo}/index.json"), false),
        (format!("/v3/{repo}/index.json"), true),
        (format!("/v3/{repo}/flat/x/1.0.0/x.nuspec"), true),
    ] {
        let mut req = client.get(format!("{}{path}", srv.base_url));
        if authenticated {
            req = req.basic_auth(&u, Some(&p));
        }
        let resp = req.send().await.unwrap();
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(
            header("content-security-policy").as_deref(),
            Some("default-src 'none'; sandbox"),
            "{path} ({})",
            resp.status()
        );
        assert_eq!(
            header("content-disposition").as_deref(),
            Some("attachment"),
            "{path}"
        );
        assert_eq!(
            header("x-content-type-options").as_deref(),
            Some("nosniff"),
            "{path}"
        );
    }
}

/// With `anonymous_mode = off`, an unauthenticated read of a non-anon repo is
/// 401; an admin (authenticated) read succeeds and the service index advertises
/// `PackagePublish` for a hosted repo.
#[tokio::test]
async fn read_authz_and_service_index() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("hosted{}", common::unique());

    // Create a hosted repo (not anonymous_read).
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Anonymous read → 401 (anon mode off).
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anon read of non-anon repo must be 401");
    assert_eq!(
        resp.headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"Forge\""),
        "native NuGet clients need a Basic challenge before sending stored source credentials"
    );

    // Authenticated read → 200, with PackagePublish advertised (hosted).
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let types: Vec<&str> = body["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["@type"].as_str().unwrap())
        .collect();
    assert!(
        types.iter().any(|t| t.starts_with("PackagePublish")),
        "hosted service index must advertise PackagePublish; got {types:?}"
    );
    // Absolute @id from public_base_url.
    let first_id = body["resources"][0]["@id"].as_str().unwrap();
    assert!(
        first_id.starts_with("http://test.local/v3/"),
        "got {first_id}"
    );
}

/// Push to a hosted repo via the NuGet PUT /package multipart endpoint, then
/// restore the same bytes via the flat container and enumerate versions.
#[tokio::test]
async fn hosted_publish_and_restore() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("pub{}", common::unique());
    let id = format!("My.Pkg{}", common::unique());
    let lower = id.to_lowercase();

    client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();

    let bytes = common::make_nupkg(&id, "1.0.0");
    let api_key = srv.admin_token().await;

    // PUT /package as multipart/form-data with the raw .nupkg as the first part.
    // NuGet clients authenticate publish with the X-NuGet-ApiKey header.
    let part = reqwest::multipart::Part::bytes(bytes.clone())
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("package", part);
    let resp = client
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", &api_key)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "publish must return 201");

    // Anonymous push must be rejected even though the read may be allowed.
    let part = reqwest::multipart::Part::bytes(bytes.clone())
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("package", part);
    let resp = client
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anonymous push must be 401");

    // Flat-container version listing.
    let resp = client
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["versions"], serde_json::json!(["1.0.0"]));

    // Download the .nupkg bytes back and compare.
    let resp = client
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/1.0.0/{lower}.1.0.0.nupkg",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let downloaded = resp.bytes().await.unwrap();
    assert_eq!(downloaded.as_ref(), bytes.as_slice(), "round-trip bytes");
}

/// A version longer than NuGet's 64 characters is refused with 400 at push
/// (it used to fail the database insert and answer 500), nothing is stored,
/// and such a version in a request path answers 404.
#[tokio::test]
async fn push_of_an_overlong_version_is_400_and_stores_nothing() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("longver{}", common::unique());
    let id = format!("Long.Ver{}", common::unique());
    let lower = id.to_lowercase();
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let version = format!("1.0.0-{}", "a".repeat(1000));
    let part = reqwest::multipart::Part::bytes(common::make_nupkg(&id, &version))
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let resp = client
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", srv.admin_token().await)
        .multipart(reqwest::multipart::Form::new().part("package", part))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("longer than 64 characters"), "{body}");

    let resp = client
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "nothing was stored");
    let resp = client
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/{version}/{lower}.{version}.nupkg",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// A browser/password session is valid for the admin UI but is not a NuGet
/// publishing credential. An unrelated Authorization scheme must not satisfy
/// the route's wire-credential check while the cookie supplies the principal.
#[tokio::test]
async fn session_plus_junk_authorization_header_cannot_publish() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("sessionpub{}", common::unique());
    let package_id = format!("Session.Bypass{}", common::unique());

    let login = client
        .post(format!("{}/auth/login", srv.base_url))
        .json(
            &serde_json::json!({"username": admin, "password": srv.admin_pass.as_deref().unwrap()}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    let cookie = session_cookie(&login);
    let me: Value = client
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf = me["csrf_token"]
        .as_str()
        .expect("/auth/me returns the csrf token")
        .to_string();

    let created = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    let push = |csrf: Option<&str>| {
        let part = reqwest::multipart::Part::bytes(common::make_nupkg(&package_id, "1.0.0"))
            .file_name("package.nupkg")
            .mime_str("application/octet-stream")
            .unwrap();
        let mut req = client
            .put(format!("{}/v3/{repo}/package", srv.base_url))
            .header("cookie", &cookie)
            .header("authorization", "Unrelated session-bypass")
            .multipart(reqwest::multipart::Form::new().part("package", part));
        if let Some(token) = csrf {
            req = req.header("x-csrf-token", token);
        }
        req.send()
    };
    // Without the CSRF token the cookie-authenticated mutation is refused
    // outright by the CSRF gate …
    let response = push(None).await.unwrap();
    assert_eq!(response.status(), 403, "cookie mutation without csrf token");
    // … and even with it, a session is not a publish credential.
    let response = push(Some(&csrf)).await.unwrap();
    assert_eq!(
        response.status(),
        401,
        "a junk auth header must not upgrade a session into a publish credential"
    );

    let repo_id = forge_db::repository_dao::find_repository_by_name(&srv.pool, &repo)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert!(
        forge_db::component_dao::find_component(&srv.pool, repo_id, &package_id, "1.0.0")
            .await
            .unwrap()
            .is_none(),
        "rejected session publish must not create a component"
    );
}

/// Anonymous read succeeds when the repo is `anonymous_read` and the server is
/// in `anonymous_mode = all`.
#[tokio::test]
async fn anonymous_read_when_allowed() {
    let srv = common::start_with(
        common::pool().await,
        ServerOpts {
            anonymous_mode: "all".into(),
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            ..Default::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("anon{}", common::unique());

    client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted", "anonymous_read": true}))
        .send()
        .await
        .unwrap();

    // Under RBAC, anonymous read flows through a grant on the built-in
    // `anonymous` role (what the RBAC data migration converted the
    // `anonymous_read` flag into), not the column. Seed that grant directly,
    // mirroring the migration, so the seam permits the anonymous read.
    let repo_id = forge_db::repository_dao::find_repository_by_name(&srv.pool, &repo)
        .await
        .unwrap()
        .expect("repo created")
        .id;
    let anon_role = forge_db::authz_dao::role_id_by_name(&srv.pool, "anonymous")
        .await
        .unwrap()
        .expect("anonymous role seeded");
    forge_db::authz_dao::add_grant(&srv.pool, anon_role, Some(repo_id), "read", None)
        .await
        .unwrap();

    // No credentials, anon mode all + anonymous-role read grant → 200.
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "anonymous read should be allowed");
}

/// Regression: pushes above axum's 2 MiB extractor default used to fail with
/// a 500. A 9 MiB package must publish (201) and restore byte-identically
/// (streamed from S3).
#[tokio::test]
async fn large_package_push_and_restore_round_trip() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("big{}", common::unique());
    let id = format!("Big.Pkg{}", common::unique());
    let lower = id.to_lowercase();
    client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&serde_json::json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();

    let bytes = common::make_nupkg_with_payload(&id, "1.0.0", 9 * 1024 * 1024);
    assert!(bytes.len() > 9 * 1024 * 1024);
    let api_key = srv.admin_token().await;
    let part = reqwest::multipart::Part::bytes(bytes.clone())
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let resp = client
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", &api_key)
        .multipart(reqwest::multipart::Form::new().part("package", part))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "a 9 MiB push must be accepted");

    let url = format!(
        "{}/v3/{repo}/flat/{lower}/1.0.0/{lower}.1.0.0.nupkg",
        srv.base_url
    );
    let head = client
        .head(&url)
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(
        head.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(bytes.len().to_string().as_str())
    );
    let resp = client
        .get(&url)
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), bytes.as_slice());
}

/// Liveness and readiness probes answer without authentication.
#[tokio::test]
async fn health_endpoints() {
    let srv = common::start().await;
    let client = srv.client();
    let live = client
        .get(format!("{}/healthz", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(live.status(), 200);
    let ready = client
        .get(format!("{}/readyz", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);
    let body: Value = ready.json().await.unwrap();
    assert_eq!(body["checks"]["database"], true);
    assert_eq!(body["checks"]["object_store"], true);
}

/// #73: an offline hosted or group repository answers every feed request with
/// 503 (pushes included); an offline proxy still serves locally (here its
/// service index). Unauthorized callers still get 401, not the 503.
#[tokio::test]
async fn offline_hosted_and_group_repositories_answer_503() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let hosted = format!("offh{s}");
    let group = format!("offg{s}");
    let proxy = format!("offp{s}");
    for body in [
        serde_json::json!({"name": hosted, "kind": "hosted"}),
        serde_json::json!({"name": group, "kind": "group"}),
        serde_json::json!({"name": proxy, "kind": "proxy",
                           "remote_url": "https://api.nuget.org/v3/index.json"}),
    ] {
        let resp = client
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{body}");
    }
    let index = |repo: &str| format!("{}/v3/{repo}/index.json", srv.base_url);
    for repo in [&hosted, &group, &proxy] {
        let resp = client
            .get(index(repo))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{repo} online");
        let resp = client
            .put(format!("{}/admin/repositories/{repo}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&serde_json::json!({"online": false}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    for repo in [&hosted, &group] {
        let resp = client
            .get(index(repo))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503, "{repo} offline");
        assert!(resp.headers().contains_key("retry-after"));
        let resp = client.get(index(repo)).send().await.unwrap();
        assert_eq!(resp.status(), 401, "{repo}: authorization first");
    }
    let part = reqwest::multipart::Part::bytes(common::make_nupkg(&format!("Off.Pkg{s}"), "1.0.0"))
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let resp = client
        .put(format!("{}/v3/{hosted}/package", srv.base_url))
        .header("X-NuGet-ApiKey", srv.admin_token().await)
        .multipart(reqwest::multipart::Form::new().part("package", part))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503, "no push into an offline repository");
    let resp = client
        .get(index(&proxy))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "an offline proxy serves what it has locally"
    );
}
