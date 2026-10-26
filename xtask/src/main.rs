//! Forge task runner — the single entry point for local dev + CI-adjacent
//! chores. Replaces the former Makefile + Justfile.
//!
//! Run `cargo xtask help` (or `cargo xtask` with no args) for the command list.
//! Every subcommand shells out to docker / cargo / pnpm / sqlx and streams their
//! output; a non-zero child exit makes `xtask` exit non-zero too.

mod changelog;
mod proc;
mod release;

use proc::{Cmd, RunningCmd};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::process::{ExitCode, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

// ── Shared constants (mirror docker-compose.yml + forge.toml) ────────────────

/// Web SPA project directory (relative to repo root / cwd).
const WEB: &str = "web";

/// docker-compose dev Postgres: host :5433 -> container :5432 (db/user/pw=forge).
const DOCKER_DB_URL: &str = "postgres://forge:forge@localhost:5433/forge";

/// Local host Postgres (`--db local`): conventional :5432, same forge role/db.
const LOCAL_DB_URL: &str = "postgres://forge:forge@localhost:5432/forge";

/// Default base URL of a running forge-server (used by `seed`).
const DEFAULT_FORGE_URL: &str = "http://127.0.0.1:8421";

/// Default forge-server HTTP port (mirrors forge.toml).
const DEFAULT_FORGE_PORT: u16 = 8421;

/// Vite dev-server HTTP port (mirrors web/vite.config.ts).
const VITE_DEV_PORT: u16 = 8420;

/// Default bootstrap admin credentials from forge.toml (used by `seed`).
const DEFAULT_ADMIN: &str = "admin@example.com:changeme";

/// The root key of the local development stack, exported as `FORGE_ROOT_KEY`
/// unless it is set (forge.toml reads it from there): base64 of
/// `dev-root-key-for-local-forge-001`, the key docker-compose.app.yml sets
/// too. Development only.
const DEV_ROOT_KEY: &str = "ZGV2LXJvb3Qta2V5LWZvci1sb2NhbC1mb3JnZS0wMDE=";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest: &[String] = args.get(1..).unwrap_or(&[]);

    let result = match cmd {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        // Infra (docker compose)
        "up" => up(),
        "down" => down(),
        "logs" => logs(),
        "ps" => ps(),
        "psql" => psql(),
        // Server
        "run" => run_server(),
        "dev" => dev(rest),
        "seed" => seed(),
        // Web SPA
        "web" => web_build(),
        "web-install" => web_install(),
        "web-dev" => web_dev(),
        "web-test" => web_test(),
        "web-e2e" => web_e2e(),
        // Rust build / quality
        "build" => build(),
        "check" => check(),
        "fmt" => fmt(),
        "clippy" => clippy(),
        "test" => test(),
        "e2e" => e2e(),
        "migrate" => migrate(),
        "prepare" => prepare(),
        "prepare-check" => prepare_check(),
        "clean" => clean(),
        // Docker image (build it; run it against the dev infra)
        "docker-build" => docker_build(rest),
        "docker-run" => docker_run(),
        // Release
        "changelog" => changelog::changelog(rest),
        "release" => release::release(rest),
        other => {
            eprintln!("xtask: unknown command `{other}`\n");
            print_help();
            Err(String::from("unknown command"))
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("\x1b[31mxtask: {msg}\x1b[0m");
            ExitCode::FAILURE
        }
    }
}

// ── Help ─────────────────────────────────────────────────────────────────────

fn print_help() {
    print!(
        r#"Forge task runner (cargo xtask <command>)

One-command dev:
  dev [--db local|docker|none]  Bring up infra, run forge-server + Vite HMR.
                                --db local (default): host Postgres on :5432
                                             (forge role+db auto-created), server pointed
                                             there via FORGE_DATABASE__URL.
                                --db docker: docker-compose Postgres (:5433).
                                --db none:   assume a DB is already up (no Postgres started).
                                versitygw (S3) always comes up via docker unless --db none.

Infrastructure (docker compose):
  up            Start Postgres + versitygw, wait until healthy.
  down          Stop and remove the dev containers.
  logs          Tail the dev container logs.
  ps            Show dev container status.
  psql          Open a psql shell on the dev database.

Server:
  run           Run forge-server (expects `up` first; loads ./forge.toml).
  seed          Demo data: anonymous reads + password Basic on, anonymous-readable repo
                + token, push the sample fixture (server must already be running).
                Honors FORGE_URL / ADMIN env vars.

Web UI (TanStack Router SPA in web/):
  web           Build the SPA into web/dist/ (run before `run` for single-origin prod-like).
  web-install   Install web dependencies (pnpm, frozen lockfile).
  web-dev       Run the Vite dev server (HMR) against a running forge-server.
  web-test      Run frontend unit/component tests (Vitest + RTL).
  web-e2e       Run the Playwright e2e suite (needs Docker; builds the UI first).

Rust build & quality:
  build         Build the whole workspace (SQLX_OFFLINE).
  check         fmt --check + clippy -D warnings.
  fmt           Verify formatting (cargo fmt --all --check).
  clippy        Lint with warnings denied.
  test          Run unit + integration tests (needs Docker for testcontainers).
  e2e           Run the end-to-end suite (forge-e2e feature; needs Docker).
  migrate       Apply all migrations against the live DB (sqlx migrate run).
  prepare       Migrate, then regenerate the sqlx offline cache (needs `up` + sqlx-cli).
  prepare-check Migrate, then verify the committed .sqlx/ cache is in sync (CI's drift guard).
  clean         Remove build artifacts (cargo clean).

Docker image (single container: web SPA + Rust server):
  docker-build [--platform <os/arch>]
                Build the application image forge:latest from ./Dockerfile
                (multi-stage: pnpm builds the SPA, cargo builds forge-server
                release), for the host's platform unless --platform names
                another one (linux/amd64, linux/arm64), passed to
                `docker buildx build`.
  docker-run    Run the built image against the dev Postgres + versitygw
                (docker-compose.yml + docker-compose.app.yml), API + SPA on :8421.

Changelog (a fragment per change, docs/changes/<milestone>/<ref>.<kind>.md;
see docs/changes/README.md):
  changelog <milestone>
                Fold the milestone's fragments into CHANGELOG.md's [Unreleased]
                and delete them, to edit the notes in a pull request before the
                release.
  changelog --check
                Check that every file under docs/changes is a fragment and that
                no fragment's milestone is released already (CI).

Release:
  release <version> [--no-tag]
                Set <version> in Cargo.toml/Cargo.lock, web/package.json, the
                Kubernetes base's image tag and the Helm chart, fold the fragments
                of docs/changes/<version>/ into CHANGELOG.md's [Unreleased] and
                delete them, turn [Unreleased] into its section and commit on
                release-<version> (HEAD must be origin/main). Then, with `gh`:
                open a pull request, wait for its CI run, merge it, wait for the
                merge commit's CI run on main, tag the merge commit v<version> and
                push the tag. When main already carries <version>, tags main's
                head once its CI passed. Refuses a changelog with an untagged
                version section, entries under [Unreleased] or fragments next to
                a drafted <version> section, and fragments of another milestone.
                --no-tag: only commit, on the current branch; never pushes.

  help          Show this help.
"#
    );
}

// ── Infrastructure ───────────────────────────────────────────────────────────

/// `docker compose ...` with the leading subcommand already applied.
fn compose(sub: &[&str]) -> Cmd {
    Cmd::new("docker").arg("compose").args(sub)
}

fn up() -> Result<(), String> {
    compose(&["up", "-d", "--wait"]).run()
}

fn down() -> Result<(), String> {
    compose(&["down"]).run()
}

fn logs() -> Result<(), String> {
    compose(&["logs", "-f"]).run()
}

fn ps() -> Result<(), String> {
    compose(&["ps"]).run()
}

fn psql() -> Result<(), String> {
    compose(&["exec", "db", "psql", "-U", "forge", "-d", "forge"]).run()
}

// ── Server ───────────────────────────────────────────────────────────────────

fn run_server() -> Result<(), String> {
    print_forge_portal();
    run_server_cmd().run()
}

/// `cargo ...` with SQLX_OFFLINE=true so a live DB isn't needed to build.
fn cargo(args: &[&str]) -> Cmd {
    Cmd::new("cargo").args(args).env("SQLX_OFFLINE", "true")
}

fn run_server_cmd() -> Cmd {
    let cmd = cargo(&["run", "-p", "forge-server"]);
    match env::var_os("FORGE_ROOT_KEY") {
        Some(_) => cmd,
        None => cmd.env("FORGE_ROOT_KEY", DEV_ROOT_KEY),
    }
}

fn print_forge_portal() {
    print_portal_urls("Forge portal", forge_server_port());
}

fn print_vite_portal() {
    println!();
    println!("Vite portal (HMR):");
    print_url_lines(VITE_DEV_PORT);
    let api_target =
        env::var("FORGE_DEV_API_TARGET").unwrap_or_else(|_| DEFAULT_FORGE_URL.to_string());
    println!("  API proxy target: {api_target}");
    println!();
}

fn print_dev_portals() {
    println!();
    println!("Development portal:");
    println!("  UI:");
    print_url_lines(VITE_DEV_PORT);
    println!("  API:");
    print_url_lines(forge_server_port());
    println!();
}

fn print_portal_urls(label: &str, port: u16) {
    println!();
    println!("{label}:");
    print_url_lines(port);
    println!();
}

fn print_url_lines(port: u16) {
    println!("  local:   http://127.0.0.1:{port}");
    if let Some(ip) = lan_ipv4() {
        println!("  network: http://{ip}:{port}");
    }
}

fn forge_server_port() -> u16 {
    env::var("FORGE_SERVER__BIND")
        .ok()
        .and_then(|bind| bind_port(&bind))
        .unwrap_or(DEFAULT_FORGE_PORT)
}

fn bind_port(bind: &str) -> Option<u16> {
    bind.parse::<SocketAddr>()
        .ok()
        .map(|addr| addr.port())
        .or_else(|| bind.rsplit_once(':')?.1.parse().ok())
}

fn lan_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

// ── dev: the one command ─────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum DbMode {
    Docker,
    Local,
    None,
}

fn parse_db_mode(rest: &[String]) -> Result<DbMode, String> {
    let mut i = 0;
    // Default to the host's local Postgres (:5432); pass `--db docker` for the
    // self-contained docker-compose DB, or `--db none` to use an already-running one.
    let mut mode = DbMode::Local;
    while i < rest.len() {
        match rest[i].as_str() {
            "--db" => {
                let val = rest
                    .get(i + 1)
                    .ok_or_else(|| "--db requires a value (local|docker|none)".to_string())?;
                mode = db_mode_from_str(val)?;
                i += 2;
            }
            other if other.starts_with("--db=") => {
                mode = db_mode_from_str(&other["--db=".len()..])?;
                i += 1;
            }
            other => return Err(format!("unknown `dev` argument `{other}`")),
        }
    }
    Ok(mode)
}

fn db_mode_from_str(s: &str) -> Result<DbMode, String> {
    match s {
        "docker" => Ok(DbMode::Docker),
        "local" => Ok(DbMode::Local),
        "none" => Ok(DbMode::None),
        other => Err(format!(
            "invalid --db value `{other}` (want local|docker|none)"
        )),
    }
}

fn dev(rest: &[String]) -> Result<(), String> {
    let mode = parse_db_mode(rest)?;

    match mode {
        DbMode::Docker => {
            // Full docker-compose stack (Postgres :5433 + versitygw :8422),
            // then Rust API + Vite HMR.
            up()?;
            run_dev_processes(run_server_cmd())
        }
        DbMode::Local => {
            // Host Postgres on :5432: ensure the forge role + db exist, then
            // bring up ONLY versitygw via compose, then run the server pointed
            // at the local DB plus Vite HMR.
            ensure_local_db()?;
            compose(&["up", "-d", "--wait", "s3"]).run()?;
            run_dev_processes(run_server_cmd().env("FORGE_DATABASE__URL", LOCAL_DB_URL))
        }
        DbMode::None => {
            // Assume the DB (and S3) are already up; run API + Vite HMR.
            run_dev_processes(run_server_cmd())
        }
    }
}

fn run_dev_processes(server_cmd: Cmd) -> Result<(), String> {
    pnpm_install()?;

    let mut children = vec![server_cmd.spawn()?];
    wait_for_forge_server(&mut children[0])?;

    match Cmd::new("pnpm")
        .args(["run", "dev"])
        .current_dir(WEB)
        .spawn()
    {
        Ok(vite) => children.push(vite),
        Err(e) => {
            children[0].kill();
            return Err(e);
        }
    }

    print_dev_portals();
    wait_for_dev_processes(&mut children)
}

fn wait_for_forge_server(server: &mut RunningCmd) -> Result<(), String> {
    let port = forge_server_port();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + Duration::from_secs(120);

    eprintln!("waiting for forge-server on http://127.0.0.1:{port} ...");
    loop {
        if let Some(status) = server.try_wait()? {
            return Err(format!(
                "`{}` exited with {} before listening on {addr}",
                server.label(),
                status_desc(status)
            ));
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            server.kill();
            return Err(format!(
                "timed out waiting for forge-server to listen on {addr}"
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn wait_for_dev_processes(children: &mut [RunningCmd]) -> Result<(), String> {
    loop {
        for i in 0..children.len() {
            if let Some(status) = children[i].try_wait()? {
                for (j, child) in children.iter_mut().enumerate() {
                    if i != j {
                        child.kill();
                    }
                }

                if status.success() {
                    return Ok(());
                }
                return Err(format!(
                    "`{}` exited with {}",
                    children[i].label(),
                    status_desc(status)
                ));
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn status_desc(status: ExitStatus) -> String {
    status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "a signal".to_string())
}

/// For `--db local`: create the `forge` role + `forge` database on the host
/// Postgres (:5432) if they don't already exist. Uses `psql` against the
/// `postgres` maintenance DB; idempotent (ignores "already exists").
fn ensure_local_db() -> Result<(), String> {
    // Connect as the invoking OS user to the default `postgres` database. We run
    // each statement separately and tolerate "already exists" so re-runs are safe.
    let admin_uri = "postgres://localhost:5432/postgres";

    // Create role if missing.
    let create_role = "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'forge') \
         THEN CREATE ROLE forge LOGIN PASSWORD 'forge'; END IF; END $$;";
    Cmd::new("psql")
        .args(["-v", "ON_ERROR_STOP=1", admin_uri, "-c", create_role])
        .run()
        .map_err(|e| {
            format!("{e}\nhint: is a host Postgres listening on :5432? (try `--db docker`)")
        })?;

    // Create database if missing (CREATE DATABASE can't run inside DO/transaction,
    // so guard via a shell check on the catalog).
    let exists = Cmd::new("psql")
        .args([
            "-tA",
            admin_uri,
            "-c",
            "SELECT 1 FROM pg_database WHERE datname = 'forge';",
        ])
        .output_string()?;
    if exists.trim() != "1" {
        Cmd::new("psql")
            .args([
                "-v",
                "ON_ERROR_STOP=1",
                admin_uri,
                "-c",
                "CREATE DATABASE forge OWNER forge;",
            ])
            .run()?;
    }
    Ok(())
}

// ── seed ─────────────────────────────────────────────────────────────────────

fn seed() -> Result<(), String> {
    let forge_url = env::var("FORGE_URL").unwrap_or_else(|_| DEFAULT_FORGE_URL.to_string());
    let admin = env::var("ADMIN").unwrap_or_else(|_| DEFAULT_ADMIN.to_string());
    let (admin_user, admin_password) = admin
        .split_once(':')
        .ok_or_else(|| "ADMIN must be <user>:<password>".to_string())?;

    // The admin API takes a browser session (or an admin-scoped token), never
    // a password over Basic: sign in through /auth/login with a cookie jar.
    let jar = env::temp_dir().join(format!("forge-seed-{}.cookies", std::process::id()));
    let jar = jar.to_string_lossy().to_string();
    let login = Cmd::new("curl")
        .args([
            "-fsS",
            "-c",
            &jar,
            "-X",
            "POST",
            &format!("{forge_url}/auth/login"),
            "-H",
            "content-type: application/json",
            "-d",
            &format!(
                r#"{{"username":"{}","password":"{}"}}"#,
                json_escape(admin_user),
                json_escape(admin_password)
            ),
        ])
        .output_string()?;
    let csrf = extract_json_string(&login, "csrf_token")
        .ok_or_else(|| "could not parse csrf_token from /auth/login".to_string())?;
    let session = |method: &'static str, path: &str, body: &'static str| {
        Cmd::new("curl").args([
            "-fsS".to_string(),
            "-b".to_string(),
            jar.clone(),
            "-X".to_string(),
            method.to_string(),
            format!("{forge_url}{path}"),
            "-H".to_string(),
            format!("X-CSRF-Token: {csrf}"),
            "-H".to_string(),
            "content-type: application/json".to_string(),
            "-d".to_string(),
            body.to_string(),
        ])
    };

    // A dev stack reads anonymously and takes passwords over Basic (so
    // `curl -u admin@example.com:changeme` works on the feeds). These are
    // auth settings now, set in the web UI (Admin → Settings) rather than in
    // forge.toml.
    println!("Opening anonymous reads and password Basic (Admin → Settings)…");
    session(
        "PUT",
        "/admin/settings/auth",
        r#"{"anonymous_mode":"all","allow_password_basic":true}"#,
    )
    .output_string()?;

    println!("Creating hosted repo 'nuget' (anonymous_read=true)…");
    // Repo creation: ignore failure (likely already exists).
    let _ = session(
        "POST",
        "/admin/repositories",
        r#"{"name":"nuget","kind":"hosted","anonymous_read":true}"#,
    )
    .run();

    // Mint a push token for the admin and extract the secret.
    let token_json = session("POST", "/admin/me/tokens", r#"{"name":"dev-seed"}"#).output_string();
    let _ = std::fs::remove_file(&jar);
    let token_json = token_json?;
    let token = extract_json_string(&token_json, "token")
        .ok_or_else(|| "could not parse push token from /admin/me/tokens response".to_string())?;
    println!("  push token: {token}");

    // Push the bundled sample package.
    Cmd::new("curl")
        .args([
            "-fsS",
            "-o",
            "/dev/null",
            "-w",
            "  push: HTTP %{http_code}\n",
            "-X",
            "PUT",
            &format!("{forge_url}/repository/nuget/package"),
            "-H",
            &format!("X-NuGet-ApiKey: {token}"),
            "-F",
            "package=@fixtures/nuget/sample.lib.1.0.0.nupkg",
        ])
        .run()?;

    println!("  feed:     {forge_url}/repository/nuget/index.json");
    let versions = Cmd::new("curl")
        .args([
            "-fsS",
            &format!("{forge_url}/repository/nuget/flat/sample.lib/index.json"),
        ])
        .output_string()
        .unwrap_or_default();
    println!("  versions: {versions}");
    Ok(())
}

/// Escape `"` and `\\` for a JSON string literal (the runner has no JSON
/// dependency).
fn json_escape(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Minimal extractor for `"<key>":"<value>"` from a JSON blob. Good enough for
/// the single-field token response; avoids a JSON dependency in the runner.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle)? + needle.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_string())
}

// ── Web SPA (pnpm) ───────────────────────────────────────────────────────────

/// `pnpm install --frozen-lockfile` inside web/.
fn pnpm_install() -> Result<(), String> {
    Cmd::new("pnpm")
        .args(["install", "--frozen-lockfile"])
        .current_dir(WEB)
        .run()
}

fn web_install() -> Result<(), String> {
    pnpm_install()
}

fn web_build() -> Result<(), String> {
    pnpm_install()?;
    Cmd::new("pnpm")
        .args(["run", "build"])
        .current_dir(WEB)
        .run()
}

fn web_dev() -> Result<(), String> {
    pnpm_install()?;
    print_vite_portal();
    Cmd::new("pnpm").args(["run", "dev"]).current_dir(WEB).run()
}

fn web_test() -> Result<(), String> {
    pnpm_install()?;
    Cmd::new("pnpm")
        .args(["run", "test"])
        .current_dir(WEB)
        .run()
}

fn web_e2e() -> Result<(), String> {
    pnpm_install()?;
    Cmd::new("pnpm")
        .args(["run", "build"])
        .current_dir(WEB)
        .run()?;
    Cmd::new("pnpm").args(["run", "e2e"]).current_dir(WEB).run()
}

// ── Rust build & quality ─────────────────────────────────────────────────────

fn build() -> Result<(), String> {
    cargo(&["build", "--workspace"]).run()
}

fn check() -> Result<(), String> {
    fmt()?;
    clippy()
}

fn fmt() -> Result<(), String> {
    cargo(&["fmt", "--all", "--check"]).run()
}

fn clippy() -> Result<(), String> {
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ])
    .run()
}

fn test() -> Result<(), String> {
    cargo(&["test", "--workspace"]).run()
}

fn e2e() -> Result<(), String> {
    cargo(&["test", "-p", "forge-e2e", "--features", "forge-e2e"]).run()
}

/// The live DB sqlx talks to for `migrate` / `prepare` / `prepare-check`. The
/// docker-compose Postgres (:5433) by default; override with `DATABASE_URL`.
fn sqlx_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| DOCKER_DB_URL.to_string())
}

/// Apply all migrations against the live DB (`sqlx migrate run`).
fn migrate() -> Result<(), String> {
    Cmd::new("sqlx")
        .args(["migrate", "run", "--source", "migrations"])
        .env("DATABASE_URL", sqlx_database_url())
        .run()
}

/// Regenerate the committed .sqlx/ offline cache from a live DB. Applies
/// migrations first, then runs `cargo sqlx prepare`. Needs `up` (or a reachable
/// DATABASE_URL) + sqlx-cli.
fn prepare() -> Result<(), String> {
    migrate()?;
    sqlx_prepare(&[])
}

/// Verify the committed .sqlx/ cache is in sync (CI's drift guard). Applies
/// migrations first, then `cargo sqlx prepare --check`.
fn prepare_check() -> Result<(), String> {
    migrate()?;
    sqlx_prepare(&["--check"])
}

/// Shared `cargo sqlx prepare [extra] --workspace -- --all-targets --all-features`.
fn sqlx_prepare(extra: &[&str]) -> Result<(), String> {
    let mut args = vec!["sqlx", "prepare"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--workspace", "--", "--all-targets", "--all-features"]);
    Cmd::new("cargo")
        .args(args)
        .env("DATABASE_URL", sqlx_database_url())
        .run()
}

fn clean() -> Result<(), String> {
    Cmd::new("cargo").arg("clean").run()
}

// ── Docker image (single-container web SPA + Rust server) ────────────────────

/// Build the single application image from the root Dockerfile (multi-stage:
/// pnpm builds the SPA, cargo builds forge-server release, slim runtime bundles
/// both). The build is self-contained (SQLX_OFFLINE inside the image) and does
/// not need a live DB. `--platform` builds the image of another platform than
/// the host's (the release publishes linux/amd64 and linux/arm64), which needs
/// a builder that runs it, natively or under QEMU emulation.
fn docker_build(rest: &[String]) -> Result<(), String> {
    let build = match parse_platform(rest)? {
        None => Cmd::new("docker").arg("build"),
        // `--load`: into the local image store, like `docker build`.
        Some(platform) => Cmd::new("docker")
            .args(["buildx", "build", "--load", "--platform"])
            .arg(platform),
    };
    build
        .args(["-t", "forge:latest", "-f", "Dockerfile", "."])
        .run()
}

/// `--platform <os/arch>` (or `--platform=<os/arch>`) of `docker-build`.
fn parse_platform(rest: &[String]) -> Result<Option<&str>, String> {
    let mut platform = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--platform" => {
                let val = rest
                    .get(i + 1)
                    .ok_or_else(|| "--platform requires a value (e.g. linux/arm64)".to_string())?;
                platform = Some(val.as_str());
                i += 2;
            }
            other if other.starts_with("--platform=") => {
                platform = Some(&other["--platform=".len()..]);
                i += 1;
            }
            other => return Err(format!("unknown `docker-build` argument `{other}`")),
        }
    }
    match platform {
        Some("") => Err("--platform requires a value (e.g. linux/arm64)".to_string()),
        _ => Ok(platform),
    }
}

/// Run the built image against the dev Postgres + versitygw. Composes the base
/// docker-compose.yml (db + s3) with docker-compose.app.yml (the app service),
/// building the image if needed. Serves the API + SPA on http://localhost:8421.
fn docker_run() -> Result<(), String> {
    print_forge_portal();
    compose_app(&["up", "--build"]).run()
}

/// `docker compose -f docker-compose.yml -f docker-compose.app.yml <sub...>`:
/// the base infra stack plus the built application image.
fn compose_app(sub: &[&str]) -> Cmd {
    Cmd::new("docker")
        .args([
            "compose",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.app.yml",
        ])
        .args(sub)
}
