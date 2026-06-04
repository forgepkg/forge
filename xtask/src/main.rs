//! envisia-forge task runner — the single entry point for local dev + CI-adjacent
//! chores. Replaces the former Makefile + Justfile.
//!
//! Run `cargo xtask help` (or `cargo xtask` with no args) for the command list.
//! Every subcommand shells out to docker / cargo / pnpm / sqlx and streams their
//! output; a non-zero child exit makes `xtask` exit non-zero too.

mod proc;

use proc::Cmd;
use std::env;
use std::process::ExitCode;

// ── Shared constants (mirror docker-compose.yml + forge.toml) ────────────────

/// Web SPA project directory (relative to repo root / cwd).
const WEB: &str = "web";

/// docker-compose dev Postgres: host :5433 -> container :5432 (db/user/pw=forge).
const DOCKER_DB_URL: &str = "postgres://forge:forge@localhost:5433/forge";

/// Local host Postgres (`--db local`): conventional :5432, same forge role/db.
const LOCAL_DB_URL: &str = "postgres://forge:forge@localhost:5432/forge";

/// Default base URL of a running forge-server (used by `seed`).
const DEFAULT_FORGE_URL: &str = "http://localhost:8420";

/// Default bootstrap admin credentials from forge.toml (used by `seed`).
const DEFAULT_ADMIN: &str = "admin:changeme";

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
        // Docker image (Dockerfile lands in phase 2; thin wrappers now)
        "docker-build" => docker_build(),
        "docker-run" => docker_run(),
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
        r#"envisia-forge task runner (cargo xtask <command>)

One-command dev:
  dev [--db local|docker|none]  Bring up infra, build the SPA, run forge-server.
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
  seed          Demo data: anonymous-readable repo + token, push the sample fixture
                (server must already be running). Honors FORGE_URL / ADMIN env vars.

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
  docker-build  Build the application image from ./Dockerfile (multi-stage:
                pnpm builds the SPA, cargo builds forge-server release).
  docker-run    Run the built image against the dev Postgres + versitygw
                (docker-compose.yml + docker-compose.app.yml), API + SPA on :8420.

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
    cargo(&["run", "-p", "forge-server"]).run()
}

/// `cargo ...` with SQLX_OFFLINE=true so a live DB isn't needed to build.
fn cargo(args: &[&str]) -> Cmd {
    Cmd::new("cargo").args(args).env("SQLX_OFFLINE", "true")
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
            // Full docker-compose stack (Postgres :5433 + versitygw :8422).
            up()?;
            web_build()?;
            run_server()
        }
        DbMode::Local => {
            // Host Postgres on :5432: ensure the forge role + db exist, then
            // bring up ONLY versitygw via compose, build the SPA, and run the
            // server pointed at the local DB via FORGE_DATABASE__URL.
            ensure_local_db()?;
            compose(&["up", "-d", "--wait", "s3"]).run()?;
            web_build()?;
            cargo(&["run", "-p", "forge-server"])
                .env("FORGE_DATABASE__URL", LOCAL_DB_URL)
                .run()
        }
        DbMode::None => {
            // Assume the DB (and S3) are already up; just build + run.
            web_build()?;
            run_server()
        }
    }
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

    println!("Creating hosted repo 'nuget' (anonymous_read=true)…");
    // Repo creation: ignore failure (likely already exists).
    let _ = Cmd::new("curl")
        .args([
            "-fsS",
            "-u",
            &admin,
            "-X",
            "POST",
            &format!("{forge_url}/admin/repositories"),
            "-H",
            "content-type: application/json",
            "-d",
            r#"{"name":"nuget","kind":"hosted","anonymous_read":true}"#,
        ])
        .run();

    // Mint a push token for admin (user id 1) and extract the secret.
    let token_json = Cmd::new("curl")
        .args([
            "-fsS",
            "-u",
            &admin,
            "-X",
            "POST",
            &format!("{forge_url}/admin/users/1/tokens"),
            "-H",
            "content-type: application/json",
            "-d",
            r#"{"name":"dev-seed"}"#,
        ])
        .output_string()?;
    let token = extract_json_string(&token_json, "token").ok_or_else(|| {
        "could not parse push token from /admin/users/1/tokens response".to_string()
    })?;
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
            &format!("{forge_url}/v3/nuget/package"),
            "-H",
            &format!("X-NuGet-ApiKey: {token}"),
            "-F",
            "package=@fixtures/nuget/sample.lib.1.0.0.nupkg",
        ])
        .run()?;

    println!("  feed:     {forge_url}/v3/nuget/index.json");
    let versions = Cmd::new("curl")
        .args([
            "-fsS",
            &format!("{forge_url}/v3/nuget/flat/sample.lib/index.json"),
        ])
        .output_string()
        .unwrap_or_default();
    println!("  versions: {versions}");
    Ok(())
}

/// Minimal extractor for `"<key>":"<value>"` from a JSON blob (matches the old
/// Makefile's `sed`). Good enough for the single-field token response; avoids a
/// JSON dependency in the runner.
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
/// migrations first (mirrors the old `just prepare`), then runs `cargo sqlx
/// prepare`. Needs `up` (or a reachable DATABASE_URL) + sqlx-cli.
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
/// not need a live DB.
fn docker_build() -> Result<(), String> {
    Cmd::new("docker")
        .args([
            "build",
            "-t",
            "envisia-forge:latest",
            "-f",
            "Dockerfile",
            ".",
        ])
        .run()
}

/// Run the built image against the dev Postgres + versitygw. Composes the base
/// docker-compose.yml (db + s3) with docker-compose.app.yml (the app service),
/// building the image if needed. Serves the API + SPA on http://localhost:8420.
fn docker_run() -> Result<(), String> {
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
