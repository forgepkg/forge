# envisia-forge developer shortcuts.
#
# Run `just <recipe>`. Requires the `just` command runner (https://github.com/casey/just)
# and the sqlx CLI (`cargo install sqlx-cli --no-default-features --features rustls,postgres`).

# Default DATABASE_URL for local dev (matches docker-compose.yml: db/user/pw = forge).
export DATABASE_URL := env_var_or_default("DATABASE_URL", "postgres://forge:forge@localhost:5432/forge")

# List available recipes.
default:
    @just --list

# Bring up the local dev Postgres + versitygw stack.
up:
    docker compose up -d

# Tear the local dev stack down.
down:
    docker compose down

# Apply all migrations against $DATABASE_URL.
migrate:
    sqlx migrate run --source migrations

# Regenerate the committed .sqlx/ offline query cache from a live database.
#
# Brings up Postgres if needed, applies migrations, then runs `cargo sqlx prepare`
# for the whole workspace. Commit the resulting .sqlx/ dir.
prepare: migrate
    cargo sqlx prepare --workspace -- --all-targets --all-features

# Verify the committed .sqlx/ cache is in sync with the current queries + schema.
# Mirrors what CI runs; fails if the cache has drifted.
prepare-check: migrate
    cargo sqlx prepare --check --workspace -- --all-targets --all-features

# Offline build (uses the committed .sqlx/ cache, no DB needed).
build:
    SQLX_OFFLINE=true cargo build --workspace

# Lint + format checks, matching CI.
lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
