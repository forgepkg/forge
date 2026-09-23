# syntax=docker/dockerfile:1.7

# ─────────────────────────────────────────────────────────────────────────────
# envisia-forge — single-image build.
#
# Packages the TanStack Router SPA *and* the Rust forge-server into ONE image.
# The server serves the API and the static SPA on a single port (no Node in
# prod). Stages:
#
#   1. web      — pnpm install + build → /web/dist
#   2. chef/...  — cargo-chef + release build of forge-server (SQLX_OFFLINE)
#   3. runtime  — debian:bookworm-slim with the binary, the SPA, and migrations/
#
# Build:  docker build -t envisia-forge:latest .   (or `cargo xtask docker-build`)
# Run:    see the `runtime` stage footer for required FORGE_* env vars.
# ─────────────────────────────────────────────────────────────────────────────


# ── Stage 1: build the web SPA ───────────────────────────────────────────────
# Node 22 (matches the dev/CI toolchain). corepack pins pnpm to the version in
# web/package.json ("packageManager"), so the lockfile install is reproducible.
FROM node:22-bookworm-slim AS web
WORKDIR /web

# Enable the pinned pnpm via corepack before any install.
RUN corepack enable

# Install deps first (cache layer keyed on the lockfile + manifests only).
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/.npmrc ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

# Build the SPA. `pnpm run build` = `tsc --noEmit && vite build` → web/dist.
COPY web/ ./
RUN pnpm run build


# ── Stage 2a: cargo-chef base ─────────────────────────────────────────────────
# Pin the Rust toolchain to match rust-toolchain.toml (1.95.0). cargo-chef lets
# us cache the dependency compile separately from the workspace sources.
FROM rust:1.95.0-bookworm AS chef
# Use the image's preinstalled 1.95.0 as-is; the copied rust-toolchain.toml
# would otherwise make rustup download its dev components (rustfmt, clippy).
ENV RUSTUP_TOOLCHAIN=1.95.0
# aws-lc-sys (transitive via aws-sdk-s3 / rustls) compiles C + asm, so the build
# needs cmake, clang and perl in addition to the default gcc toolchain.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang perl \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version ^0.1
WORKDIR /app

# ── Stage 2b: plan the dependency graph ───────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2c: build dependencies, then the workspace ──────────────────────────
FROM chef AS builder
# sqlx is compile-time-checked against the committed .sqlx/ offline cache; no DB
# is reachable in the image build, so the offline mode is mandatory.
ENV SQLX_OFFLINE=true
# Cook the dependency layer first (cached unless the recipe changes).
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --locked --recipe-path recipe.json -p forge-server
# Now build the actual server binary. .sqlx/ and migrations/ come in with the
# source copy (migrations/ is embedded into the binary via sqlx::migrate!).
# `--locked`: the committed Cargo.lock is the release's dependency set.
# FORGE_GIT_SHA is compiled in and reported by `GET /version` and the startup
# log (`docker build --build-arg FORGE_GIT_SHA=$(git rev-parse HEAD) .`).
ARG FORGE_GIT_SHA=unknown
ENV FORGE_GIT_SHA=${FORGE_GIT_SHA}
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked -p forge-server \
    && cp target/release/forge-server /usr/local/bin/forge-server


# ── Stage 3: slim runtime ─────────────────────────────────────────────────────
# debian:bookworm-slim (glibc + libgcc that aws-lc-rs needs) plus ca-certificates
# for outbound HTTPS (S3, OIDC discovery, credential-forwarding upstreams).
FROM debian:bookworm-slim AS runtime
ARG FORGE_VERSION=0.1.0
ARG FORGE_GIT_SHA=unknown
LABEL org.opencontainers.image.title="envisia-forge" \
      org.opencontainers.image.description="Self-hosted NuGet V3 registry (hosted, proxy, group)" \
      org.opencontainers.image.version="${FORGE_VERSION}" \
      org.opencontainers.image.revision="${FORGE_GIT_SHA}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user.
RUN useradd --system --uid 10001 --user-group --no-create-home forge
WORKDIR /app

# The server binary.
COPY --from=builder /usr/local/bin/forge-server /usr/local/bin/forge-server
# The built SPA (served from FORGE_WEB__ASSETS_DIR, default /app/web/dist below).
COPY --from=web /web/dist /app/web/dist
# Migrations are embedded at compile time, but we ship them too so an operator
# can inspect/run them out-of-band, and to keep the layout self-documenting.
COPY migrations /app/migrations
# A baked, secret-free base config. Real secrets come from FORGE_* env at runtime
# and override these values (FORGE_DATABASE__URL, FORGE_S3__*). Its placeholder
# credentials (minioadmin, bootstrap admin/changeme) are REFUSED at startup
# unless overridden (or FORGE_SERVER__ALLOW_INSECURE_DEFAULTS=true for local dev).
COPY docker/forge.docker.toml /app/forge.toml

USER forge

# ── Runtime configuration (FORGE_* override the baked forge.toml) ─────────────
# Baked defaults (see docker/forge.docker.toml): bind 0.0.0.0:8421, SPA at
# /app/web/dist, anonymous_mode=off, allow_password_basic, bootstrap admin
# (placeholder password — must be overridden).
ENV FORGE_CONFIG=/app/forge.toml \
    FORGE_WEB__ASSETS_DIR=/app/web/dist \
    RUST_LOG=info

# Required at runtime (no safe default — must be supplied):
#   FORGE_DATABASE__URL          postgres://user:pass@host:5432/forge
#   FORGE_S3__ENDPOINT           http://s3:8422  (or a real S3 endpoint)
#   FORGE_S3__BUCKET             forge
#   FORGE_S3__ACCESS_KEY         <s3 access key>
#   FORGE_S3__SECRET_KEY         <s3 secret key>
#   FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD   <a real password>
# Strongly recommended:
#   FORGE_SERVER__PUBLIC_BASE_URL   https://forge.example.com (for absolute @id URLs)
# Local dev only (accept the placeholder credentials):
#   FORGE_SERVER__ALLOW_INSECURE_DEFAULTS=true
EXPOSE 8421
# Probes (no curl in the image; point the orchestrator at them):
#   liveness  GET /healthz   readiness  GET /readyz   build  GET /version

ENTRYPOINT ["/usr/local/bin/forge-server"]
