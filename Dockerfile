# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# ─────────────────────────────────────────────────────────────────────────────
# Forge — single-image build.
#
# Packages the TanStack Router SPA *and* the Rust forge-server into ONE image.
# The server serves the API and the static SPA on a single port (no Node in
# prod). Stages:
#
#   1. web      — pnpm install + build → /web/dist
#   2. chef/...  — cargo-chef + release build of forge-server (SQLX_OFFLINE)
#   3. runtime  — debian:bookworm-slim with the binary, the SPA, and migrations/
#
# Licenses: the runtime image carries LICENSE and the third-party notices of
# the Rust crates and npm packages it ships in /usr/share/doc/forge/. For the
# SBOM attestation (release.yml), the web and builder stages are scanned as
# well as the final one, and the binary embeds its crate list (cargo-auditable).
#
# Build:  docker build -t forge:latest .   (or `cargo xtask docker-build`)
# Run:    see the `runtime` stage footer for required FORGE_* env vars.
#
# The syntax line pins the Dockerfile frontend by digest (1.7, the same one
# for every builder, whatever frontend its BuildKit has built in); Dependabot
# does not update it, so bump tag and digest by hand. The base images below
# are pinned the same way, and .github/scripts/image-pin-check.sh (CI) fails
# on any reference without a digest.
# ─────────────────────────────────────────────────────────────────────────────


# ── Stage 1: build the web SPA ───────────────────────────────────────────────
# corepack pins pnpm to the version in web/package.json ("packageManager"), so
# the lockfile install is reproducible.
# Base images are pinned by digest (tag kept for readability); Dependabot
# (.github/dependabot.yml) proposes tag + digest bumps.
FROM node:26-bookworm-slim@sha256:298992629d69bbd5b2b03ad57094d8e4fcb3a8eeb7c4e25d29de656519568913 AS web
# BuildKit scans only the final stage for the SBOM unless a stage declares
# this: the npm packages are in node_modules here, but only minified into the
# bundle the runtime image ships.
ARG BUILDKIT_SBOM_SCAN_STAGE=true
WORKDIR /web

# Enable the pinned pnpm via corepack before any install. Node 25+ no longer
# bundles corepack, so install it (pinned) from npm first.
RUN npm install -g corepack@0.36.0 && corepack enable

# Install deps first (cache layer keyed on the lockfile + manifests only).
# `pnpm licenses` reads the store, a cache mount, so it runs in the same step:
# the licenses of the production dependencies, the packages the SPA ships.
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/.npmrc ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile \
    && mkdir /licenses \
    && pnpm licenses list --prod --json > /licenses/web-licenses.json
# Their third-party notices, with each package's license files.
COPY docker/licenses/web-notices.mjs /licenses/
RUN node /licenses/web-notices.mjs /licenses/web-licenses.json > /licenses/THIRD-PARTY-WEB.txt

# Build the SPA. `pnpm run build` = `tsc --noEmit && vite build` → web/dist.
COPY web/ ./
RUN pnpm run build


# ── Stage 2a: cargo-chef base ─────────────────────────────────────────────────
# Pin the Rust toolchain to match rust-toolchain.toml (1.99.1). cargo-chef lets
# us cache the dependency compile separately from the workspace sources.
FROM rust:1.99.1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS chef
# Use the image's preinstalled 1.99.1 as-is; the copied rust-toolchain.toml
# would otherwise make rustup download its dev components (rustfmt, clippy).
ENV RUSTUP_TOOLCHAIN=1.99.1
# aws-lc-sys (transitive via aws-sdk-s3 / rustls) compiles C + asm, so the build
# needs cmake, clang and perl in addition to the default gcc toolchain.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang perl \
    && rm -rf /var/lib/apt/lists/*
# Exact version: the dependency-layer recipe format is cargo-chef specific.
RUN cargo install cargo-chef --locked --version 0.1.78
# cargo-auditable embeds the binary's crate list in it, where SBOM generators
# and image scanners find it (they do not read Cargo.lock in an image);
# cargo-about renders the crates' license notices. Pinned like cargo-chef.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-auditable --locked --version 0.7.7 \
    && cargo install cargo-about --locked --version 0.9.2 --features cli
WORKDIR /app

# ── Stage 2b: plan the dependency graph ───────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2c: build dependencies, then the workspace ──────────────────────────
FROM chef AS builder
# Scanned for the SBOM as well (see the web stage): Cargo.lock and the crates.
ARG BUILDKIT_SBOM_SCAN_STAGE=true
# sqlx is compile-time-checked against the committed .sqlx/ offline cache; no DB
# is reachable in the image build, so the offline mode is mandatory.
ENV SQLX_OFFLINE=true
# Cook the dependency layer first (cached unless the recipe changes). The
# compiled dependencies stay in this layer's target/, not in a cache mount:
# a layer cache (CI's `cache-to: type=gha`) exports layers but never cache
# mounts, so with target/ in one every fresh builder found an empty target/
# and compiled all dependencies again, cached cook layer or not.
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo chef cook --release --locked --recipe-path recipe.json -p forge-server
# Third-party notices for the crates compiled into forge-server
# (docker/licenses/about.toml). They depend on the dependencies alone, so they
# are rendered from the skeleton the cook leaves (every manifest and
# Cargo.lock), before the sources come in: cached as long as the cook is, and
# the same file as from the full tree. cargo-about reads the metadata of every
# locked crate, so fetch those of the other platforms too; then it needs no
# network (--frozen) and takes the license texts from the crates' sources.
COPY docker/licenses/ docker/licenses/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo fetch --locked \
    && mkdir /licenses \
    && cargo about generate --frozen --fail -c docker/licenses/about.toml \
       -m crates/server/Cargo.toml -o /licenses/THIRD-PARTY-RUST.txt \
       docker/licenses/about.hbs
# Now build the actual server binary. .sqlx/ and migrations/ come in with the
# source copy (migrations/ is embedded into the binary via sqlx::migrate!).
# `--locked`: the committed Cargo.lock is the release's dependency set.
# FORGE_GIT_SHA is compiled in and reported by `GET /version` and the startup
# log (`docker build --build-arg FORGE_GIT_SHA=$(git rev-parse HEAD) .`).
ARG FORGE_GIT_SHA=unknown
ENV FORGE_GIT_SHA=${FORGE_GIT_SHA}
# target/ is removed in the same step, so the layer holds the binary alone.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo auditable build --release --locked -p forge-server \
    && cp target/release/forge-server /usr/local/bin/forge-server \
    && rm -rf target


# ── Stage 3: slim runtime ─────────────────────────────────────────────────────
# debian:bookworm-slim (glibc + libgcc that aws-lc-rs needs) plus ca-certificates
# for outbound HTTPS (S3, OIDC discovery, credential-forwarding upstreams).
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user.
RUN useradd --system --uid 10001 --user-group --no-create-home forge
WORKDIR /app

# The image's version label. The release workflow passes the released version;
# a local or CI build is not a release, so it says so instead of naming one.
# Declared after the RUN steps: BuildKit hands every build argument to each
# RUN that follows it, so a new commit SHA would rebuild them.
ARG FORGE_VERSION=0.0.0-dev
ARG FORGE_GIT_SHA=unknown
LABEL org.opencontainers.image.title="forge" \
      org.opencontainers.image.description="Self-hosted NuGet, Docker / OCI and Helm registry (hosted, proxy and group repositories)" \
      org.opencontainers.image.version="${FORGE_VERSION}" \
      org.opencontainers.image.revision="${FORGE_GIT_SHA}"

# The license (MIT) and the third-party notices of what the image
# redistributes.
COPY LICENSE /usr/share/doc/forge/LICENSE
COPY --from=builder /licenses/THIRD-PARTY-RUST.txt /usr/share/doc/forge/
COPY --from=web /licenses/THIRD-PARTY-WEB.txt /usr/share/doc/forge/
# The server binary.
COPY --from=builder /usr/local/bin/forge-server /usr/local/bin/forge-server
# The built SPA (served from FORGE_WEB__ASSETS_DIR, default /app/web/dist below).
COPY --from=web /web/dist /app/web/dist
# Migrations are embedded at compile time, but we ship them too so an operator
# can inspect/run them out-of-band, and to keep the layout self-documenting.
COPY migrations /app/migrations
# A baked, secret-free base config. Real secrets come from FORGE_* env at runtime
# (FORGE_DATABASE__URL, FORGE_S3__*): it holds no S3 keys, so an image started
# without them (and without short-lived S3 credentials) refuses to start. It
# bakes NO bootstrap admin: that comes only from FORGE_AUTH__BOOTSTRAP_ADMIN__*
# env.
COPY docker/forge.docker.toml /app/forge.toml

# Numeric UID:GID (the `forge` user above) so Kubernetes `runAsNonRoot` can
# verify the image runs unprivileged without resolving a user name.
USER 10001:10001

# ── Runtime configuration (FORGE_* override the baked forge.toml) ─────────────
# Baked defaults (see docker/forge.docker.toml): bind 0.0.0.0:8421, SPA at
# /app/web/dist, no bootstrap admin (set FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD
# for the first start). Anonymous access and password Basic start off; they
# are set in the web UI (Admin → Settings).
ENV FORGE_CONFIG=/app/forge.toml \
    FORGE_WEB__ASSETS_DIR=/app/web/dist \
    RUST_LOG=info

# Required at runtime (no safe default — must be supplied):
#   FORGE_DATABASE__URL          postgres://user:pass@host:5432/forge
#   FORGE_S3__ENDPOINT           http://s3:8422  (or a real S3 endpoint)
#   FORGE_S3__BUCKET             forge
#   FORGE_S3__ACCESS_KEY         <s3 access key>
#   FORGE_S3__SECRET_KEY         <s3 secret key>
# First start only (creates the bootstrap admin; remove it afterwards):
#   FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD   <a real password>
# Strongly recommended:
#   FORGE_SERVER__PUBLIC_BASE_URL   https://forge.example.com (for absolute @id URLs)
# Local dev only (accept the placeholder credentials):
#   FORGE_SERVER__ALLOW_INSECURE_DEFAULTS=true
EXPOSE 8421
# Probes (no curl in the image; point the orchestrator at them):
#   liveness  GET /healthz   readiness  GET /readyz   build  GET /version

ENTRYPOINT ["/usr/local/bin/forge-server"]
