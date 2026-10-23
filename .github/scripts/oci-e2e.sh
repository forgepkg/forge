#!/usr/bin/env bash
# End-to-end check of the Docker / OCI registry with real clients (used by
# ci.yml): boots forge-server, then runs
#
#   1. the OCI distribution-spec conformance suite against a hosted repository;
#   2. docker: login with an API token, a multi-arch buildx push, pull;
#   3. crane: ls, manifest, copy;
#   4. a proxy repository of a `registry:2` upstream (seeded with crane) and a
#      group over the hosted and proxy repositories, pulled with docker;
#   5. cosign: a signature and an attestation pushed as OCI 1.1 referrers,
#      found through the referrers API and verified.
#
# Usage: oci-e2e.sh <forge-server binary> <results dir>
# Needs on PATH: docker (with buildx), go, crane, cosign, curl, jq, git.
# Postgres and S3 come from the environment (defaults match ci.yml):
#   FORGE_E2E_DATABASE_URL  (postgres://forge:forge@localhost:5432/forge)
#   FORGE_E2E_S3_ENDPOINT   (http://localhost:7070), access/secret forge-e2e-key
#   FORGE_E2E_UPSTREAM_PORT (5005: the registry:2 upstream of the proxy)
#   FORGE_E2E_UPSTREAM_IMAGE (mirror.gcr.io/library/registry:2, that upstream's image)
#   FORGE_E2E_BUILDKIT_IMAGE (mirror.gcr.io/moby/buildkit:buildx-stable-1, for buildx)
set -euo pipefail

server_bin="$(realpath "$1")"
results="$(mkdir -p "$2" && realpath "$2")"
db_url="${FORGE_E2E_DATABASE_URL:-postgres://forge:forge@localhost:5432/forge}"
s3_endpoint="${FORGE_E2E_S3_ENDPOINT:-http://localhost:7070}"
upstream_port="${FORGE_E2E_UPSTREAM_PORT:-5005}"
upstream_image="${FORGE_E2E_UPSTREAM_IMAGE:-mirror.gcr.io/library/registry:2}"
buildkit_image="${FORGE_E2E_BUILDKIT_IMAGE:-mirror.gcr.io/moby/buildkit:buildx-stable-1}"
# The conformance runner of distribution-spec main (2026-08-31).
conformance_rev=97274622c11112caa21efb8c52acca3c6b8fa7f1
registry=localhost:8421
base="http://$registry"
admin_user="admin@example.com"
admin_password="e2e-$(openssl rand -hex 12)"

work=$(mktemp -d)
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  docker rm -f forge-e2e-upstream >/dev/null 2>&1 || true
  docker buildx rm forge-e2e >/dev/null 2>&1 || true
  docker logout "$registry" >/dev/null 2>&1 || true
  cp "$work/server.log" "$results/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { echo; echo "── $* ──"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

step "start forge-server"
cat > "$work/forge.toml" <<EOF
[server]
bind = "127.0.0.1:8421"
public_base_url = "$base"
[database]
url = "$db_url"
[s3]
endpoint = "$s3_endpoint"
region = "us-east-1"
bucket = "forge-e2e"
access_key = "forge-e2e-key"
secret_key = "forge-e2e-secret"
force_path_style = true
[auth.bootstrap_admin]
username = "$admin_user"
password = "$admin_password"
[outbox]
grace_seconds = 0
poll_interval_seconds = 2
[web]
enabled = false
EOF
FORGE_CONFIG="$work/forge.toml" RUST_LOG=info "$server_bin" > "$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 60); do
  if curl -fsS "$base/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "$base/readyz" >/dev/null || { cat "$work/server.log"; fail "server not ready"; }

step "create repositories and an API token"
login=$(curl -fsS -c "$work/jar" -H 'content-type: application/json' \
  -d "{\"username\":\"$admin_user\",\"password\":\"$admin_password\"}" "$base/auth/login")
csrf=$(jq -r .csrf_token <<<"$login")
admin() { # <method> <path> [json body]
  curl -fsS -b "$work/jar" -H "x-csrf-token: $csrf" -H 'content-type: application/json' \
    -X "$1" "$base$2" ${3:+-d "$3"}
}
token=$(admin POST /admin/me/tokens '{"name":"oci-e2e"}' | jq -r .token)
admin POST /admin/repositories '{"name":"docker-hosted","kind":"hosted","format":"docker"}' >/dev/null
admin POST /admin/repositories "{\"name\":\"docker-proxy\",\"kind\":\"proxy\",\"format\":\"docker\",\"remote_url\":\"http://localhost:$upstream_port\"}" >/dev/null
admin POST /admin/repositories '{"name":"docker-group","kind":"group","format":"docker","writable_member":"docker-hosted"}' >/dev/null
admin POST /admin/repositories/docker-group/members '{"member":"docker-hosted","priority":10}' >/dev/null
admin POST /admin/repositories/docker-group/members '{"member":"docker-proxy","priority":5}' >/dev/null

step "OCI distribution-spec conformance"
git clone -q https://github.com/opencontainers/distribution-spec.git "$work/distribution-spec"
git -C "$work/distribution-spec" checkout -q "$conformance_rev"
(cd "$work/distribution-spec/conformance" && go build -o "$work/conformance" .)
(
  cd "$work"
  OCI_REGISTRY=$registry OCI_TLS=disabled \
    OCI_REPO1=docker-hosted/conformance/repo1 OCI_REPO2=docker-hosted/conformance/repo2 \
    OCI_USERNAME="$admin_user" OCI_PASSWORD="$token" \
    OCI_API_BLOBS_UPLOAD_CANCEL=true OCI_API_MANIFESTS_TAG_PARAM=true \
    OCI_RESULTS_DIR="$results/conformance" OCI_LOG=warn \
    ./conformance
) | tee "$results/conformance.txt"
grep -q '^OCI Conformance Test: Pass' "$results/conformance.txt" || fail "conformance"

step "docker: login, multi-arch push, pull"
echo "$token" | docker login "$registry" -u "$admin_user" --password-stdin
mkdir -p "$work/ctx"
echo "built by forge e2e" > "$work/ctx/hello.txt"
printf 'FROM scratch\nCOPY hello.txt /hello.txt\n' > "$work/ctx/Dockerfile"
docker buildx create --name forge-e2e --driver docker-container \
  --driver-opt network=host --driver-opt "image=$buildkit_image" --use >/dev/null
image="$registry/docker-hosted/e2e/multi:1"
docker buildx build --platform linux/amd64,linux/arm64 --provenance=false -t "$image" --push "$work/ctx"
docker pull "$image"

step "crane: ls, manifest, copy"
crane auth login "$registry" -u "$admin_user" -p "$token" --insecure
platforms=$(crane manifest --insecure "$image" | jq -r '[.manifests[].platform | .os + "/" + .architecture] | sort | join(",")')
[ "$platforms" = "linux/amd64,linux/arm64" ] || fail "multi-arch index platforms: $platforms"
crane ls --insecure "$registry/docker-hosted/e2e/multi" | grep -qx 1 || fail "crane ls"
digest=$(crane digest --insecure "$image")
crane copy --insecure "$image" "$registry/docker-hosted/e2e/copy:1"
[ "$(crane digest --insecure "$registry/docker-hosted/e2e/copy:1")" = "$digest" ] || fail "crane copy"

step "proxy of a registry:2 upstream, and a group"
docker run -d --name forge-e2e-upstream -p "$upstream_port:5000" "$upstream_image" >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://localhost:$upstream_port/v2/" >/dev/null 2>&1 && break; sleep 1; done
crane copy --insecure "$image" "localhost:$upstream_port/upstream/multi:1"
docker pull "$registry/docker-proxy/upstream/multi:1"
[ "$(crane digest --insecure "$registry/docker-proxy/upstream/multi:1")" = "$digest" ] || fail "proxy digest"
# The group serves the hosted image first and the proxied one by name.
docker pull "$registry/docker-group/e2e/multi:1"
docker pull "$registry/docker-group/upstream/multi:1"
# A push to the group lands in its writable member.
crane copy --insecure "$image" "$registry/docker-group/e2e/via-group:1"
crane digest --insecure "$registry/docker-hosted/e2e/via-group:1" >/dev/null || fail "group push"

step "cosign: signature and attestation as referrers"
# cosign 3 stores both as Sigstore bundles through the OCI 1.1 referrers
# API. Signed with a local key and no transparency log, so verification
# needs only an empty trusted root.
export COSIGN_PASSWORD="" COSIGN_YES=true
(cd "$work" && cosign generate-key-pair >/dev/null)
echo '{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}' > "$work/trusted_root.json"
echo '{"builder":{"id":"forge-e2e"},"buildType":"forge-e2e"}' > "$work/predicate.json"
signed="$registry/docker-hosted/e2e/multi@$digest"
offline=(--tlog-upload=false --use-signing-config=false --allow-insecure-registry)
cosign sign --key "$work/cosign.key" "${offline[@]}" "$signed"
cosign attest --key "$work/cosign.key" "${offline[@]}" \
  --type slsaprovenance --predicate "$work/predicate.json" "$signed"
pull_token=$(curl -fsS -u "$admin_user:$token" "$base/v2/token?scope=repository:docker-hosted/e2e/multi:pull" | jq -r .token)
referrers=$(curl -fsS -H "Authorization: Bearer $pull_token" "$base/v2/docker-hosted/e2e/multi/referrers/$digest")
echo "$referrers" | jq -c '.manifests[] | {artifactType, predicate: .annotations["dev.sigstore.bundle.predicateType"]}'
predicates=$(jq -r '[.manifests[].annotations["dev.sigstore.bundle.predicateType"]] | sort | join(",")' <<<"$referrers")
[ "$predicates" = "https://sigstore.dev/cosign/sign/v1,https://slsa.dev/provenance/v0.2" ] \
  || fail "referrers: expected a signature and an attestation, got $predicates"
verify=(--key "$work/cosign.pub" --insecure-ignore-tlog --private-infrastructure
  --trusted-root "$work/trusted_root.json" --allow-insecure-registry)
cosign verify "${verify[@]}" "$signed" >/dev/null
cosign verify-attestation "${verify[@]}" --type slsaprovenance "$signed" >/dev/null

step "OK: conformance, docker, crane, proxy, group and cosign"
