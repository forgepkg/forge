#!/usr/bin/env bash
# Smoke test of the built container image (used by ci.yml's docker-platform
# job on each platform, #239). Starts the image the way the Kubernetes
# manifests and the Helm chart run it, checks that it serves, restarts it, and
# checks again:
#
#   - read-only root filesystem, /tmp a tmpfs (the manifests' emptyDir), user
#     10001:10001, every capability dropped, no privilege escalation;
#   - the baked /app/forge.toml, configured through FORGE_* only (the root
#     key of the secret encryption included), without
#     server.allow_insecure_defaults;
#   - a local blob cache in a volume prepared like a new persistent volume
#     under fsGroup 10001 (root's, group 10001, setgid and group-writable), at
#     the path deploy/kubernetes/components/local-cache-persistent uses;
#   - PostgreSQL and versitygw (S3) in containers of their own.
#
# Each start must reach /readyz. The first checks /version names the commit,
# serves the web UI and one of its assets, pushes a NuGet package with an
# API token (staged in /tmp, stored in S3 and written through to the cache)
# that downloads unchanged, and pushes a container image to a docker
# repository with docker, logged in with the token, that pulls unchanged.
# After the restart (the same database and cache volume, a fresh /tmp) the
# package downloads unchanged again, served from the cache the startup scan
# found.
#
# Usage: image-smoke.sh <image> [<commit>]
# Needs on PATH: docker, curl, jq, cmp, tar. Images (defaults match ci.yml):
#   FORGE_SMOKE_POSTGRES_IMAGE (mirror.gcr.io/library/postgres:18)
#   FORGE_SMOKE_S3_IMAGE       (mirror.gcr.io/versity/versitygw:v1.4.1)
set -euo pipefail

image="$1"
commit="${2:-}"
postgres_image="${FORGE_SMOKE_POSTGRES_IMAGE:-mirror.gcr.io/library/postgres:18}"
s3_image="${FORGE_SMOKE_S3_IMAGE:-mirror.gcr.io/versity/versitygw:v1.4.1}"
package="$(realpath "$(dirname "$0")/../../fixtures/nuget/sample.lib.1.0.0.nupkg")"
port="${FORGE_SMOKE_PORT:-18421}"
base="http://127.0.0.1:$port"
admin_user="admin@example.com"
admin_password="smoke-$(openssl rand -hex 12)"
s3_secret="smoke-$(openssl rand -hex 12)"
root_key=$(openssl rand -base64 32)
net=forge-smoke
cache_volume=forge-smoke-cache
# Docker treats a registry on a loopback address as one served over plain HTTP.
pushed_image="127.0.0.1:$port/docker/smoke/hello:1"

work=$(mktemp -d)
cleanup() {
  docker rm -f forge-smoke forge-smoke-db forge-smoke-s3 forge-smoke-pulled >/dev/null 2>&1 || true
  docker rmi "$pushed_image" >/dev/null 2>&1 || true
  docker volume rm "$cache_volume" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { echo; echo "── $* ──"; }
fail() {
  echo "FAIL: $*" >&2
  echo "── forge-server log ──" >&2
  docker logs forge-smoke 2>&1 | tail -n 100 >&2 || true
  exit 1
}

step "start PostgreSQL and versitygw"
docker network create "$net" >/dev/null
docker run -d --name forge-smoke-db --network "$net" \
  -e POSTGRES_DB=forge -e POSTGRES_USER=forge -e POSTGRES_PASSWORD=forge \
  "$postgres_image" >/dev/null
docker run -d --name forge-smoke-s3 --network "$net" "$s3_image" \
  --port :7070 --access forge-smoke --secret "$s3_secret" posix /tmp >/dev/null
for _ in $(seq 1 60); do
  if docker exec forge-smoke-db pg_isready -U forge -d forge >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec forge-smoke-db pg_isready -U forge -d forge >/dev/null || fail "PostgreSQL did not start"

# A new persistent volume as the kubelet hands it over under fsGroup 10001
# with fsGroupChangePolicy OnRootMismatch: the root stays root's, its group is
# 10001, setgid and group-writable. Forge makes its own cache directory in it.
docker volume create "$cache_volume" >/dev/null
docker run --rm --user 0 --entrypoint sh -v "$cache_volume:/cache" "$postgres_image" \
  -c 'chown 0:10001 /cache && chmod 2775 /cache'

start_forge() {
  docker run -d --name forge-smoke --network "$net" -p "127.0.0.1:$port:8421" \
    --read-only --tmpfs /tmp:rw,nosuid,nodev,size=1g,mode=1777 \
    --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges \
    -v "$cache_volume:/var/cache/forge" \
    -e FORGE_DATABASE__URL=postgres://forge:forge@forge-smoke-db:5432/forge \
    -e FORGE_S3__ENDPOINT=http://forge-smoke-s3:7070 \
    -e FORGE_S3__BUCKET=forge \
    -e FORGE_S3__ACCESS_KEY=forge-smoke \
    -e FORGE_S3__SECRET_KEY="$s3_secret" \
    -e FORGE_SERVER__PUBLIC_BASE_URL="$base" \
    -e FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME="$admin_user" \
    -e FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD="$admin_password" \
    -e FORGE_CRYPTO__ROOT__PROVIDER=env \
    -e FORGE_ROOT_KEY="$root_key" \
    -e FORGE_BLOB_CACHE__PATH=/var/cache/forge/blobs \
    -e FORGE_BLOB_CACHE__MAX_BYTES=1073741824 \
    "$image" >/dev/null
}

# Wait for /readyz; fail at once when the container exits (a crash loop).
wait_ready() {
  for _ in $(seq 1 120); do
    if [ "$(docker inspect -f '{{.State.Running}}' forge-smoke)" != true ]; then
      fail "the container exited ($(docker inspect -f '{{.State.ExitCode}}' forge-smoke))"
    fi
    if curl -fsS "$base/readyz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "not ready after 120 s"
}

sign_in() {
  local login
  login=$(curl -fsS -c "$work/jar" -H 'content-type: application/json' \
    -d "{\"username\":\"$admin_user\",\"password\":\"$admin_password\"}" "$base/auth/login") \
    || fail "sign-in failed"
  csrf=$(jq -r .csrf_token <<<"$login")
}
admin() { # <method> <path> [json body]
  curl -fsS -b "$work/jar" -H "x-csrf-token: $csrf" -H 'content-type: application/json' \
    -X "$1" "$base$2" ${3:+-d "$3"}
}

# Download the pushed package and compare it with the fixture.
download() {
  curl -fsS -u "$admin_user:$token" -o "$work/download.nupkg" "$nupkg_url" \
    || fail "download of $nupkg_url failed"
  cmp "$package" "$work/download.nupkg" || fail "the download differs from the package pushed"
}

step "start the image read-only, as user 10001, with the baked forge.toml"
start_forge
wait_ready

step "version, web UI"
version=$(curl -fsS "$base/version")
echo "$version"
if [ -n "$commit" ] && [ "$(jq -r .revision <<<"$version")" != "$commit" ]; then
  fail "/version does not name $commit: $version"
fi
index=$(curl -fsS "$base/") || fail "the web UI is not served"
grep -q '<div id="root">' <<<"$index" || fail "/ is not the web UI's index.html"
asset=$(grep -o '/assets/[^"]*\.js' <<<"$index" | head -n 1)
[ -n "$asset" ] || fail "index.html names no script under /assets/"
curl -fsS -o /dev/null "$base$asset" || fail "the web UI's $asset is not served"

step "push a NuGet package with an API token and download it"
sign_in
admin POST /admin/repositories '{"name":"nuget","kind":"hosted"}' >/dev/null \
  || fail "creating a repository failed"
token=$(admin POST /admin/me/tokens '{"name":"smoke"}' | jq -r .token)
status=$(curl -sS -o "$work/push.txt" -w '%{http_code}' -X PUT -H "X-NuGet-ApiKey: $token" \
  -F "package=@$package" "$base/repository/nuget/package")
[ "$status" = 201 ] || fail "push answered $status: $(cat "$work/push.txt")"
version=$(curl -fsS -u "$admin_user:$token" "$base/repository/nuget/flat/sample.lib/index.json" \
  | jq -r '.versions[0]')
nupkg_url="$base/repository/nuget/flat/sample.lib/$version/sample.lib.$version.nupkg"
download
[ "$(admin GET /admin/blob-cache | jq .entries)" -ge 1 ] || fail "the push left the cache empty"

step "push a container image with docker and pull it"
admin POST /admin/repositories '{"name":"docker","kind":"hosted","format":"docker"}' >/dev/null \
  || fail "creating a docker repository failed"
# A one-layer image of a file only this run has: no other image has its
# layer, so the pull downloads it. The login's credentials stay in a docker
# config of its own.
mkdir -p "$work/image"
echo "image smoke test $(openssl rand -hex 12)" > "$work/image/hello.txt"
tar -C "$work/image" -c hello.txt | docker import - "$pushed_image" >/dev/null
echo "$token" | DOCKER_CONFIG="$work/docker" docker login "127.0.0.1:$port" -u "$admin_user" --password-stdin \
  || fail "docker login failed"
DOCKER_CONFIG="$work/docker" docker push "$pushed_image" || fail "docker push failed"
docker rmi "$pushed_image" >/dev/null
DOCKER_CONFIG="$work/docker" docker pull "$pushed_image" || fail "docker pull failed"
# The image has no command to run; the file is copied out of a container.
docker create --name forge-smoke-pulled "$pushed_image" /hello.txt >/dev/null
docker cp forge-smoke-pulled:/hello.txt "$work/pulled.txt" >/dev/null
cmp "$work/image/hello.txt" "$work/pulled.txt" || fail "the pulled image differs from the one pushed"

step "restart on the same database and cache volume"
docker stop -t 30 forge-smoke >/dev/null
docker start forge-smoke >/dev/null
wait_ready
sign_in
stats=$(admin GET /admin/blob-cache)
[ "$(jq .entries <<<"$stats")" -ge 1 ] || fail "the restarted cache found nothing: $stats"
download
stats=$(admin GET /admin/blob-cache)
[ "$(jq .hits <<<"$stats")" -ge 1 ] || fail "the download after the restart missed the cache: $stats"

echo
echo "image smoke test passed"
