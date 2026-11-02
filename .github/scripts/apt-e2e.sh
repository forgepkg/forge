#!/usr/bin/env bash
# End-to-end check of apt repositories with the real apt-get (used by
# ci.yml): boots forge-server, then
#
#   1. hosted: uploads packages built with dpkg-deb (Nexus' raw-body POST
#      and a PUT), refuses a redeploy and path traversal, verifies InRelease
#      and Release.gpg with gpgv against the repository's key.gpg, and in a
#      debian:bookworm container adds the source with signed-by and
#      credentials in /etc/apt/auth.conf.d, runs apt-get update (no warning),
#      installs a package, and upgrades it after a newer version is uploaded;
#   2. key rotation: adds a second signing key; InRelease and Release.gpg
#      verify with either key alone, and apt-get update trusting only the
#      old key still has no warning; the old key is then deleted;
#   3. proxy: a mock Debian mirror (dpkg-scanpackages, signed with its own
#      key, by-hash copies) behind a proxy repository; apt-get installs
#      through it, then installs again in a fresh container while the mirror
#      is down.
#
# Usage: apt-e2e.sh <forge-server binary> <results dir>
# Needs on PATH: curl, jq, python3, docker, dpkg-deb, dpkg-scanpackages,
# gpg, gpgv, sha256sum, gzip, openssl. Postgres and S3 come from the
# environment (defaults match ci.yml):
#   FORGE_E2E_DATABASE_URL  (postgres://forge:forge@localhost:5432/forge)
#   FORGE_E2E_S3_ENDPOINT   (http://localhost:7070), access/secret forge-e2e-key
#   FORGE_E2E_PORT          (8441: forge-server's)
#   FORGE_E2E_MIRROR_PORT   (5031: the mock mirror's)
set -euo pipefail

server_bin="$(realpath "$1")"
results="$(mkdir -p "$2" && realpath "$2")"
db_url="${FORGE_E2E_DATABASE_URL:-postgres://forge:forge@localhost:5432/forge}"
s3_endpoint="${FORGE_E2E_S3_ENDPOINT:-http://localhost:7070}"
port="${FORGE_E2E_PORT:-8441}"
mirror_port="${FORGE_E2E_MIRROR_PORT:-5031}"
base="http://127.0.0.1:$port"
admin_password="e2e-$(openssl rand -hex 12)"
# Docker Hub images come through mirror.gcr.io (AGENTS.md), pinned.
debian_image="mirror.gcr.io/library/debian:bookworm@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880"

work=$(mktemp -d)
server_pid=""
mirror_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  if [ -n "$mirror_pid" ]; then kill "$mirror_pid" 2>/dev/null || true; fi
  cp "$work/server.log" "$work/mirror.log" "$work"/apt-*.log "$results/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { echo; echo "── $* ──"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_status() { # <status> <curl args...>
  local want=$1
  shift
  local got
  got=$(curl -sS -o "$work/body" -w '%{http_code}' "$@")
  [ "$got" = "$want" ] || fail "curl $* answered $got, not $want: $(head -c 300 "$work/body")"
}

# A binary package <name> <version> <arch> [section] in $work/debs.
deb() {
  local name=$1 version=$2 arch=$3 section=${4:-utils}
  local dir="$work/build/${name}_${version}_${arch}"
  mkdir -p "$dir/DEBIAN" "$dir/usr/bin" "$work/debs"
  printf '#!/bin/sh\necho "%s %s"\n' "$name" "$version" > "$dir/usr/bin/$name"
  chmod 755 "$dir/usr/bin/$name"
  cat > "$dir/DEBIAN/control" <<EOF
Package: $name
Version: $version
Architecture: $arch
Maintainer: Forge e2e <forge@example.com>
Section: $section
Priority: optional
Description: $name for the apt e2e
 A package built by apt-e2e.sh.
EOF
  dpkg-deb -Zxz --build --root-owner-group "$dir" "$work/debs/${name}_${version}_${arch}.deb" >/dev/null
}

# Run <script> in a fresh debian:bookworm container on the host's network,
# with the files of $work/client mounted at /client; its output goes to
# $work/apt-<label>.log, which must hold no apt warning or error.
apt_container() { # <label> <script>
  local label=$1 script=$2
  printf 'set -eu\n%s\n' "$script" > "$work/client/run.sh"
  if ! docker run --rm --network host -v "$work/client:/client:ro" "$debian_image" \
      sh /client/run.sh > "$work/apt-$label.log" 2>&1; then
    cat "$work/apt-$label.log"
    fail "apt in a container ($label)"
  fi
  if grep -E '^(W|E): ' "$work/apt-$label.log"; then
    cat "$work/apt-$label.log"
    fail "apt warned ($label)"
  fi
  cat "$work/apt-$label.log"
}

# The shell lines that point a container's apt at one source only.
apt_source() { # <sources.list line> [auth.conf entry]
  cat <<EOF
mkdir -p /etc/apt/only.d
echo '$1' > /etc/apt/only.d/forge.list
printf 'Dir::Etc::SourceParts "/etc/apt/only.d";\nDir::Etc::SourceList "/dev/null";\n' > /etc/apt/apt.conf.d/99only
EOF
  if [ -n "${2:-}" ]; then
    printf "printf '%s' > /etc/apt/auth.conf.d/forge.conf\nchmod 600 /etc/apt/auth.conf.d/forge.conf\n" "$2"
  fi
}

step "start forge-server"
head -c 32 /dev/urandom | base64 > "$work/root.key"
cat > "$work/forge.toml" <<EOF
[server]
bind = "127.0.0.1:$port"
public_base_url = "$base"
[database]
url = "$db_url"
[s3]
endpoint = "$s3_endpoint"
region = "us-east-1"
bucket = "forge-apt-e2e"
access_key = "forge-e2e-key"
secret_key = "forge-e2e-secret"
force_path_style = true
[crypto.root]
provider = "file"
root_key_path = "$work/root.key"
[auth.bootstrap_admin]
username = "admin@example.com"
password = "$admin_password"
[outbox]
grace_seconds = 0
poll_interval_seconds = 2
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
  -d "{\"username\":\"admin@example.com\",\"password\":\"$admin_password\"}" "$base/auth/login")
csrf=$(jq -r .csrf_token <<<"$login")
admin() { # <method> <path> [json body]
  curl -fsS -b "$work/jar" -H "x-csrf-token: $csrf" -H 'content-type: application/json' \
    -X "$1" "$base$2" ${3:+-d "$3"}
}
token=$(admin POST /admin/me/tokens '{"name":"apt-e2e"}' | jq -r .token)
auth=(-u "admin@example.com:$token")
admin POST /admin/repositories \
  '{"name":"apt-internal","kind":"hosted","format":"apt","options":{"distribution":"bookworm"}}' >/dev/null
repo="$base/repository/apt-internal"
mkdir -p "$work/client"
# apt sends credentials over plain HTTP only to a machine written with http://.
auth_conf="machine $base/repository/apt-internal\nlogin admin@example.com\npassword $token\n"

step "hosted: upload, redeploy, path traversal"
deb forge-hello 1.0-1 all
deb forge-hello 1.1-1 all
deb forge-tool 2.0-1 amd64 contrib/utils
expect_status 401 -H "Content-Type: multipart/form-data" --data-binary "@$work/debs/forge-hello_1.0-1_all.deb" "$repo/"
expect_status 201 "${auth[@]}" -H "Content-Type: multipart/form-data" \
  --data-binary "@$work/debs/forge-hello_1.0-1_all.deb" "$repo/"
expect_status 201 "${auth[@]}" --upload-file "$work/debs/forge-tool_2.0-1_amd64.deb" "$repo/"
expect_status 409 "${auth[@]}" -H "Content-Type: multipart/form-data" \
  --data-binary "@$work/debs/forge-hello_1.0-1_all.deb" "$repo/"
expect_status 400 "${auth[@]}" --data-binary "not a package" "$repo/"
for path in \
  "dists/bookworm/../../../etc/passwd" \
  "dists/%2e%2e/bookworm/InRelease" \
  "pool/main/f/forge-hello/%2e%2e/forge-hello_1.0-1_all.deb" \
  "pool/main/f%2Fforge-hello/forge-hello_1.0-1_all.deb" \
  "pool//main/f/forge-hello/forge-hello_1.0-1_all.deb" \
  "pool/main/f/forge-hello/..%5cforge-hello_1.0-1_all.deb"; do
  got=$(curl -sS --path-as-is -o /dev/null -w '%{http_code}' "${auth[@]}" "$repo/$path")
  case "$got" in 400 | 404) ;; *) fail "GET $path answered $got" ;; esac
done
got=$(curl -sS --path-as-is -o /dev/null -w '%{http_code}' "${auth[@]}" \
  --upload-file "$work/debs/forge-hello_1.1-1_all.deb" "$repo/%2e%2e/x.deb")
case "$got" in 400 | 404) ;; *) fail "PUT through %2e%2e answered $got" ;; esac

step "hosted: the indexes verify with gpgv"
curl -fsS "${auth[@]}" -o "$work/key-old.gpg" "$repo/key.gpg"
curl -fsS "${auth[@]}" -o "$work/client/key-old.asc" "$repo/key.asc"
curl -fsS "${auth[@]}" -o "$work/InRelease" "$repo/dists/bookworm/InRelease"
curl -fsS "${auth[@]}" -o "$work/Release" "$repo/dists/bookworm/Release"
curl -fsS "${auth[@]}" -o "$work/Release.gpg" "$repo/dists/bookworm/Release.gpg"
gpgv --keyring "$work/key-old.gpg" "$work/InRelease"
gpgv --keyring "$work/key-old.gpg" "$work/Release.gpg" "$work/Release"
grep -q '^Acquire-By-Hash: yes$' "$work/Release" || fail "Release without Acquire-By-Hash"
grep -q '^Components: contrib main$' "$work/Release" || fail "Release components: $(cat "$work/Release")"
# Every file Release names is there with its digest, by name and by hash.
awk '/^SHA256:/{on=1;next} /^[^ ]/{on=0} on{print $1, $3}' "$work/Release" | while read -r sha path; do
  [ "$(curl -fsS "${auth[@]}" "$repo/dists/bookworm/$path" | sha256sum | cut -d' ' -f1)" = "$sha" ] \
    || fail "$path does not match Release"
  [ "$(curl -fsS "${auth[@]}" "$repo/dists/bookworm/$(dirname "$path")/by-hash/SHA256/$sha" | sha256sum | cut -d' ' -f1)" = "$sha" ] \
    || fail "$path by hash does not match Release"
done

step "hosted: apt-get update, install, upgrade (debian:bookworm)"
docker pull -q "$debian_image" >/dev/null
hosted_source=$(apt_source "deb [signed-by=/client/key-old.asc] $repo/ bookworm main contrib" "$auth_conf")
apt_container hosted-install "$hosted_source
apt-get update
apt-get install -y forge-hello forge-tool
forge-hello | grep -qx 'forge-hello 1.0-1'
forge-tool | grep -qx 'forge-tool 2.0-1'
echo 'installed 1.0-1'
while [ ! -f /client/newer ]; do sleep 1; done
apt-get update
apt-get install -y --only-upgrade forge-hello
forge-hello | grep -qx 'forge-hello 1.1-1'
echo 'upgraded to 1.1-1'" &
container=$!
# Upload the newer version while the container waits.
for _ in $(seq 1 120); do
  grep -q 'installed 1.0-1' "$work/apt-hosted-install.log" 2>/dev/null && break
  kill -0 "$container" 2>/dev/null || break
  sleep 1
done
expect_status 201 "${auth[@]}" -H "Content-Type: multipart/form-data" \
  --data-binary "@$work/debs/forge-hello_1.1-1_all.deb" "$repo/"
touch "$work/client/newer"
wait "$container" || fail "the install and upgrade failed"
grep -q 'upgraded to 1.1-1' "$work/apt-hosted-install.log" || fail "no upgrade"
rm -f "$work/client/newer"

step "key rotation: both keys sign until the old one is deleted"
old=$(admin GET /admin/repositories/apt-internal/signing-keys | jq -r '.[0].fingerprint')
new=$(admin POST /admin/repositories/apt-internal/signing-keys '{}' | jq -r .fingerprint)
[ "$old" != "$new" ] || fail "no new key"
admin GET /admin/repositories/apt-internal/signing-keys \
  | jq -r ".[] | select(.fingerprint == \"$new\") | .public_key" | gpg --dearmor > "$work/key-new.gpg"
curl -fsS "${auth[@]}" -o "$work/InRelease" "$repo/dists/bookworm/InRelease"
curl -fsS "${auth[@]}" -o "$work/Release" "$repo/dists/bookworm/Release"
curl -fsS "${auth[@]}" -o "$work/Release.gpg" "$repo/dists/bookworm/Release.gpg"
# gpgv exits 2 when it cannot check one of the signatures (a key it does
# not have), as a client trusting one key of the rollover sees it; apt
# accepts the file when one signature is good.
good() { # <gpgv args...>: how many signatures verify
  local out
  out=$(gpgv "$@" 2>&1 || true)
  grep -c 'Good signature' <<<"$out" || true
}
for keyring in "$work/key-old.gpg" "$work/key-new.gpg"; do
  [ "$(good --keyring "$keyring" "$work/InRelease")" = 1 ] || fail "InRelease with $keyring"
  [ "$(good --keyring "$keyring" "$work/Release.gpg" "$work/Release")" = 1 ] \
    || fail "Release.gpg with $keyring"
done
[ "$(good --keyring "$work/key-old.gpg" --keyring "$work/key-new.gpg" "$work/InRelease")" = 2 ] \
  || fail "InRelease is not signed by both keys"
curl -fsS "${auth[@]}" -o "$work/client/key-both.asc" "$repo/key.asc"
apt_container rotation "$hosted_source
apt-get update
apt-cache policy forge-hello | grep -q 'Candidate: 1.1-1'"
expect_status 204 -b "$work/jar" -H "x-csrf-token: $csrf" -X DELETE \
  "$base/admin/repositories/apt-internal/signing-keys/$old"
expect_status 409 -b "$work/jar" -H "x-csrf-token: $csrf" -X DELETE \
  "$base/admin/repositories/apt-internal/signing-keys/$new"
curl -fsS "${auth[@]}" -o "$work/InRelease" "$repo/dists/bookworm/InRelease"
gpgv --keyring "$work/key-new.gpg" "$work/InRelease"
if gpgv --keyring "$work/key-old.gpg" "$work/InRelease" 2>/dev/null; then
  fail "the deleted key still signs"
fi

step "proxy: a mock mirror, signed with its own key"
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --passphrase '' --quick-gen-key 'Mock Mirror <mirror@example.com>' ed25519 sign never 2>/dev/null
gpg --export > "$work/client/mirror.gpg"
mirror="$work/mirror/debian"
deb mirror-pkg 3.0-1 amd64
mkdir -p "$mirror/pool/main/m/mirror-pkg" "$mirror/dists/bookworm/main/binary-amd64"
cp "$work/debs/mirror-pkg_3.0-1_amd64.deb" "$mirror/pool/main/m/mirror-pkg/"
(cd "$mirror" && dpkg-scanpackages --arch amd64 pool > dists/bookworm/main/binary-amd64/Packages 2>/dev/null)
gzip -9kn "$mirror/dists/bookworm/main/binary-amd64/Packages"
{
  echo "Origin: Mock"
  echo "Suite: bookworm"
  echo "Codename: bookworm"
  echo "Date: $(date -Ru)"
  echo "Architectures: amd64"
  echo "Components: main"
  echo "Acquire-By-Hash: yes"
  echo "SHA256:"
  for f in main/binary-amd64/Packages main/binary-amd64/Packages.gz; do
    sha=$(sha256sum "$mirror/dists/bookworm/$f" | cut -d' ' -f1)
    printf ' %s %s %s\n' "$sha" "$(stat -c %s "$mirror/dists/bookworm/$f")" "$f"
    mkdir -p "$mirror/dists/bookworm/main/binary-amd64/by-hash/SHA256"
    cp "$mirror/dists/bookworm/$f" "$mirror/dists/bookworm/main/binary-amd64/by-hash/SHA256/$sha"
  done
} > "$mirror/dists/bookworm/Release"
gpg --batch --yes --clearsign -o "$mirror/dists/bookworm/InRelease" "$mirror/dists/bookworm/Release"
python3 -u -m http.server "$mirror_port" --bind 127.0.0.1 --directory "$work/mirror" > "$work/mirror.log" 2>&1 &
mirror_pid=$!
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$mirror_port/debian/dists/bookworm/Release" >/dev/null 2>&1 && break
  sleep 1
done
admin POST /admin/repositories "{\"name\":\"debian-proxy\",\"kind\":\"proxy\",\"format\":\"apt\",
  \"remote_url\":\"http://127.0.0.1:$mirror_port/debian\",\"options\":{\"distribution\":\"bookworm\"}}" >/dev/null
proxy="$base/repository/debian-proxy"
cmp <(curl -fsS "${auth[@]}" "$proxy/dists/bookworm/InRelease") "$mirror/dists/bookworm/InRelease" \
  || fail "the proxy changed InRelease"
proxy_auth="machine $base/repository/debian-proxy\nlogin admin@example.com\npassword $token\n"
proxy_source=$(apt_source "deb [signed-by=/client/mirror.gpg] $proxy/ bookworm main" "$proxy_auth")
apt_container proxy-install "$proxy_source
apt-get update
apt-get install -y mirror-pkg
mirror-pkg | grep -qx 'mirror-pkg 3.0-1'"

step "proxy: installs again while the mirror is down"
kill "$mirror_pid"
wait "$mirror_pid" 2>/dev/null || true
mirror_pid=""
apt_container proxy-down "$proxy_source
apt-get update
apt-get install -y mirror-pkg
mirror-pkg | grep -qx 'mirror-pkg 3.0-1'"

step "all apt e2e checks passed"
