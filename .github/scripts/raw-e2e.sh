#!/usr/bin/env bash
# End-to-end check of raw (generic file) repositories with curl (used by
# ci.yml): boots forge-server, then
#
#   1. uploads to a hosted repository with an API token (PUT and a multipart
#      form), downloads with a range and a resumed download, verifies the
#      checksum sidecars with sha256sum -c and friends, lists directories,
#      and checks that a redeploy is refused by default;
#   2. sends path traversal attempts (`..`, `%2e%2e`, `//`, `\`) as they are;
#   3. proxies a mock upstream whose release host redirects to an asset host
#      on another origin (credentials go to the first only);
#   4. reads through a group of the two, falling through by priority;
#   5. the pdfium example: proxies a release asset of
#      github.com/bblanchon/pdfium-binaries and hosts a re-packaged copy
#      (skipped with FORGE_E2E_SKIP_GITHUB=1).
#
# Usage: raw-e2e.sh <forge-server binary> <results dir>
# Needs on PATH: curl, jq, python3, sha256sum, sha512sum, sha1sum, md5sum,
# tar, openssl. Postgres and S3 come from the environment (defaults match
# ci.yml):
#   FORGE_E2E_DATABASE_URL  (postgres://forge:forge@localhost:5432/forge)
#   FORGE_E2E_S3_ENDPOINT   (http://localhost:7070), access/secret forge-e2e-key
#   FORGE_E2E_PORT          (8431: forge-server's)
#   FORGE_E2E_UPSTREAM_PORT (5011: the mock release host; the asset host is
#                            the next port)
set -euo pipefail

server_bin="$(realpath "$1")"
results="$(mkdir -p "$2" && realpath "$2")"
db_url="${FORGE_E2E_DATABASE_URL:-postgres://forge:forge@localhost:5432/forge}"
s3_endpoint="${FORGE_E2E_S3_ENDPOINT:-http://localhost:7070}"
port="${FORGE_E2E_PORT:-8431}"
release_port="${FORGE_E2E_UPSTREAM_PORT:-5011}"
asset_port=$((release_port + 1))
base="http://127.0.0.1:$port"
admin_password="e2e-$(openssl rand -hex 12)"

work=$(mktemp -d)
server_pid=""
upstream_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  if [ -n "$upstream_pid" ]; then kill "$upstream_pid" 2>/dev/null || true; fi
  cp "$work/server.log" "$work/upstream.log" "$results/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { echo; echo "── $* ──"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
# Assert that `curl <args>` answers <status>.
expect_status() { # <status> <curl args...>
  local want=$1
  shift
  local got
  got=$(curl -sS -o "$work/body" -w '%{http_code}' "$@")
  [ "$got" = "$want" ] || fail "curl $* answered $got, not $want: $(head -c 300 "$work/body")"
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
bucket = "forge-raw-e2e"
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
token=$(admin POST /admin/me/tokens '{"name":"raw-e2e"}' | jq -r .token)
auth=(-u "admin:$token")
admin POST /admin/repositories '{"name":"binaries","kind":"hosted","format":"raw"}' >/dev/null
admin POST /admin/repositories "{\"name\":\"releases\",\"kind\":\"proxy\",\"format\":\"raw\",
  \"remote_url\":\"http://127.0.0.1:$release_port/releases/download/\",
  \"upstream_username\":\"mirror\",\"upstream_password\":\"upstream-secret\"}" >/dev/null
admin POST /admin/repositories '{"name":"files","kind":"group","format":"raw"}' >/dev/null
admin POST /admin/repositories/files/members '{"member":"binaries","priority":10}' >/dev/null
admin POST /admin/repositories/files/members '{"member":"releases","priority":5}' >/dev/null

step "hosted: upload with a token, download, ranges, resume"
mkdir -p "$work/up" "$work/down"
head -c 1048576 /dev/urandom > "$work/up/tool-linux-x64.tgz"
url="$base/repository/binaries/tools/1.0/tool-linux-x64.tgz"
expect_status 401 --upload-file "$work/up/tool-linux-x64.tgz" "$url"
expect_status 201 "${auth[@]}" --upload-file "$work/up/tool-linux-x64.tgz" "$url"
curl -fsS "${auth[@]}" -o "$work/down/tool-linux-x64.tgz" "$url"
cmp "$work/up/tool-linux-x64.tgz" "$work/down/tool-linux-x64.tgz" || fail "download differs"
headers=$(curl -fsS "${auth[@]}" -I "$url")
grep -qi "^etag: \"$(sha256sum "$work/up/tool-linux-x64.tgz" | cut -d' ' -f1)\"" <<<"$headers" \
  || fail "ETag is not the SHA-256: $headers"
grep -qi '^last-modified: ' <<<"$headers" || fail "no Last-Modified"
grep -qi '^content-length: 1048576' <<<"$headers" || fail "no Content-Length"
expect_status 206 "${auth[@]}" -r 1000-1999 "$url"
cmp <(head -c 2000 "$work/up/tool-linux-x64.tgz" | tail -c 1000) "$work/body" || fail "range differs"
# A download cut short, then resumed.
curl -fsS "${auth[@]}" -r 0-4095 -o "$work/down/resumed.tgz" "$url"
curl -fsS "${auth[@]}" -C - -o "$work/down/resumed.tgz" "$url"
cmp "$work/up/tool-linux-x64.tgz" "$work/down/resumed.tgz" || fail "resumed download differs"
expect_status 304 "${auth[@]}" -H "If-None-Match: \"$(sha256sum "$work/up/tool-linux-x64.tgz" | cut -d' ' -f1)\"" "$url"

step "checksum sidecars"
(
  cd "$work/down"
  for sum in sha256 sha512 sha1 md5; do
    curl -fsS "${auth[@]}" "$url.$sum" | "${sum}sum" -c - || fail "$sum sidecar"
  done
)
expect_status 404 "${auth[@]}" "$base/repository/binaries/tools/1.0/missing.tgz.sha256"

step "redeploy is refused by default; a form upload; listings"
echo "other content" > "$work/up/other"
expect_status 409 "${auth[@]}" --upload-file "$work/up/other" "$url"
expect_status 204 "${auth[@]}" --upload-file "$work/up/tool-linux-x64.tgz" "$url"
echo "notes" > "$work/up/NOTES.txt"
expect_status 201 "${auth[@]}" -F raw.directory=docs -F "raw.asset1=@$work/up/NOTES.txt" \
  -F raw.asset1.filename=RELEASE-NOTES.txt "$base/repository/binaries/tools/1.0/"
[ "$(curl -fsS "${auth[@]}" "$base/repository/binaries/tools/1.0/docs/RELEASE-NOTES.txt")" = notes ] \
  || fail "form upload"
names=$(curl -fsS "${auth[@]}" -H 'Accept: application/json' "$base/repository/binaries/tools/1.0/" \
  | jq -r '[.entries[].name] | join(",")')
[ "$names" = "docs/,tool-linux-x64.tgz" ] || fail "listing: $names"
curl -fsS "${auth[@]}" "$base/repository/binaries/tools/" | grep -q '<a href="1.0/">1.0/</a>' \
  || fail "HTML listing"

step "path traversal is refused"
for path in '../x' 'tools/../tools/1.0/tool-linux-x64.tgz' '%2e%2e/x' '.%2e/x' \
  'tools/%2E%2E/x' 'tools//1.0' 'tools%2f1.0' 'tools%5c1.0' '..%5cx' 'tools/./1.0'; do
  for method in GET PUT DELETE; do
    expect_status 400 "${auth[@]}" --path-as-is -X "$method" -d x "$base/repository/binaries/$path"
  done
done
code=$(curl -sS -o /dev/null -w '%{http_code}' "${auth[@]}" --path-as-is "$base/repository/../admin/repositories")
[ "$code" != 200 ] || fail "/repository/../admin answered 200"

step "proxy: a release host that redirects to an asset host on another origin"
mkdir -p "$work/upstream/tool/2.0"
head -c 65536 /dev/urandom > "$work/upstream/tool/2.0/tool-linux-x64.tgz"
cat > "$work/upstream.py" <<'EOF'
import functools, http.server, os, sys, threading

root, release_port, asset_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

class Release(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.removeprefix("/releases/download/")
        print(f"release {self.path} auth={'Authorization' in self.headers}", flush=True)
        if name == self.path or not os.path.isfile(os.path.join(root, name)):
            self.send_error(404)
            return
        self.send_response(302)
        self.send_header("Location", f"http://localhost:{asset_port}/{name}?signature=x")
        self.end_headers()

class Asset(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"asset {self.path} auth={'Authorization' in self.headers}", flush=True)
        self.path = self.path.split("?")[0]
        super().do_GET()

asset = http.server.ThreadingHTTPServer(
    ("127.0.0.1", asset_port), functools.partial(Asset, directory=root))
threading.Thread(target=asset.serve_forever, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", release_port), Release).serve_forever()
EOF
python3 -u "$work/upstream.py" "$work/upstream" "$release_port" "$asset_port" > "$work/upstream.log" 2>&1 &
upstream_pid=$!
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$asset_port/" >/dev/null 2>&1 && break; sleep 0.5; done
proxied="$base/repository/releases/tool/2.0/tool-linux-x64.tgz"
curl -fsS "${auth[@]}" -o "$work/down/proxied.tgz" "$proxied"
cmp "$work/upstream/tool/2.0/tool-linux-x64.tgz" "$work/down/proxied.tgz" || fail "proxied file differs"
grep -q '^release /releases/download/tool/2.0/tool-linux-x64.tgz auth=True' "$work/upstream.log" \
  || fail "the release host did not get the credentials: $(cat "$work/upstream.log")"
grep -q '^asset /tool/2.0/tool-linux-x64.tgz?signature=x auth=False' "$work/upstream.log" \
  || fail "the asset host got the credentials: $(cat "$work/upstream.log")"
# Cached: served without the upstream, also while it is down.
kill "$upstream_pid"
wait "$upstream_pid" 2>/dev/null || true
upstream_pid=""
curl -fsS "${auth[@]}" -o "$work/down/proxied-again.tgz" "$proxied"
cmp "$work/down/proxied.tgz" "$work/down/proxied-again.tgz" || fail "cached file differs"
(cd "$work/down" && curl -fsS "${auth[@]}" "$proxied.sha256" | sed 's/tool-linux-x64.tgz$/proxied.tgz/' | sha256sum -c -) \
  || fail "proxied sidecar"
expect_status 502 "${auth[@]}" "$base/repository/releases/tool/2.0/not-cached.tgz"

step "group: the first member that has the path"
[ "$(curl -fsS "${auth[@]}" "$base/repository/files/tools/1.0/docs/RELEASE-NOTES.txt")" = notes ] \
  || fail "group: hosted member"
curl -fsS "${auth[@]}" -o "$work/down/via-group.tgz" "$base/repository/files/tool/2.0/tool-linux-x64.tgz"
cmp "$work/down/proxied.tgz" "$work/down/via-group.tgz" || fail "group: proxy member"
names=$(curl -fsS "${auth[@]}" -H 'Accept: application/json' "$base/repository/files/" \
  | jq -r '[.entries[].name] | join(",")')
[ "$names" = "tool/,tools/" ] || fail "group listing: $names"

if [ "${FORGE_E2E_SKIP_GITHUB:-0}" != 1 ]; then
  step "pdfium: proxy a GitHub release asset, host a re-packaged copy"
  admin POST /admin/repositories '{"name":"pdfium","kind":"proxy","format":"raw",
    "remote_url":"https://github.com/bblanchon/pdfium-binaries/releases/download/",
    "max_age_seconds":0}' >/dev/null
  asset="$base/repository/pdfium/chromium/7350/pdfium-linux-x64.tgz"
  (
    cd "$work/down"
    curl -fsS "${auth[@]}" -O "$asset"
    # Listed to a file: `grep -q` would end the pipe early (pipefail).
    tar -tzf pdfium-linux-x64.tgz > contents
    grep -qx 'lib/libpdfium.so' contents || fail "not a pdfium archive"
    curl -fsS "${auth[@]}" "$asset.sha256" | sha256sum -c - || fail "pdfium sidecar"
    # Re-packaged: only the library and the headers.
    mkdir pdfium
    tar -xzf pdfium-linux-x64.tgz -C pdfium
    tar -czf repackaged.tgz -C pdfium lib include
    hosted="$base/repository/binaries/pdfium/7350/pdfium-linux-x64.tgz"
    expect_status 201 "${auth[@]}" --upload-file repackaged.tgz "$hosted"
    mkdir check
    cd check
    curl -fsS "${auth[@]}" -o pdfium-linux-x64.tgz "$hosted"
    curl -fsS "${auth[@]}" "$hosted.sha256" | sha256sum -c - || fail "hosted pdfium sidecar"
    cmp pdfium-linux-x64.tgz ../repackaged.tgz || fail "hosted pdfium differs"
  )
fi

echo
echo "raw e2e: all checks passed"
