#!/usr/bin/env bash
# End-to-end check of npm repositories with the real clients (used by
# ci.yml): boots forge-server and a mock upstream registry, then
#
#   1. signs in with npm's web login (`npm login`, approved through the API
#      of the browser page it opens) and with the legacy login of Yarn
#      (`yarn npm login`: npm's own legacy login refuses a username with an
#      `@`, which every Forge account has), checks whoami, and logs out;
#   2. publishes a scoped and an unscoped package with npm, one with pnpm,
#      and one through the group (to its writable member); a republish is
#      refused;
#   3. installs with npm and pnpm from the hosted repository, from the proxy
#      of the mock upstream and from the group, checks that the lockfiles
#      point at Forge, and that the proxy's full packument carries the
#      upstream's publish times (npm and pnpm 11 read them), its abbreviated
#      one none;
#   4. moves dist-tags, deprecates a version and unpublishes;
#   5. the group's dependency-confusion guard: the upstream's package in the
#      internal scope `@acme` is never served through the group;
#   6. runs npm audit through the group, whose upstream request leaves the
#      internal scope's packages out.
#
# Usage: npm-e2e.sh <forge-server binary> <results dir>
# Needs on PATH: curl, jq, python3, node, npm, pnpm, tar, openssl. Yarn 2+ is
# YARN_BERRY (a yarn.js), else fetched from the npm registry with npm pack.
# Postgres and S3 come from the environment (defaults match ci.yml):
#   FORGE_E2E_DATABASE_URL  (postgres://forge:forge@localhost:5432/forge)
#   FORGE_E2E_S3_ENDPOINT   (http://localhost:7070), access/secret forge-e2e-key
#   FORGE_E2E_PORT          (8431: forge-server's)
#   FORGE_E2E_UPSTREAM_PORT (5021: the mock upstream registry)
set -euo pipefail

server_bin="$(realpath "$1")"
results="$(mkdir -p "$2" && realpath "$2")"
db_url="${FORGE_E2E_DATABASE_URL:-postgres://forge:forge@localhost:5432/forge}"
s3_endpoint="${FORGE_E2E_S3_ENDPOINT:-http://localhost:7070}"
port="${FORGE_E2E_PORT:-8431}"
upstream_port="${FORGE_E2E_UPSTREAM_PORT:-5021}"
base="http://127.0.0.1:$port"
upstream="http://127.0.0.1:$upstream_port"
admin_user="admin@example.com"
admin_password="e2e-$(openssl rand -hex 12)"

work=$(mktemp -d)
server_pid=""
upstream_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  if [ -n "$upstream_pid" ]; then kill "$upstream_pid" 2>/dev/null || true; fi
  cp "$work/server.log" "$work/upstream.log" "$results/" 2>/dev/null || true
  cp "$work"/*.out "$results/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { echo; echo "── $* ──"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
# The clients' configuration and caches stay inside the work directory.
export HOME="$work/home" NPM_CONFIG_USERCONFIG="$work/home/.npmrc"
export npm_config_cache="$work/npm-cache" npm_config_update_notifier=false
export npm_config_fund=false npm_config_audit=false
mkdir -p "$HOME"
reg() { echo "$base/npm/$1/"; }
# The versions `npm view` lists, as a JSON array (one version is printed
# bare by some npm releases).
versions() { # <package> <registry>
  npm view "$1" versions --json --registry "$2" | jq -c 'if type == "array" then . else [.] end'
}

step "a mock upstream registry"
# Its packages, made with npm pack: e2e-public (1.0.0, and 1.1.0 depending
# on e2e-dep) and a public @acme/ui that claims the internal scope.
mkdir -p "$work/upstream"
pack() { # <dir> <name> <version> [dependencies json]
  mkdir -p "$1"
  jq -n --arg name "$2" --arg version "$3" --argjson deps "${4:-{\}}" \
    '{name: $name, version: $version, description: "e2e", license: "MIT", main: "index.js",
      dependencies: $deps}' > "$1/package.json"
  echo "module.exports = '$2@$3'" > "$1/index.js"
  echo "# $2" > "$1/README.md"
  (cd "$1" && npm pack --silent --pack-destination "$work/upstream" >/dev/null)
}
pack "$work/src/up-public-1.0.0" e2e-public 1.0.0
pack "$work/src/up-public-1.1.0" e2e-public 1.1.0 '{"e2e-dep":"^2.0.0"}'
pack "$work/src/up-dep-2.0.0" e2e-dep 2.0.0
pack "$work/src/up-acme-ui" @acme/ui 9.9.9
cat > "$work/upstream.py" <<'EOF'
import base64, glob, hashlib, http.server, json, os, sys, tarfile, threading, urllib.parse

root, port = sys.argv[1], int(sys.argv[2])
packages, tarballs = {}, {}
for path in sorted(glob.glob(os.path.join(root, "*.tgz"))):
    data = open(path, "rb").read()
    with tarfile.open(path) as tar:
        manifest = json.load(tar.extractfile("package/package.json"))
    name, version = manifest["name"], manifest["version"]
    file = f"{name.split('/')[-1]}-{version}.tgz"
    tarballs[f"/{name}/-/{file}"] = data
    manifest["_id"] = f"{name}@{version}"
    manifest["dist"] = {
        "tarball": f"http://127.0.0.1:{port}/{name}/-/{file}",
        "shasum": hashlib.sha1(data).hexdigest(),
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
    }
    doc = packages.setdefault(name, {"name": name, "versions": {}, "time": {}, "dist-tags": {}})
    doc["versions"][version] = manifest
    doc["time"][version] = "2020-01-01T00:00:00.000Z"
    doc["dist-tags"]["latest"] = version

# Requests are handled on threads of their own: each logs one whole line at
# a time, or two lines written at once run together and the checks that
# count them miss one.
log_lock = threading.Lock()

def log(line):
    with log_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

class Registry(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def answer(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.unquote(self.path.split("?")[0])
        auth = f"auth={'Authorization' in self.headers}"
        if path in tarballs:
            log(f"GET {path} {auth}")
            self.answer(200, tarballs[path], "application/octet-stream")
        elif path.lstrip("/") in packages:
            # Which packument the proxy asked for: the abbreviated one
            # installs need, or the full one.
            abbreviated = "application/vnd.npm.install-v1+json" in self.headers.get("Accept", "")
            log(f"GET {path} {auth} packument={'abbreviated' if abbreviated else 'full'}")
            self.answer(200, json.dumps(packages[path.lstrip("/")]).encode())
        elif path == "/-/v1/search":
            self.answer(200, b'{"objects":[],"total":0,"time":"2020-01-01T00:00:00.000Z"}')
        else:
            self.answer(404, b'{"error":"not found"}')

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        log(f"POST {self.path} {body.decode()}")
        if self.path != "/-/npm/v1/security/advisories/bulk":
            self.answer(404, b'{"error":"not found"}')
            return
        advisories = {}
        if "e2e-public" in json.loads(body):
            advisories["e2e-public"] = [{
                "id": 1001, "url": "https://advisories.example.com/1001",
                "title": "Prototype pollution in e2e-public", "severity": "high",
                "vulnerable_versions": "<1.1.0", "cwe": ["CWE-1321"],
                "cvss": {"score": 7.5, "vectorString": None},
            }]
        self.answer(200, json.dumps(advisories).encode())

http.server.ThreadingHTTPServer(("127.0.0.1", port), Registry).serve_forever()
EOF
python3 -u "$work/upstream.py" "$work/upstream" "$upstream_port" > "$work/upstream.log" 2>&1 &
upstream_pid=$!
for _ in $(seq 1 30); do curl -fsS "$upstream/e2e-public" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$upstream/e2e-public" >/dev/null || fail "the mock upstream did not start"

step "start forge-server"
mkdir -p "$work/web"
echo '<!doctype html><title>Forge</title>' > "$work/web/index.html"
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
bucket = "forge-npm-e2e"
access_key = "forge-e2e-key"
secret_key = "forge-e2e-secret"
force_path_style = true
[crypto.root]
provider = "file"
root_key_path = "$work/root.key"
[auth.bootstrap_admin]
username = "$admin_user"
password = "$admin_password"
[outbox]
grace_seconds = 0
poll_interval_seconds = 2
[web]
enabled = true
assets_dir = "$work/web"
EOF
FORGE_CONFIG="$work/forge.toml" RUST_LOG=info "$server_bin" > "$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 60); do
  if curl -fsS "$base/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "$base/readyz" >/dev/null || { cat "$work/server.log"; fail "server not ready"; }

step "create repositories"
login=$(curl -fsS -c "$work/jar" -H 'content-type: application/json' \
  -d "{\"username\":\"$admin_user\",\"password\":\"$admin_password\"}" "$base/auth/login")
csrf=$(jq -r .csrf_token <<<"$login")
admin() { # <method> <path> [json body]
  curl -fsS -b "$work/jar" -H "x-csrf-token: $csrf" -H 'content-type: application/json' \
    -X "$1" "$base$2" ${3:+-d "$3"}
}
admin POST /admin/repositories '{"name":"npm-hosted","kind":"hosted","format":"npm"}' >/dev/null
admin POST /admin/repositories "{\"name\":\"npm-proxy\",\"kind\":\"proxy\",\"format\":\"npm\",
  \"remote_url\":\"$upstream\"}" >/dev/null
admin POST /admin/repositories '{"name":"npm-all","kind":"group","format":"npm",
  "reserved_prefixes":["@acme"],"writable_member":"npm-hosted"}' >/dev/null
admin POST /admin/repositories/npm-all/members '{"member":"npm-hosted","priority":10}' >/dev/null
admin POST /admin/repositories/npm-all/members '{"member":"npm-proxy","priority":5}' >/dev/null

step "web login with npm"
# `npm login` prints the page to open and polls until it is approved; the
# page's API approves it here, as the signed-in admin would in the browser.
web_login() { # <userconfig> <output>
  npm login --browser=false --registry "$(reg npm-all)" --userconfig "$1" \
    > "$2" 2>&1 < /dev/null &
  local pid=$! url=""
  for _ in $(seq 1 30); do
    url=$(grep -o "$base/cli-login/[A-Za-z0-9_-]*" "$2" | head -1 || true)
    [ -n "$url" ] && break
    sleep 0.5
  done
  [ -n "$url" ] || { kill "$pid"; fail "npm login printed no login URL: $(cat "$2")"; }
  admin GET "/auth/cli-login/${url##*/}" | jq -e '.client == "npm" and .repository == "npm-all"' \
    >/dev/null || fail "the login request does not say who asks"
  admin POST "/auth/cli-login/${url##*/}" '{"approve":true}'
  wait "$pid" || fail "npm login failed: $(cat "$2")"
}
web_login "$NPM_CONFIG_USERCONFIG" "$work/npm-login.out"
grep -q "Logged in on $(reg npm-all)" "$work/npm-login.out" || fail "npm login: $(cat "$work/npm-login.out")"
[ "$(npm whoami --registry "$(reg npm-all)")" = "$admin_user" ] || fail "npm whoami"
token=$(sed -n 's#^//127.0.0.1:'"$port"'/npm/npm-all/:_authToken=##p' "$NPM_CONFIG_USERCONFIG")
[ -n "$token" ] || fail "npm login stored no token"
# The token is the account's: the other repositories take it too.
for repo in npm-hosted npm-proxy; do
  echo "//127.0.0.1:$port/npm/$repo/:_authToken=$token" >> "$NPM_CONFIG_USERCONFIG"
done
[ "$(npm whoami --registry "$(reg npm-hosted)")" = "$admin_user" ] || fail "npm whoami (hosted)"

step "legacy login with Yarn, and logout"
yarn_js="${YARN_BERRY:-}"
if [ -z "$yarn_js" ]; then
  mkdir -p "$work/yarn"
  (cd "$work/yarn" && npm pack --silent @yarnpkg/cli-dist@4.18.1 >/dev/null && tar xzf ./*.tgz)
  yarn_js="$work/yarn/package/bin/yarn.js"
fi
# Answers a client's prompts on a terminal: answer.py <prompt> <answer>... -- <command...>
cat > "$work/answer.py" <<'EOF'
import os, pty, sys, time
args = sys.argv[1:]
split = args.index("--")
pairs = list(zip(args[:split:2], args[1:split:2]))
pid, fd = pty.fork()
if pid == 0:
    os.execvp(args[split + 1], args[split + 1:])
seen, deadline = b"", time.time() + 60
while time.time() < deadline:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    sys.stdout.buffer.write(chunk)
    seen += chunk
    if pairs and pairs[0][0].encode() in seen:
        seen = b""
        os.write(fd, pairs.pop(0)[1].encode() + b"\r")
else:
    os.kill(pid, 9)
    sys.exit("timed out")
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
EOF
mkdir -p "$work/yarn-project"
(
  cd "$work/yarn-project"
  echo '{"name":"yarn-project","version":"1.0.0"}' > package.json
  touch yarn.lock
  printf 'npmRegistryServer: "%s"\nunsafeHttpWhitelist: ["127.0.0.1"]\nenableTelemetry: false\n' \
    "$(reg npm-all)" > .yarnrc.yml
  python3 "$work/answer.py" Username "$admin_user" Password "$admin_password" -- \
    node "$yarn_js" npm login > "$work/yarn-login.out" 2>&1 \
    || fail "yarn npm login: $(cat "$work/yarn-login.out")"
  # Read the output whole: a `| grep -q` that exits at its match leaves Yarn
  # writing into a closed pipe, which it dies of (EPIPE).
  who=$(node "$yarn_js" npm whoami 2>&1) || fail "yarn npm whoami: $who"
  [[ "$who" == *"$admin_user"* ]] || fail "yarn npm whoami: $who"
)
grep -q npmAuthToken "$HOME/.yarnrc.yml" || fail "yarn stored no token"
# A wrong password is refused.
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'content-type: application/json' \
  -d "{\"name\":\"$admin_user\",\"password\":\"wrong\"}" \
  "$base/npm/npm-all/-/user/org.couchdb.user:$admin_user")
[ "$code" = 401 ] || fail "a wrong password answered $code"
# `npm logout` revokes the token it signed in with.
web_login "$work/throwaway-npmrc" "$work/npm-login-2.out"
throwaway=$(sed -n 's#^//127.0.0.1:'"$port"'/npm/npm-all/:_authToken=##p' "$work/throwaway-npmrc")
npm logout --registry "$(reg npm-all)" --userconfig "$work/throwaway-npmrc" >/dev/null
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $throwaway" "$base/npm/npm-all/-/whoami")
[ "$code" = 401 ] || fail "a logged-out token answered $code"

step "the group keeps the internal scope internal"
[ "$(npm view @acme/ui version --registry "$(reg npm-proxy)")" = 9.9.9 ] \
  || fail "the proxy does not see the upstream's @acme/ui"
if npm view @acme/ui --registry "$(reg npm-all)" > "$work/guard.out" 2>&1; then
  fail "the group served the upstream's @acme/ui: $(cat "$work/guard.out")"
fi
grep -q E404 "$work/guard.out" || fail "the guard: $(cat "$work/guard.out")"

step "publish with npm and pnpm"
package() { # <dir> <name> <version> [dependencies json]
  mkdir -p "$1"
  jq -n --arg name "$2" --arg version "$3" --argjson deps "${4:-{\}}" \
    '{name: $name, version: $version, description: "published by the e2e", license: "MIT",
      main: "index.js", dependencies: $deps}' > "$1/package.json"
  echo "module.exports = '$2@$3'" > "$1/index.js"
  printf '# %s\n\nPublished by the npm e2e.\n' "$2" > "$1/README.md"
}
package "$work/src/acme-ui" @acme/ui 1.0.0
package "$work/src/hosted-1.0.0" e2e-hosted 1.0.0
package "$work/src/hosted-1.1.0" e2e-hosted 1.1.0 '{"@acme/ui":"^1.0.0"}'
package "$work/src/acme-core" @acme/core 1.0.0
package "$work/src/pnpm-made" pnpm-made 1.0.0
(cd "$work/src/acme-ui" && npm publish --registry "$(reg npm-hosted)") >/dev/null
(cd "$work/src/hosted-1.0.0" && npm publish --registry "$(reg npm-hosted)") >/dev/null
(cd "$work/src/hosted-1.1.0" && npm publish --registry "$(reg npm-hosted)") >/dev/null
# Through the group: it lands in the writable member.
(cd "$work/src/acme-core" && npm publish --registry "$(reg npm-all)") >/dev/null
(cd "$work/src/pnpm-made" && pnpm publish --no-git-checks --registry "$(reg npm-hosted)") >/dev/null
[ "$(npm view @acme/core version --registry "$(reg npm-hosted)")" = 1.0.0 ] \
  || fail "a publish through the group did not land in npm-hosted"
# --force: npm 11 refuses a version the registry lists by itself; the
# server must refuse it too.
if (cd "$work/src/hosted-1.0.0" && npm publish --force --registry "$(reg npm-hosted)") \
  > "$work/republish.out" 2>&1; then
  fail "a republish of e2e-hosted@1.0.0 was accepted"
fi
grep -q "409 Conflict.*e2e-hosted 1.0.0 already exists" "$work/republish.out" \
  || fail "the republish: $(cat "$work/republish.out")"
# The internal @acme/ui is the group's now, the public one still is not.
[ "$(versions @acme/ui "$(reg npm-all)")" = '["1.0.0"]' ] \
  || fail "the group serves another @acme/ui: $(versions @acme/ui "$(reg npm-all)")"

step "install with npm and pnpm"
project() { # <dir> <registry>
  mkdir -p "$1"
  echo '{"name":"consumer","version":"1.0.0","private":true}' > "$1/package.json"
  echo "registry=$2" > "$1/.npmrc"
}
resolved_from() { # <package-lock.json> <registry>: every resolved URL is under it
  jq -e --arg reg "$2" '[.packages[] | select(.resolved) | .resolved | startswith($reg)] | all' "$1" \
    >/dev/null || fail "$1 resolves elsewhere than $2: $(jq -c '[.packages[].resolved]' "$1")"
}
version_of() { node -p "require('$1/package.json').version"; }
# Hosted.
project "$work/use-hosted" "$(reg npm-hosted)"
(cd "$work/use-hosted" && npm install e2e-hosted pnpm-made) >/dev/null
[ "$(version_of "$work/use-hosted/node_modules/e2e-hosted")" = 1.1.0 ] || fail "npm install from hosted"
[ "$(version_of "$work/use-hosted/node_modules/@acme/ui")" = 1.0.0 ] || fail "a scoped dependency from hosted"
resolved_from "$work/use-hosted/package-lock.json" "$(reg npm-hosted)"
# Proxy: the tarballs come through Forge, the upstream sees each once.
project "$work/use-proxy" "$(reg npm-proxy)"
(cd "$work/use-proxy" && npm install e2e-public) >/dev/null
[ "$(version_of "$work/use-proxy/node_modules/e2e-public")" = 1.1.0 ] || fail "npm install from the proxy"
[ "$(version_of "$work/use-proxy/node_modules/e2e-dep")" = 2.0.0 ] || fail "a dependency from the proxy"
resolved_from "$work/use-proxy/package-lock.json" "$(reg npm-proxy)"
rm -rf "$work/use-proxy/node_modules" "$work/npm-cache"
(cd "$work/use-proxy" && npm ci) >/dev/null
[ "$(grep -c '^GET /e2e-public/-/e2e-public-1.1.0.tgz' "$work/upstream.log")" = 1 ] \
  || fail "the upstream served the tarball more than once: $(cat "$work/upstream.log")"
# Group, with npm and with pnpm.
project "$work/use-group" "$(reg npm-all)"
(cd "$work/use-group" && npm install e2e-public @acme/ui e2e-hosted) >/dev/null
[ "$(version_of "$work/use-group/node_modules/@acme/ui")" = 1.0.0 ] || fail "the group installed another @acme/ui"
resolved_from "$work/use-group/package-lock.json" "$(reg npm-all)"
project "$work/use-pnpm" "$(reg npm-all)"
(cd "$work/use-pnpm" && pnpm add --store-dir "$work/pnpm-store" e2e-public @acme/ui e2e-hosted pnpm-made) >/dev/null
[ "$(version_of "$work/use-pnpm/node_modules/@acme/ui")" = 1.0.0 ] || fail "pnpm installed another @acme/ui"
[ "$(version_of "$work/use-pnpm/node_modules/e2e-public")" = 1.1.0 ] || fail "pnpm add through the group"
grep -q "tarball: $(reg npm-all)" "$work/use-pnpm/pnpm-lock.yaml" 2>/dev/null \
  || grep -q 'e2e-public@1.1.0' "$work/use-pnpm/pnpm-lock.yaml" || fail "no pnpm lockfile"
project "$work/use-pnpm-proxy" "$(reg npm-proxy)"
(cd "$work/use-pnpm-proxy" && pnpm add --store-dir "$work/pnpm-store-2" e2e-public) >/dev/null
[ "$(version_of "$work/use-pnpm-proxy/node_modules/e2e-public")" = 1.1.0 ] || fail "pnpm add from the proxy"
# The proxy's full packument has the upstream's publish times (`npm view
# time`, `npm install --before`, pnpm's minimumReleaseAge); the abbreviated
# one, which installs may ask for instead, has none.
published=$(npm view e2e-public time --json --registry "$(reg npm-proxy)" | jq -r '.["1.1.0"]')
[ "$published" = 2020-01-01T00:00:00.000Z ] || fail "the proxy's publish time of e2e-public 1.1.0: $published"
curl -fsS -D "$work/corgi.headers" -o "$work/corgi.json" -H "Authorization: Bearer $token" \
  -H 'Accept: application/vnd.npm.install-v1+json' "$base/npm/npm-proxy/e2e-public"
grep -qi '^content-type: application/vnd.npm.install-v1+json' "$work/corgi.headers" \
  || fail "the abbreviated packument: $(cat "$work/corgi.headers")"
jq -e '(has("time") | not) and .versions["1.1.0"].dist.tarball != null' "$work/corgi.json" >/dev/null \
  || fail "the abbreviated packument: $(cat "$work/corgi.json")"
if command -v bun >/dev/null; then
  project "$work/use-bun" "$(reg npm-all)"
  (cd "$work/use-bun" && bun add --cache-dir "$work/bun-cache" e2e-hosted) >/dev/null
  [ "$(version_of "$work/use-bun/node_modules/e2e-hosted")" = 1.1.0 ] || fail "bun add through the group"
fi

step "dist-tags, deprecation, unpublishing"
hosted=(--registry "$(reg npm-hosted)")
npm dist-tag add e2e-hosted@1.0.0 legacy "${hosted[@]}" >/dev/null
npm dist-tag ls e2e-hosted "${hosted[@]}" > "$work/tags.out"
grep -qx 'latest: 1.1.0' "$work/tags.out" && grep -qx 'legacy: 1.0.0' "$work/tags.out" \
  || fail "dist-tags: $(cat "$work/tags.out")"
(cd "$work/use-hosted" && npm install e2e-hosted@legacy) >/dev/null
[ "$(version_of "$work/use-hosted/node_modules/e2e-hosted")" = 1.0.0 ] || fail "install by dist-tag"
npm dist-tag rm e2e-hosted legacy "${hosted[@]}" >/dev/null
tags=$(npm dist-tag ls e2e-hosted "${hosted[@]}") || fail "npm dist-tag ls"
[[ "$tags" != *legacy* ]] || fail "dist-tag rm: $tags"
npm deprecate e2e-hosted@1.0.0 "use 1.1.0" "${hosted[@]}" >/dev/null
[ "$(npm view e2e-hosted@1.0.0 deprecated "${hosted[@]}")" = "use 1.1.0" ] || fail "npm deprecate"
rm -rf "$work/use-hosted/node_modules"
(cd "$work/use-hosted" && npm install e2e-hosted@1.0.0) > "$work/deprecated.out" 2>&1
grep -q "deprecated e2e-hosted@1.0.0: use 1.1.0" "$work/deprecated.out" \
  || fail "npm did not warn about the deprecation: $(cat "$work/deprecated.out")"
npm unpublish e2e-hosted@1.1.0 --force "${hosted[@]}" >/dev/null
[ "$(versions e2e-hosted "$(reg npm-hosted)")" = '["1.0.0"]' ] || fail "unpublish a version"
[ "$(npm view e2e-hosted dist-tags.latest "${hosted[@]}")" = 1.0.0 ] || fail "latest after the unpublish"
npm unpublish pnpm-made --force "${hosted[@]}" >/dev/null
if npm view pnpm-made "${hosted[@]}" >/dev/null 2>&1; then fail "unpublish a package"; fi

step "npm audit through the group"
project "$work/audit" "$(reg npm-all)"
(cd "$work/audit" && npm install e2e-public@1.0.0 @acme/ui) >/dev/null
(cd "$work/audit" && npm audit --json --audit=true > "$work/audit.out") || true
jq -e '.vulnerabilities["e2e-public"].severity == "high"' "$work/audit.out" >/dev/null \
  || fail "npm audit: $(cat "$work/audit.out")"
grep '^POST /-/npm/v1/security/advisories/bulk' "$work/upstream.log" > "$work/audits.out" \
  || fail "no audit reached the upstream"
if grep -q '@acme' "$work/audits.out"; then fail "the audit told the upstream about @acme: $(cat "$work/audits.out")"; fi

step "the upstream never saw Forge's credentials"
if grep -q 'auth=True' "$work/upstream.log"; then fail "credentials went upstream"; fi

echo
echo "npm e2e passed"
