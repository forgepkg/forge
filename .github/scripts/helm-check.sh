#!/usr/bin/env bash
# Lint and render the Helm chart (deploy/helm/forge) and validate the output
# (used by ci.yml): `helm template` refusing the default values, which have no
# root key; `helm lint --strict` and `helm template` with the default values
# plus a root key and with each file in the chart's ci/ directory; kubeconform
# against the Kubernetes schemas (plus the Gateway API and cert-manager CRDs), every
# rendered forge.toml parsed as TOML, a Recreate strategy rendered without
# rollingUpdate, and the pod annotations that roll the pods on a secret change
# salted.
#
# Usage: helm-check.sh <kubernetes version, e.g. 1.33.0>
# Needs helm, kubeconform and python3 (3.11+) on PATH.
set -euo pipefail

k8s_version="$1"
chart="$(cd "$(dirname "$0")/../.." && pwd)/deploy/helm/forge"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

render() { # <output name> [helm values args...]
  local name="$1"
  shift
  echo "helm lint + template: $name" >&2
  helm lint --strict --with-subcharts --kube-version "$k8s_version" "$chart" "$@" > "$work/lint.log" \
    || { cat "$work/lint.log"; return 1; }
  helm template forge "$chart" --namespace forge --kube-version "$k8s_version" "$@" > "$work/$name.yaml"
}

# Without a root key the chart refuses to render, naming the setting.
if helm template forge "$chart" --namespace forge --kube-version "$k8s_version" \
  > /dev/null 2> "$work/no-root-key.log"; then
  echo "the chart renders without a root key" >&2
  exit 1
fi
grep -q 'set FORGE_ROOT_KEY in secretEnv' "$work/no-root-key.log" \
  || { cat "$work/no-root-key.log"; exit 1; }
rm -f "$work/no-root-key.log"
echo "no root key: refused" >&2

root_key=(--set-string secretEnv.FORGE_ROOT_KEY=check-only)
render default "${root_key[@]}"
for values in "$chart"/ci/*.yaml; do
  render "$(basename "$values" .yaml)" --values "$values"
done
# Numbers given with --set arrive as integers, not as YAML's floats.
render set-flags --set config.server.max_staging_bytes=8589934592 --set replicaCount=2 \
  "${root_key[@]}"
rm -f "$work/lint.log"

kubeconform -strict -summary -kubernetes-version "$k8s_version" \
  -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  "$work"/*.yaml

# The chart writes forge.toml itself (Helm's toToml prints integers as
# floats): each rendering must be valid TOML, and since Forge has no float
# settings, any float is a rendering bug.
python3 - "$work"/*.yaml <<'EOF'
import sys
import tomllib


def forge_tomls(path):
    """The forge.toml block scalars of the rendered ConfigMaps in `path`."""
    lines = open(path, encoding="utf-8").read().split("\n")
    for i, line in enumerate(lines):
        if line == "  forge.toml: |":
            block = []
            for body in lines[i + 1 :]:
                if body.strip() and not body.startswith("    "):
                    break
                block.append(body[4:])
            yield "\n".join(block)


def floats(value, path=""):
    if isinstance(value, float):
        yield path
    elif isinstance(value, dict):
        for key, inner in value.items():
            yield from floats(inner, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for index, inner in enumerate(value):
            yield from floats(inner, f"{path}[{index}]")


failed = False
for path in sys.argv[1:]:
    documents = list(forge_tomls(path))
    if len(documents) != 1:
        print(f"{path}: expected one forge.toml, found {len(documents)}")
        failed = True
        continue
    try:
        config = tomllib.loads(documents[0])
    except tomllib.TOMLDecodeError as err:
        print(f"{path}: forge.toml is not valid TOML: {err}\n{documents[0]}")
        failed = True
        continue
    for key in floats(config):
        print(f"{path}: forge.toml has a float at {key}")
        failed = True
    if not config.get("server", {}).get("bind"):
        print(f"{path}: forge.toml has no server.bind")
        failed = True
sys.exit(1 if failed else 0)
EOF
echo "forge.toml: every rendering parses" >&2

# The API server refuses a Deployment whose Recreate strategy carries
# rollingUpdate, a rule kubeconform does not check. A values file's
# `strategy.type: Recreate` is merged into the default's rollingUpdate, which
# the chart must leave out (ci/persistent-cache-values.yaml).
python3 - "$work"/*.yaml <<'EOF'
import re
import sys

failed = False
recreate = False
for path in sys.argv[1:]:
    for document in open(path, encoding="utf-8").read().split("\n---\n"):
        if not re.search(r"^kind: Deployment$", document, re.M):
            continue
        strategy = re.search(r"^  strategy:\n((?:    .*\n)*)", document, re.M)
        if not strategy or not re.search(r"^    type: Recreate$", strategy.group(1), re.M):
            continue
        recreate = True
        if re.search(r"^    rollingUpdate:", strategy.group(1), re.M):
            print(f"{path}: a Recreate strategy with rollingUpdate:\n{strategy.group(1)}")
            failed = True
if not recreate:
    print("no rendering has a Recreate strategy")
    failed = True
sys.exit(1 if failed else 0)
EOF
echo "strategy: Recreate renders without rollingUpdate" >&2

# A secretEnv or Valkey password change rolls the pods through a pod
# annotation (checksum/secret-env, Valkey's checksum/auth) that anyone who can
# read the pods sees, so it must not be the plain SHA-256 of the secrets,
# which can be tested against guesses. Render known secrets, once with a
# generated salt and once with one set in the values, next to the plain JSON
# the chart hashes (an extraObjects ConfigMap): each annotation must differ
# from the plain hash and be the hash salted with the salt the chart keeps in
# its Secret (the same value in one render).
plain='[{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "plain-secrets"},
  "data": {"secret-env": "{{ toJson .Values.secretEnv }}", "valkey-auth": "{{ toJson .Values.valkey.auth }}"}}]'
for salt in "" check-salt; do
  helm template forge "$chart" --namespace forge --kube-version "$k8s_version" \
    --set valkey.enabled=true \
    --set-string secretEnv.FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD=check-only \
    "${root_key[@]}" \
    --set-string valkey.auth.password=check-only \
    --set-string secretEnvChecksumSalt="$salt" --set-string valkey.auth.checksumSalt="$salt" \
    --set-json extraObjects="$plain" > "$work/salted-${salt:-generated}.yaml"
done
python3 - "$work/salted-generated.yaml" "$work/salted-check-salt.yaml" <<'EOF'
import base64
import hashlib
import json
import re
import sys


def find(documents, kind, name):
    for document in documents:
        if re.search(rf"^kind: {kind}$", document, re.M) and re.search(rf"^  name: {re.escape(name)}$", document, re.M):
            return document
    sys.exit(f"no {kind} {name}")


def field(document, key):
    match = re.search(rf"^ +{re.escape(key)}: (.+)$", document, re.M)
    if not match:
        sys.exit(f"no {key} in\n{document}")
    value = match.group(1)
    return value[1:-1] if value[0] in "'\"" else value


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


failed = False
for path, set_salt in zip(sys.argv[1:], ["", "check-salt"]):
    documents = open(path, encoding="utf-8").read().split("\n---\n")
    plain = find(documents, "ConfigMap", "plain-secrets")
    env_json = field(plain, "secret-env")
    auth_json = field(plain, "valkey-auth")
    salts = {
        "checksum/secret-env": base64.b64decode(field(find(documents, "Secret", "forge-checksum-salt"), "salt")).decode(),
        "checksum/auth": base64.b64decode(field(find(documents, "Secret", "forge-valkey"), "checksum-salt")).decode(),
    }
    auth = {k: v for k, v in json.loads(auth_json).items() if k not in ("password", "checksumSalt")}
    auth["password"] = sha256(salts["checksum/auth"] + "\n" + json.loads(auth_json)["password"])
    cases = [
        ("checksum/secret-env", "forge", env_json, sha256(salts["checksum/secret-env"] + "\n" + env_json)),
        ("checksum/auth", "forge-valkey", auth_json, sha256(json.dumps(auth, separators=(",", ":"), sort_keys=True))),
    ]
    for annotation, deployment, plain_json, salted in cases:
        value = field(find(documents, "Deployment", deployment), annotation)
        salt = salts[annotation]
        if value == sha256(plain_json):
            print(f"{path}: {annotation} is the plain SHA-256 of {plain_json}")
            failed = True
        if value != salted:
            print(f"{path}: {annotation} is not the hash salted with the salt the chart keeps ({salt!r})")
            failed = True
        if set_salt and salt != set_salt or not set_salt and len(salt) < 32:
            print(f"{path}: {annotation}: the chart keeps the salt {salt!r}, expected {set_salt or 'a generated one'}")
            failed = True
sys.exit(1 if failed else 0)
EOF
echo "checksum annotations: salted" >&2
