#!/usr/bin/env bash
# Lint and render the Helm chart (deploy/helm/forge) and validate the output
# (used by ci.yml): `helm lint --strict` and `helm template` with the default
# values and with each file in the chart's ci/ directory, kubeconform against
# the Kubernetes schemas (plus the Gateway API and cert-manager CRDs), and
# every rendered forge.toml parsed as TOML.
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

render default
for values in "$chart"/ci/*.yaml; do
  render "$(basename "$values" .yaml)" --values "$values"
done
# Numbers given with --set arrive as integers, not as YAML's floats.
render set-flags --set config.server.max_upload_bytes=1048576 --set replicaCount=2
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
