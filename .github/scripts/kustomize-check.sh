#!/usr/bin/env bash
# Render the Kubernetes manifests (deploy/kubernetes) and validate them (used
# by ci.yml): every overlay, and the base with each component on its own, are
# built with kustomize and checked with kubeconform against the Kubernetes
# schemas (plus the Gateway API CRDs for the HTTPRoute). An overlay that sets
# FORGE_AUTH__TRUSTED_PROXY_CIDRS must also render the forge NetworkPolicy
# (components/network-policy).
#
# Usage: kustomize-check.sh <kubernetes version, e.g. 1.33.0>
# Needs kustomize and kubeconform on PATH.
set -euo pipefail

k8s_version="$1"
root="$(cd "$(dirname "$0")/../.." && pwd)/deploy/kubernetes"
work=$(mktemp -d)
# Kustomize only follows relative paths, so the per-component kustomizations
# live next to the base.
scratch=$(mktemp -d "$root/.check.XXXXXX")
created=()
cleanup() {
  rm -rf "$work" "$scratch"
  if [ "${#created[@]}" -gt 0 ]; then rm -f "${created[@]}"; fi
}
trap cleanup EXIT

render() { # <output name> <kustomization dir>
  echo "kustomize build ${2#"$root"/}" >&2
  kustomize build "$2" > "$work/$1.yaml"
}

# An overlay reads its Secret from a git-ignored forge.env; the example stands
# in for it (a real forge.env is left alone).
for overlay in "$root"/overlays/*/; do
  overlay="${overlay%/}"
  if [ ! -e "$overlay/forge.env" ]; then
    cp "$overlay/forge.env.example" "$overlay/forge.env"
    created+=("$overlay/forge.env")
  fi
  render "overlay-$(basename "$overlay")" "$overlay"
done

for component in "$root"/components/*/; do
  component="${component%/}"
  name=$(basename "$component")
  mkdir "$scratch/$name"
  cat > "$scratch/$name/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
components:
  - ../../components/$name
secretGenerator:
  - name: forge-env
    literals:
      - POSTGRES_PASSWORD=check
      - VALKEY_PASSWORD=check
      - FORGE_S3__ACCESS_KEY=check
      - FORGE_S3__SECRET_KEY=check
      - FORGE_ROOT_KEY=check
EOF
  render "component-$name" "$scratch/$name"
done

kubeconform -strict -summary -kubernetes-version "$k8s_version" \
  -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  "$work"/*.yaml

# Forge believes X-Forwarded-For from every peer in
# FORGE_AUTH__TRUSTED_PROXY_CIDRS (usually the whole pod network), so an
# overlay that sets it must keep the other pods away from Forge: a
# NetworkPolicy named forge with a `from` restriction.
failed=0
for output in "$work"/overlay-*.yaml; do
  grep -q 'FORGE_AUTH__TRUSTED_PROXY_CIDRS' "$output" || continue
  if ! awk '
    /^---$/ { if (policy && forge && from) found = 1; policy = forge = from = 0; next }
    /^kind: NetworkPolicy$/ { policy = 1 }
    /^  name: forge$/ { forge = 1 }
    /^ *(- )?from:$/ { from = 1 }
    END { if (policy && forge && from) found = 1; exit !found }
  ' "$output"; then
    echo "$(basename "$output" .yaml) sets FORGE_AUTH__TRUSTED_PROXY_CIDRS but renders no forge NetworkPolicy restricting who reaches Forge (components/network-policy)" >&2
    failed=1
  fi
done
exit "$failed"
