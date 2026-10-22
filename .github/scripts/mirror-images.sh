#!/usr/bin/env bash
# Mirror the images of the in-cluster dependencies (PostgreSQL, Valkey,
# versitygw) from Docker Hub to ghcr.io (used by mirror-images.yml), so the
# Helm chart and the Kubernetes manifests pull every image from ghcr.io.
# deploy/ names them as ghcr.io/<owner>/<repo>/<name>:<tag>@sha256:…; each
# copy is byte for byte, so it keeps its Docker Hub digest and can be checked
# against it.
#
# Per image:
#   - every digest deploy/ pins (the kustomize components' `image:` and the
#     Helm sub-charts' image maps) is copied, and its tag set to it when
#     ghcr.io has no such tag yet: the chart and the manifests always pull;
#   - unless --pinned-only, the tags in the format of the pinned tag
#     (`9.1-alpine`: <n>.<n>-alpine) that are not older than it are brought
#     in line with Docker Hub, so Dependabot, which watches the ghcr.io names,
#     proposes the tag and digest updates it would propose on Docker Hub.
#     Older digests stay on ghcr.io (untagged), so earlier releases still
#     pull.
#
# Docker Hub's registry rate-limits anonymous requests, and CI runners share
# addresses, so it is never asked: the tags and their digests come from
# Docker Hub's web API, the content from mirror.gcr.io by digest.
#
# Clusters pull them anonymously, so a mirror that cannot be pulled without
# a login is a warning, and with --require-public (the release) an error.
#
# Usage: mirror-images.sh [--pinned-only] [--require-public] [<push prefix>]
#   <push prefix> defaults to the one deploy/ names (ghcr.io/<owner>/<repo>);
#   another one, such as a local registry, is a dry run.
# Needs crane, curl and jq on PATH, and a login to the push registry.
set -euo pipefail

cd "$(dirname "$0")/../.."

pinned_only=false
require_public=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pinned-only) pinned_only=true ;;
    --require-public) require_public=true ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
  shift
done

# <name under the prefix> <repository on Docker Hub>
upstream() {
  case "$1" in
    postgres) echo library/postgres ;;
    valkey) echo valkey/valkey ;;
    versitygw) echo versity/versitygw ;;
    *) return 1 ;;
  esac
}

# Every image reference deploy/ makes on ghcr.io, one per line.
references() {
  grep -rhoE "^ *image: *[\"']?ghcr\.io/[^\"' ]+" deploy/kubernetes | sed -E "s/^ *image: *[\"']?//"
  for values in deploy/helm/forge/charts/*/values.yaml; do
    awk '
      /^image:/ { image = 1; next }
      /^[^ #]/ { image = 0 }
      image && /^  (registry|repository|tag):/ {
        value = $2
        gsub(/^["\047]|["\047]$/, "", value)
        field[substr($1, 1, length($1) - 1)] = value
      }
      END {
        if (field["registry"] == "ghcr.io")
          print field["registry"] "/" field["repository"] ":" field["tag"]
      }
    ' "$values"
  done
}

# The pinned references to mirrored images, as "<prefix> <name> <tag> <digest>".
pins=$(references | sort -u | while IFS= read -r ref; do
  repository=${ref%%:*}
  name=${repository##*/}
  upstream "$name" > /dev/null || continue
  rest=${ref#*:}
  case "$rest" in
    *@sha256:*) ;;
    *) echo "::error::$ref is not pinned by digest" >&2; exit 1 ;;
  esac
  echo "${repository%/*} $name ${rest%@*} ${rest#*@}"
done)
[ -n "$pins" ] || { echo "::error::deploy/ names no mirrored image on ghcr.io" >&2; exit 1; }

prefixes=$(cut -d' ' -f1 <<< "$pins" | sort -u)
if [ "$(wc -l <<< "$prefixes")" -ne 1 ]; then
  echo "::error::deploy/ names mirrored images under several prefixes: $(tr '\n' ' ' <<< "$prefixes")" >&2
  exit 1
fi
push="${1:-$prefixes}"

# copy <Docker Hub repository> <digest> <destination>: from mirror.gcr.io,
# then checked to have arrived under that digest.
copy() {
  crane copy "mirror.gcr.io/$1@$2" "$3"
  local got
  got=$(crane digest "$3")
  if [ "$got" != "$2" ]; then
    echo "::error::$3 is $got after copying $1@$2" >&2
    exit 1
  fi
}

# The pinned digests, and their tags where ghcr.io has none yet.
while read -r _ name tag digest; do
  from=$(upstream "$name")
  to="$push/$name"
  if crane digest "$to@$digest" > /dev/null 2>&1; then
    echo "$to@$digest: present"
  else
    echo "$to@$digest: copying $from@$digest"
    copy "$from" "$digest" "$to@$digest"
  fi
  if ! crane digest "$to:$tag" > /dev/null 2>&1; then
    echo "$to:$tag: tagging $digest"
    crane tag "$to@$digest" "$tag"
  fi
done <<< "$pins"

if ! $pinned_only; then
  # Per image, the oldest pinned tag sets the format and the lower bound.
  while read -r name; do
    from=$(upstream "$name")
    to="$push/$name"
    pinned=$(awk -v n="$name" '$2 == n { print $3 }' <<< "$pins" | sort -V | head -n1)
    format="^$(sed -E 's/\./\\./g; s/[0-9]+/[0-9]+/g' <<< "$pinned")\$"

    # "<tag> <digest>": the pinned tag, and the 300 most recently updated
    # tags (every maintained tag is rebuilt with each base image update).
    tags=$(
      curl -sSf "https://hub.docker.com/v2/repositories/$from/tags/$pinned" | jq -r '"\(.name) \(.digest)"'
      url="https://hub.docker.com/v2/repositories/$from/tags?page_size=100&ordering=last_updated"
      for _ in 1 2 3; do
        page=$(curl -sSf "$url")
        jq -r '.results[] | select(.digest) | "\(.name) \(.digest)"' <<< "$page"
        url=$(jq -r '.next // empty' <<< "$page")
        [ -n "$url" ] || break
      done
    )
    while read -r tag digest; do
      [[ "$tag" =~ $format ]] || continue
      [ "$(printf '%s\n%s\n' "$pinned" "$tag" | sort -V | head -n1)" = "$pinned" ] || continue
      current=$(crane digest "$to:$tag" 2> /dev/null || true)
      if [ "$current" = "$digest" ]; then
        echo "$to:$tag: up to date"
      else
        echo "$to:$tag: ${current:-new}, copying $from@$digest"
        copy "$from" "$digest" "$to:$tag"
      fi
    done < <(sort -u <<< "$tags")
  done < <(cut -d' ' -f2 <<< "$pins" | sort -u)
fi

# Clusters pull anonymously: a private package needs a pull secret in every
# namespace. GitHub creates a new package private; make it public once.
if [[ "$push" == ghcr.io/* ]]; then
  private=false
  while read -r _ name _ digest; do
    path="${push#ghcr.io/}/$name"
    token=$(curl -sSf "https://ghcr.io/token?service=ghcr.io&scope=repository:$path:pull" | jq -r '.token // empty') || token=""
    if [ -z "$token" ] || ! curl -sSf -o /dev/null -I -H "Authorization: Bearer $token" \
      -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
      "https://ghcr.io/v2/$path/manifests/$digest"; then
      level=warning
      if $require_public; then level=error; fi
      echo "::$level::ghcr.io/$path cannot be pulled anonymously: make the package public (Package settings, Change visibility)"
      private=true
    fi
  done <<< "$pins"
  if $private && $require_public; then exit 1; fi
fi
