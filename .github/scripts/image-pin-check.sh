#!/usr/bin/env bash
# Fail on a container image reference that is not pinned by digest (used by
# ci.yml): a tag can be moved to other content, a digest cannot. Checked:
#   - Dockerfiles: the `# syntax=` frontend, every FROM and --from image;
#   - deploy/: every `image:` of the Kubernetes manifests, kustomize
#     `images:` overrides, and the Helm values' image maps (a
#     `tag: <tag>@sha256:…`, the form Dependabot updates, or a `digest:`);
#   - the workflows (.github/workflows): service and container images,
#     `docker://` actions, BuildKit (setup-buildx-action must pass
#     `driver-opts: image=…@sha256:…`; its default is a floating tag) and
#     the SBOM generator (`sbom: true` runs a floating one; name it with
#     `generator=…@sha256:…`).
#
# Exempt on purpose:
#   - Forge's own image, ghcr.io/schmitch/forge, which the release pins
#     itself: the published chart pulls it by the digest the release workflow
#     signed (Chart.yaml annotation forge.envisia.de/image-digest), and the
#     Kubernetes base names the release's tag, which the release workflow
#     attaches only to that signed digest and never moves on a re-run
#     (components/image-latest follows :latest on purpose).
#   - `docker pull` in the e2e jobs: it only warms the cache for the test
#     harnesses, which name their images by tag in their own code
#     (crates/e2e, web/e2e).
#
# Usage: image-pin-check.sh
# Needs bash and a POSIX awk (mawk is enough).
set -euo pipefail

cd "$(dirname "$0")/../.."

# Shared by both awk programs.
common='
function pinned(ref,   at) {
  at = index(ref, "@sha256:")
  return at > 0 && length(ref) - at - 7 == 64 && substr(ref, at + 8) ~ /^[0-9a-f]+$/
}
function own(ref) {
  return ref ~ /^ghcr\.io\/schmitch\/forge([:@]|$)/
}
function check(ref, what, file, line) {
  if (ref == "" || own(ref) || pinned(ref)) return
  printf "%s:%d: %s %s is not pinned by digest\n", file, line, what, ref
  bad = 1
}
function unquote(v) {
  sub(/[ \t]+#.*$/, "", v)
  sub(/[ \t]+$/, "", v)
  gsub(/^["\047]|["\047]$/, "", v)
  return v
}
'

dockerfiles=()
while IFS= read -r file; do dockerfiles+=("$file"); done < <(
  find . \( -path ./.git -o -path ./target -o -path ./web/node_modules \) -prune -o \
    -type f \( -name Dockerfile -o -name '*.Dockerfile' -o -name Containerfile \) -print \
    | sed 's|^\./||' | sort
)
yamls=()
while IFS= read -r file; do yamls+=("$file"); done < <(
  find deploy .github/workflows -type f \( -name '*.yaml' -o -name '*.yml' \) | sort
)

failed=0

# Dockerfiles: the syntax directive, FROM (a stage name or scratch is no
# image), and COPY --from= / RUN --mount=…,from= (a stage name or an index
# is none either).
awk "$common"'
FNR == 1 { split("", stages) }
/^#[ \t]*[sS][yY][nN][tT][aA][xX][ \t]*=/ {
  ref = $0
  sub(/^#[ \t]*[sS][yY][nN][tT][aA][xX][ \t]*=[ \t]*/, "", ref)
  sub(/[ \t].*$/, "", ref)
  check(ref, "Dockerfile frontend", FILENAME, FNR)
  next
}
/^[ \t]*#/ { next }
toupper($1) == "FROM" {
  i = 2
  while (i <= NF && $i ~ /^--/) i++
  ref = $i
  if (!(tolower(ref) in stages) && tolower(ref) != "scratch") check(ref, "base image", FILENAME, FNR)
  if (toupper($(i + 1)) == "AS") stages[tolower($(i + 2))] = 1
  next
}
{
  for (i = 1; i <= NF; i++) {
    if ($i !~ /^--(from|mount)=/) continue
    n = split($i, opts, ",")
    for (j = 1; j <= n; j++) {
      opt = opts[j]
      sub(/^--(mount=)?/, "", opt)
      if (opt !~ /^from=/) continue
      ref = substr(opt, 6)
      if (!(tolower(ref) in stages) && ref !~ /^[0-9]+$/) check(ref, "--from image", FILENAME, FNR)
    }
  }
}
END { exit bad }
' "${dockerfiles[@]}" || failed=1

# YAML: `image:` values and maps, kustomize `images:` entries; in the
# workflows also `container:` values, docker:// actions, BuildKit and SBOM
# generator options, setup-buildx-action without a pinned BuildKit and
# `sbom: true`.
awk "$common"'
function finish_map(   ref) {
  if (map_line && map_repo != "") {
    ref = (map_registry != "" ? map_registry "/" : "") map_repo
    if (map_tag != "") ref = ref ":" map_tag
    if (map_digest != "") ref = ref "@" map_digest
    check(ref, "image", file, map_line)
  }
  map_line = 0
}
function finish_entry(   name) {
  name = entry_new != "" ? entry_new : entry_name
  if (entry_line && entry_digest == "" && (entry_tag != "" || entry_new != ""))
    check(name ":" entry_tag, "kustomize image override", file, entry_line)
  entry_line = 0
  entry_name = entry_new = entry_tag = entry_digest = ""
}
function finish_buildx() {
  if (buildx_line && !buildx_ok) {
    printf "%s:%d: docker/setup-buildx-action runs a floating BuildKit; pass driver-opts: image=moby/buildkit:<version>@sha256:<digest>\n", file, buildx_line
    bad = 1
  }
  buildx_line = 0
}
FNR == 1 {
  finish_map(); finish_entry(); finish_buildx()
  images_col = -1
  file = FILENAME
  workflow = (file ~ /\.github\/workflows\//)
}
/^[ \t]*(#|$)/ { next }
{
  match($0, /^ */); lead = RLENGTH
  dash = (substr($0, lead + 1, 2) == "- ")
  match($0, /^ *(- +)*/); col = RLENGTH
  rest = substr($0, col + 1)
  key = rest; sub(/:.*$/, "", key)
  value = rest
  if (!sub(/^[^:]*:[ \t]*/, "", value)) value = ""
  value = unquote(value)

  # Blocks end at a line indented no deeper than their key.
  if (map_line && col <= map_col) finish_map()
  if (images_col >= 0 && (col <= images_col || (dash && lead <= images_col))) {
    finish_entry(); images_col = -1
  }
  if (buildx_line && (col < buildx_col || (dash && lead < buildx_col))) finish_buildx()

  if (map_line) {
    if (map_child < 0) map_child = col
    if (col == map_child) {
      if (key == "registry") map_registry = value
      else if (key == "repository") map_repo = value
      else if (key == "tag") map_tag = value
      else if (key == "digest") map_digest = value
    }
  }
  if (images_col >= 0) {
    if (dash) { finish_entry(); entry_line = FNR }
    if (key == "name") entry_name = value
    else if (key == "newName") entry_new = value
    else if (key == "newTag") entry_tag = value
    else if (key == "digest") entry_digest = value
  }

  # A map is a Helm values image (registry, repository, tag, digest); in a
  # GitHub workflow `image:` is only ever a scalar (an empty one is a job
  # named image).
  if (key == "image") {
    if (value == "" && !workflow) {
      map_line = FNR; map_col = col; map_child = -1
      map_registry = map_repo = map_tag = map_digest = ""
    } else if (value != "" && value !~ /\{\{/) {
      check(value, "image", file, FNR)
    }
  }
  if (key == "images" && value == "") images_col = col
  if (workflow && key == "container" && value != "" && value !~ /\$\{\{/)
    check(value, "container image", file, FNR)

  if (workflow) {
    if (key == "uses" && value ~ /^docker\/setup-buildx-action@/) {
      finish_buildx()
      buildx_line = FNR; buildx_col = col; buildx_ok = 0
    }
    if (key == "uses" && value ~ /^docker:\/\//) check(substr(value, 10), "docker:// action", file, FNR)
    if (key == "sbom" && value == "true") {
      printf "%s:%d: sbom: true runs a floating SBOM generator; use attests: type=sbom,generator=<image>@sha256:<digest>\n", file, FNR
      bad = 1
    }
    line = $0
    while (match(line, /(^|[ ,"\047])(image|generator)=[^ ,"\047]+/)) {
      token = substr(line, RSTART, RLENGTH)
      line = substr(line, RSTART + RLENGTH)
      sub(/^[ ,"\047]/, "", token)
      what = (token ~ /^image=/) ? "BuildKit image" : "SBOM generator"
      ref = token
      sub(/^[a-z]+=/, "", ref)
      if (buildx_line && what == "BuildKit image" && pinned(ref)) buildx_ok = 1
      check(ref, what, file, FNR)
    }
  }
}
END { finish_map(); finish_entry(); finish_buildx(); exit bad }
' "${yamls[@]}" || failed=1

if [ "$failed" = 0 ]; then
  echo "image references: all pinned by digest (${#dockerfiles[@]} Dockerfiles, ${#yamls[@]} YAML files)" >&2
fi
exit "$failed"
