/**
 * Presentation helpers for Docker / OCI data on the browse screens: short
 * digests, what kind of manifest a row is, and human-readable sizes. Pure
 * functions, so the tables stay declarative and the rules are unit-tested.
 */

/** Media types of an image index / manifest list. */
const INDEX_MEDIA_TYPES = new Set([
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
])

/**
 * Config media types of a runnable image: an `artifact_type` of one of these
 * is a plain image, not an artifact.
 */
const IMAGE_CONFIG_TYPES = new Set([
  'application/vnd.oci.image.config.v1+json',
  'application/vnd.docker.container.image.v1+json',
])

/** What a manifest row is: a runnable image, an index, or another artifact. */
export type ManifestKind = 'Image' | 'Index' | 'Artifact'

/** Classify a manifest by its media type and artifact type. */
export function manifestKind(manifest: {
  media_type: string
  artifact_type: string | null
}): ManifestKind {
  if (INDEX_MEDIA_TYPES.has(manifest.media_type)) return 'Index'
  if (manifest.artifact_type && !IMAGE_CONFIG_TYPES.has(manifest.artifact_type)) {
    return 'Artifact'
  }
  return 'Image'
}

/**
 * A readable name for a referrer's artifact type (the manifest has a
 * `subject`): signatures (cosign, Notation, Sigstore bundles), attestations
 * (in-toto) and SBOMs (SPDX, CycloneDX). `null` for anything else.
 */
export function referrerKind(artifactType: string | null): string | null {
  if (!artifactType) return null
  const t = artifactType.toLowerCase()
  if (t.includes('spdx') || t.includes('cyclonedx') || t.includes('sbom')) {
    return 'SBOM'
  }
  if (t.includes('in-toto') || t.includes('attestation') || t.includes('provenance')) {
    return 'Attestation'
  }
  if (t.includes('signature') || t.includes('.sig') || t.includes('sigstore')) {
    return 'Signature'
  }
  return null
}

/**
 * Tags that name a referrer rather than an image: cosign's tag-based
 * signatures, attestations and SBOMs (`sha256-<hex>.sig`, `.att`, `.sbom`)
 * and the OCI referrers tag schema's fallback index (`sha256-<hex>`).
 */
const REFERRER_TAG = /^sha(256|512)-[0-9a-f]+(\.[a-z]+)?$/

/** Whether a tag names a referrer (a signature, SBOM, …), not an image. */
export function isReferrerTag(tag: string): boolean {
  return REFERRER_TAG.test(tag)
}

/**
 * The tag the pull commands start with: `latest`, else the most recently
 * pushed tag, preferring tags of images (or indexes) over tags of other
 * artifacts, and those over referrer tags. Tags arrive sorted by name, so
 * the first one is often a signature (`sha256-….sig` sorts before `v1.2.0`)
 * or the oldest version.
 */
export function defaultPullTag<T extends { tag: string; digest: string }>(
  tags: T[],
  manifests: {
    digest: string
    media_type: string
    artifact_type: string | null
    subject_digest: string | null
    created_at: string
  }[],
): T | undefined {
  const byDigest = new Map(manifests.map((m) => [m.digest, m]))
  /** 0: an image or index, 1: another artifact, 2: a referrer tag. */
  const tier = (t: T) => {
    if (isReferrerTag(t.tag)) return 2
    const manifest = byDigest.get(t.digest)
    return manifest &&
      (manifest.subject_digest || manifestKind(manifest) === 'Artifact')
      ? 1
      : 0
  }
  const pushed = (t: T) =>
    Date.parse(byDigest.get(t.digest)?.created_at ?? '') || 0
  /** Negative when `a` is the better default; ties keep the name order. */
  const compare = (a: T, b: T) =>
    tier(a) - tier(b) ||
    Number(b.tag === 'latest') - Number(a.tag === 'latest') ||
    pushed(b) - pushed(a)
  return tags.reduce<T | undefined>(
    (best, t) => (best === undefined || compare(t, best) < 0 ? t : best),
    undefined,
  )
}

/**
 * The first 12 hex characters of a digest — Docker's short image id. A
 * non-`sha256` algorithm keeps its prefix (`sha512:0123456789ab`).
 */
export function shortDigest(digest: string): string {
  const colon = digest.indexOf(':')
  if (colon < 0) return digest.slice(0, 12)
  const algorithm = digest.slice(0, colon)
  const hex = digest.slice(colon + 1, colon + 13)
  return algorithm === 'sha256' ? hex : `${algorithm}:${hex}`
}

/** Binary-unit byte size (`2.1 MiB`); an em dash when unknown. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || !Number.isFinite(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(1)} ${units[unit]}`
}

/** Locale date + time of an ISO timestamp; an em dash when absent / invalid. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? '—'
    : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/** The config media type of a Helm chart pushed as an artifact (`helm push`). */
export const HELM_CHART_CONFIG = 'application/vnd.cncf.helm.config.v1+json'

/** Whether a manifest is a Helm chart (and not a referrer of one). */
export function isChart(manifest: {
  artifact_type: string | null
  subject_digest: string | null
}): boolean {
  return manifest.artifact_type === HELM_CHART_CONFIG && !manifest.subject_digest
}

/**
 * Whether an image holds Helm charts: its top-level manifests (neither an
 * index's children nor referrers such as signatures) are all charts, as
 * `helm push` leaves `oci://<registry>/<repo>/<name>`.
 */
export function isChartImage(
  manifests: {
    digest: string
    artifact_type: string | null
    subject_digest: string | null
    children: string[]
  }[],
): boolean {
  const children = new Set(manifests.flatMap((m) => m.children))
  const top = manifests.filter((m) => !m.subject_digest && !children.has(m.digest))
  return top.length > 0 && top.every(isChart)
}

/**
 * The chart version a tag names: `helm push` writes a version's build
 * metadata (`+`, which a tag cannot hold) as `_`, and Helm reads it back.
 */
export function chartVersion(tag: string): string {
  return tag.replaceAll('_', '+')
}

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/

/** A version's numbers and prerelease identifiers, or `null` if not SemVer. */
function semver(version: string): { core: number[]; pre: string[] } | null {
  const m = SEMVER.exec(version)
  if (!m) return null
  return { core: [m[1], m[2], m[3]].map(Number), pre: m[4] ? m[4].split('.') : [] }
}

/** SemVer 2 precedence of two prerelease identifier lists (empty: a release). */
function comparePre(a: string[], b: string[]): number {
  if (a.length === 0 || b.length === 0) return b.length - a.length
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i]
    const y = b[i]
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) {
      const d = Number(x) - Number(y)
      if (d !== 0) return d
    } else if (xn !== yn) {
      return xn ? -1 : 1
    } else if (x !== y) {
      return x < y ? -1 : 1
    }
  }
  return a.length - b.length
}

/**
 * The chart versions of an image: the tags of its charts, newest first.
 * Tags that are SemVer versions (as `helm push` tags a chart) come by
 * precedence, the others after them by name.
 */
export function chartVersions<T extends { tag: string; digest: string }>(
  tags: T[],
  manifests: { digest: string; artifact_type: string | null; subject_digest: string | null }[],
): T[] {
  const charts = new Set(manifests.filter(isChart).map((m) => m.digest))
  const parsed = tags
    .filter((t) => charts.has(t.digest))
    .map((t) => ({ t, v: semver(chartVersion(t.tag)) }))
  parsed.sort((a, b) => {
    if (a.v && b.v) {
      for (let i = 0; i < 3; i++) {
        const d = b.v.core[i] - a.v.core[i]
        if (d !== 0) return d
      }
      return comparePre(b.v.pre, a.v.pre)
    }
    if (a.v || b.v) return a.v ? -1 : 1
    return a.t.tag < b.t.tag ? -1 : a.t.tag > b.t.tag ? 1 : 0
  })
  return parsed.map((p) => p.t)
}

/**
 * The version the install commands start with: the newest release, as
 * `helm install` without `--version` picks it, else the newest prerelease.
 * `versions` are {@link chartVersions}, newest first.
 */
export function defaultChartVersion<T extends { tag: string }>(versions: T[]): T | undefined {
  return versions.find((t) => semver(chartVersion(t.tag))?.pre.length === 0) ?? versions[0]
}

/** `url` as a link target when it is an http(s) URL; `null` otherwise. */
export function httpUrl(url: string | undefined): string | null {
  if (!url) return null
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : null
  } catch {
    return null
  }
}
