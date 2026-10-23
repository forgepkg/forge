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
