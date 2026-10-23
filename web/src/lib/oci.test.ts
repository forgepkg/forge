import { describe, expect, it } from 'vitest'

import {
  defaultPullTag,
  formatBytes,
  formatDateTime,
  isReferrerTag,
  manifestKind,
  referrerKind,
  shortDigest,
} from './oci'

/**
 * OCI presentation helpers: the manifest kind derived from media / artifact
 * type, the referrer label, the default pull tag, Docker-style short digests
 * and binary sizes.
 */
describe('manifestKind', () => {
  it('classifies indexes and manifest lists as Index', () => {
    for (const media_type of [
      'application/vnd.oci.image.index.v1+json',
      'application/vnd.docker.distribution.manifest.list.v2+json',
    ]) {
      expect(manifestKind({ media_type, artifact_type: null })).toBe('Index')
    }
  })

  it('treats an image config artifact type (or none) as Image', () => {
    const media_type = 'application/vnd.oci.image.manifest.v1+json'
    expect(manifestKind({ media_type, artifact_type: null })).toBe('Image')
    expect(
      manifestKind({
        media_type,
        artifact_type: 'application/vnd.oci.image.config.v1+json',
      }),
    ).toBe('Image')
    expect(
      manifestKind({
        media_type: 'application/vnd.docker.distribution.manifest.v2+json',
        artifact_type: 'application/vnd.docker.container.image.v1+json',
      }),
    ).toBe('Image')
  })

  it('treats any other artifact type as Artifact', () => {
    expect(
      manifestKind({
        media_type: 'application/vnd.oci.image.manifest.v1+json',
        artifact_type: 'application/vnd.dev.cosign.artifact.sig.v1+json',
      }),
    ).toBe('Artifact')
  })
})

describe('referrerKind', () => {
  it('names signatures, attestations and SBOMs', () => {
    expect(referrerKind('application/vnd.dev.cosign.artifact.sig.v1+json')).toBe(
      'Signature',
    )
    expect(referrerKind('application/vnd.cncf.notary.signature')).toBe('Signature')
    expect(referrerKind('application/vnd.in-toto+json')).toBe('Attestation')
    expect(referrerKind('application/spdx+json')).toBe('SBOM')
    expect(referrerKind('application/vnd.cyclonedx+json')).toBe('SBOM')
    expect(referrerKind('application/vnd.example.thing')).toBeNull()
    expect(referrerKind(null)).toBeNull()
  })
})

describe('isReferrerTag', () => {
  it('recognizes cosign tags and the referrers tag schema fallback', () => {
    const hex = 'a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4'
    for (const tag of [`sha256-${hex}.sig`, `sha256-${hex}.att`, `sha256-${hex}.sbom`, `sha256-${hex}`]) {
      expect(isReferrerTag(tag), tag).toBe(true)
    }
    for (const tag of ['latest', 'v1.2.0', 'sha256', 'sha256-build', `${hex}.sig`]) {
      expect(isReferrerTag(tag), tag).toBe(false)
    }
  })
})

describe('defaultPullTag', () => {
  const image = 'application/vnd.oci.image.manifest.v1+json'
  const manifest = (
    digest: string,
    created_at: string,
    extra: { artifact_type?: string; subject_digest?: string } = {},
  ) => ({
    digest,
    media_type: image,
    artifact_type: extra.artifact_type ?? 'application/vnd.oci.image.config.v1+json',
    subject_digest: extra.subject_digest ?? null,
    created_at,
  })
  const manifests = [
    manifest('sha256:old', '2026-09-01T08:00:00Z'),
    manifest('sha256:new', '2026-10-21T10:00:00Z'),
    manifest('sha256:sig', '2026-10-22T09:00:00Z', {
      artifact_type: 'application/vnd.dev.cosign.artifact.sig.v1+json',
      subject_digest: 'sha256:new',
    }),
    manifest('sha256:chart', '2026-10-23T09:00:00Z', {
      artifact_type: 'application/vnd.cncf.helm.config.v1+json',
    }),
  ]
  const tag = (name: string, digest: string) => ({ tag: name, digest })

  it('prefers `latest`', () => {
    expect(
      defaultPullTag(
        [tag('2.0.0', 'sha256:new'), tag('latest', 'sha256:old')],
        manifests,
      )?.tag,
    ).toBe('latest')
  })

  it('otherwise takes the most recently pushed image tag, not the first by name', () => {
    expect(
      defaultPullTag(
        [tag('1.10', 'sha256:old'), tag('1.9', 'sha256:new')],
        manifests,
      )?.tag,
    ).toBe('1.9')
  })

  it('skips signature tags and artifacts, even newer ones', () => {
    const tags = [
      tag('chart-1.0.0', 'sha256:chart'),
      // A tag-based cosign signature (legacy cosign: an image config, no subject).
      tag('sha256-0123abcd.sig', 'sha256:old'),
      tag('signed', 'sha256:sig'),
      tag('v1.2.0', 'sha256:old'),
    ]
    expect(defaultPullTag(tags, manifests)?.tag).toBe('v1.2.0')
    // With no image tag left, an artifact's tag before a referrer tag.
    expect(defaultPullTag(tags.slice(0, 2), manifests)?.tag).toBe('chart-1.0.0')
    expect(defaultPullTag(tags.slice(1, 2), manifests)?.tag).toBe(
      'sha256-0123abcd.sig',
    )
  })

  it('keeps the name order for ties and has nothing for no tags', () => {
    expect(
      defaultPullTag([tag('a', 'sha256:new'), tag('b', 'sha256:new')], manifests)?.tag,
    ).toBe('a')
    expect(defaultPullTag([], manifests)).toBeUndefined()
  })
})

describe('shortDigest', () => {
  it('keeps the first 12 hex characters of a sha256 digest', () => {
    expect(
      shortDigest(
        'sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4',
      ),
    ).toBe('a3ed95caeb02')
  })

  it('keeps the algorithm of a non-sha256 digest', () => {
    expect(shortDigest('sha512:0123456789abcdef0123')).toBe('sha512:0123456789ab')
  })
})

describe('formatBytes', () => {
  it('renders binary units and a dash when unknown', () => {
    expect(formatBytes(null)).toBe('—')
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(2048)).toBe('2.0 KiB')
    expect(formatBytes(2_206_402)).toBe('2.1 MiB')
    expect(formatBytes(3 * 1024 ** 3)).toBe('3.0 GiB')
  })
})

describe('formatDateTime', () => {
  it('renders a dash for a missing or invalid timestamp', () => {
    expect(formatDateTime(null)).toBe('—')
    expect(formatDateTime('not a date')).toBe('—')
    expect(formatDateTime('2026-10-21T10:58:44Z')).not.toBe('—')
  })
})
