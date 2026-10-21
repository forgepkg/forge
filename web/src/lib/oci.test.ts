import { describe, expect, it } from 'vitest'

import {
  formatBytes,
  formatDateTime,
  manifestKind,
  referrerKind,
  shortDigest,
} from './oci'

/**
 * OCI presentation helpers: the manifest kind derived from media / artifact
 * type, the referrer label, Docker-style short digests and binary sizes.
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
