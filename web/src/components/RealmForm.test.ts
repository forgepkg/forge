import { describe, expect, it } from 'vitest'

import type { RealmView } from '~/api/realms'
import type { RealmFormValues } from './RealmForm'
import {
  formatClaimRules,
  parseClaimRules,
  parseLines,
  seedRealmFormValues,
  toRealmConfig,
} from './RealmForm'

describe('OIDC required-claims editor', () => {
  it('parses one claim value per line and skips incomplete lines', () => {
    expect(
      parseClaimRules('tid = tenant-a\n groups = dev \ngroups = ops\nbroken line\nhd =\n'),
    ).toEqual({ tid: ['tenant-a'], groups: ['dev', 'ops'] })
  })

  it('keeps commas and = inside a value', () => {
    expect(parseClaimRules('groups = CN=Forge Users,OU=Groups,DC=corp')).toEqual({
      groups: ['CN=Forge Users,OU=Groups,DC=corp'],
    })
  })

  it('round-trips the stored map, so editing a realm keeps its gate', () => {
    const rules = {
      tid: ['tenant-a'],
      groups: ['dev', 'CN=Forge Users,OU=Groups,DC=corp'],
    }
    expect(parseClaimRules(formatClaimRules(rules))).toEqual(rules)
    expect(formatClaimRules(undefined)).toBe('')
  })
})

describe('list fields', () => {
  it('take one entry per line and keep commas', () => {
    expect(parseLines(' CN=Forge Admins,OU=Groups,DC=corp \r\n\nforge-ops\n')).toEqual([
      'CN=Forge Admins,OU=Groups,DC=corp',
      'forge-ops',
    ])
  })

  const dn = 'CN=Forge Admins,OU=Groups,DC=corp'
  const stored = (kind: RealmView['kind'], config: RealmView['config']): RealmView => ({
    id: 1,
    kind,
    name: 'r',
    enabled: true,
    priority: 1,
    config,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  })

  // Saving an untouched form sends what is stored (PATCH replaces the config).
  it.each<[RealmView['kind'], RealmView['config']]>([
    [
      'oidc',
      {
        issuer: 'https://idp.example.com',
        client_id: 'forge',
        auto_provision: true,
        link_existing_by_username: false,
        allow_http_issuer: false,
        scopes: ['openid', 'profile'],
        admin_groups: [dn, 'forge-ops'],
        login_domains: ['example.com', 'corp.example.com'],
        endpoint_hosts: ['oauth2.googleapis.com', 'www.googleapis.com'],
        required_claims: { groups: [dn, 'CN=Forge Users,OU=Groups,DC=corp'] },
      },
    ],
    [
      'credential_forwarding',
      {
        url: 'https://auth.example.com/check',
        auto_provision: true,
        success_status: [200, 204],
        required_groups: [dn, 'developers'],
      },
    ],
    [
      'workload_identity',
      {
        issuer: 'https://ci.example',
        allowed_audiences: ['https://forge.example.com', 'aud,with,commas'],
        allow_http_issuer: false,
        rules: [
          {
            role: 'ci',
            conditions: [{ claim: 'sub', any_of: ['repo:acme/api,ref:main', 'x'] }],
          },
        ],
        allowed_authorized_parties: ['a,b'],
        identity_claims: ['pipeline_id', 'runner_id'],
      },
    ],
  ])('round-trips a %s config with commas in list values', (kind, config) => {
    expect(toRealmConfig(seedRealmFormValues(stored(kind, config)))).toEqual(config)
  })
})

describe('workload identity config', () => {
  const values = (identity_claims: string) =>
    ({
      kind: 'workload_identity',
      issuer: 'https://ci.example',
      allowed_audiences: 'forge',
      allow_http_issuer: false,
      wifRules: [{ role: 'ci', conditions: [{ claim: 'pipeline_id', anyOf: '42' }] }],
      clock_skew_seconds: '',
      max_token_age_seconds: '',
      allowed_authorized_parties: '',
      positive_cache_seconds: '',
      identity_claims,
    }) as unknown as RealmFormValues

  it('sends declared identity claims and omits an empty list', () => {
    expect(toRealmConfig(values('pipeline_id\nrunner_id'))).toMatchObject({
      identity_claims: ['pipeline_id', 'runner_id'],
    })
    expect(toRealmConfig(values(' '))).not.toHaveProperty('identity_claims')
  })
})
