import { describe, expect, it } from 'vitest'

import type { RealmFormValues } from './RealmForm'
import { formatClaimRules, parseClaimRules, toRealmConfig } from './RealmForm'

describe('OIDC required-claims editor', () => {
  it('parses one claim per line and skips incomplete lines', () => {
    expect(
      parseClaimRules('tid = tenant-a\n groups = dev, ops \nbroken line\nhd =\n'),
    ).toEqual({ tid: ['tenant-a'], groups: ['dev', 'ops'] })
  })

  it('round-trips the stored map, so editing a realm keeps its gate', () => {
    const rules = { tid: ['tenant-a'], groups: ['dev', 'ops'] }
    expect(parseClaimRules(formatClaimRules(rules))).toEqual(rules)
    expect(formatClaimRules(undefined)).toBe('')
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
    expect(toRealmConfig(values('pipeline_id, runner_id'))).toMatchObject({
      identity_claims: ['pipeline_id', 'runner_id'],
    })
    expect(toRealmConfig(values(' '))).not.toHaveProperty('identity_claims')
  })
})
