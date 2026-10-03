import { describe, expect, it } from 'vitest'

import { formatClaimRules, parseClaimRules } from './RealmForm'

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
