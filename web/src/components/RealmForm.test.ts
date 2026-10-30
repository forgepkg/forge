import { describe, expect, it } from 'vitest'

import type { RealmView } from '~/api/realms'
import type { RealmFormValues } from './RealmForm'
import {
  federatedSubject,
  formatClaimRules,
  formatWifRulesJson,
  parseClaimRules,
  parseLines,
  parseWifRulesJson,
  randomSecret,
  secretError,
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
      'oidc',
      {
        issuer: 'https://login.microsoftonline.com/tenant/v2.0',
        client_id: 'app-id',
        auto_provision: true,
        link_existing_by_username: false,
        allow_http_issuer: false,
        client_authentication: 'federated_credential',
        assertion_audience: 'api://AzureADTokenExchangeUSGov',
      },
    ],
    [
      'credential_forwarding',
      {
        url: 'https://auth.example.com/check',
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
        api_key_ttl_seconds: 900,
        identity_claims: ['pipeline_id', 'runner_id'],
      },
    ],
  ])('round-trips a %s config with commas in list values', (kind, config) => {
    expect(toRealmConfig(seedRealmFormValues(stored(kind, config)))).toEqual(config)
  })
})

describe('trusted-header config', () => {
  const stored: RealmView = {
    id: 1,
    kind: 'trusted_header',
    name: 'sso',
    enabled: true,
    priority: 1,
    config: {
      username_header: 'x-forwarded-user',
      secret_header: 'x-forge-proxy-secret',
      secret_set: true,
      auto_provision: true,
    },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }

  it('keeps the stored secret when it is left blank', () => {
    expect(toRealmConfig(seedRealmFormValues(stored))).toEqual({
      username_header: 'x-forwarded-user',
      secret_header: 'x-forge-proxy-secret',
      auto_provision: true,
    })
  })

  it('sends a typed secret, and creates no accounts by default', () => {
    const values = {
      ...seedRealmFormValues(),
      kind: 'trusted_header' as const,
      username_header: ' X-Forwarded-User ',
      secret_header: 'X-Forge-Proxy-Secret',
      secret: 'a'.repeat(32),
    }
    expect(toRealmConfig(values)).toEqual({
      username_header: 'X-Forwarded-User',
      secret_header: 'X-Forge-Proxy-Secret',
      auto_provision: false,
      secret: 'a'.repeat(32),
    })
  })

  it('generates secrets the server accepts', () => {
    const one = randomSecret()
    expect(one).toMatch(/^[0-9a-f]{64}$/)
    expect(secretError(one)).toBeNull()
    expect(randomSecret()).not.toBe(one)
    expect(secretError('short')).not.toBeNull()
    expect(secretError('0123456789abcdef 0123456789abcdef')).not.toBeNull()
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
      api_key_ttl_seconds: '',
      identity_claims,
    }) as unknown as RealmFormValues

  it('sends declared identity claims and omits an empty list', () => {
    expect(toRealmConfig(values('pipeline_id\nrunner_id'))).toMatchObject({
      identity_claims: ['pipeline_id', 'runner_id'],
    })
    expect(toRealmConfig(values(' '))).not.toHaveProperty('identity_claims')
  })

  it('omits a blank exchanged-key lifetime so the server default applies', () => {
    expect(toRealmConfig(values(''))).not.toHaveProperty('api_key_ttl_seconds')
  })

  it('sends issuer_wide only for a rule that takes every project', () => {
    const config = toRealmConfig({
      ...values(''),
      wifRules: [
        { role: 'ci', issuerWide: false, conditions: [{ claim: 'pipeline_id', anyOf: '42' }] },
        { role: 'ci-read', issuerWide: true, conditions: [] },
      ],
    })
    expect(config).toMatchObject({
      rules: [
        { role: 'ci', conditions: [{ claim: 'pipeline_id', any_of: ['42'] }] },
        { role: 'ci-read', issuer_wide: true, conditions: [] },
      ],
    })
    expect((config as { rules: object[] }).rules[0]).not.toHaveProperty('issuer_wide')
  })

  it('reads issuer_wide back from a stored realm', () => {
    const seeded = seedRealmFormValues({
      kind: 'workload_identity',
      config: {
        issuer: 'https://gitlab.example.com',
        allowed_audiences: ['forge'],
        rules: [
          { role: 'ci', conditions: [{ claim: 'job_project_id', any_of: ['1001'] }] },
          { role: 'ci-read', issuer_wide: true, conditions: [] },
        ],
      },
    } as unknown as RealmView)
    expect(seeded.wifRules.map((rule) => rule.issuerWide)).toEqual([false, true])
  })
})

describe('workload identity rules as JSON', () => {
  const rules: RealmFormValues['wifRules'] = [
    {
      role: 'gitlab-ci-read',
      issuerWide: false,
      conditions: [
        { claim: 'job_project_id', anyOf: '1001\n1002' },
        { claim: 'sub', anyOf: 'project_path:acme/api,ref:"main"' },
      ],
    },
    { role: 'readers', issuerWide: true, conditions: [] },
  ]

  it('exports the rules as the admin API takes them, laid out like the guides', () => {
    expect(formatWifRulesJson(rules.slice(0, 1))).toBe(
      [
        '[',
        '  {',
        '    "role": "gitlab-ci-read",',
        '    "conditions": [',
        '      { "claim": "job_project_id", "any_of": ["1001", "1002"] },',
        '      { "claim": "sub", "any_of": ["project_path:acme/api,ref:\\"main\\""] }',
        '    ]',
        '  }',
        ']',
      ].join('\n'),
    )
    expect(JSON.parse(formatWifRulesJson(rules))).toEqual([
      {
        role: 'gitlab-ci-read',
        conditions: [
          { claim: 'job_project_id', any_of: ['1001', '1002'] },
          { claim: 'sub', any_of: ['project_path:acme/api,ref:"main"'] },
        ],
      },
      { role: 'readers', issuer_wide: true, conditions: [] },
    ])
    expect(formatWifRulesJson([])).toBe('[]')
  })

  it('imports what it exports', () => {
    expect(parseWifRulesJson(formatWifRulesJson(rules))).toEqual({ rules })
  })

  it("takes a realm's config or a whole realm, and keeps only the rules", () => {
    const stored = [{ role: 'ci', conditions: [{ claim: 'job_project_id', any_of: ['1001'] }] }]
    const expected = {
      rules: [{ role: 'ci', issuerWide: false, conditions: [{ claim: 'job_project_id', anyOf: '1001' }] }],
    }
    const config = {
      issuer: 'https://gitlab.example.com',
      allowed_audiences: ['https://forge.example.com'],
      rules: stored,
    }
    expect(parseWifRulesJson(JSON.stringify(config))).toEqual(expected)
    expect(
      parseWifRulesJson(JSON.stringify({ kind: 'workload_identity', name: 'gitlab', config })),
    ).toEqual(expected)
    expect(parseWifRulesJson(JSON.stringify(stored[0]))).toEqual(expected)
  })

  it('takes a condition without any_of, as the server does', () => {
    expect(
      parseWifRulesJson('[{ "role": "ci", "conditions": [{ "claim": "sub" }] }]'),
    ).toEqual({
      rules: [{ role: 'ci', issuerWide: false, conditions: [{ claim: 'sub', anyOf: '' }] }],
    })
  })

  it('reports malformed JSON with where it is', () => {
    const result = parseWifRulesJson('[\n  { "role": "ci", }\n]')
    expect(result).toEqual({ error: expect.stringMatching(/^This is not valid JSON: /) })
    expect(result).toEqual({ error: expect.stringMatching(/line 2 column \d+/) })
  })

  it.each([
    ['"rules"', "Paste the rules (a JSON array), a realm's config or a whole realm, or one rule."],
    ['{ "issuer": "https://gitlab.example.com" }', "Paste the rules (a JSON array), a realm's config or a whole realm, or one rule."],
    ['{ "rules": {} }', 'rules must be an array of rules.'],
    ['{ "config": { "issuer": "https://idp.example.com" } }', 'config.rules is missing: the realm has no rules.'],
    ['[1]', 'rules[0] must be an object, a rule.'],
    ['[{ "conditions": [] }]', 'rules[0].role is missing.'],
    ['[{ "role": 4 }]', 'rules[0].role must be a string, the name of a role.'],
    ['[{ "role": "ci", "issuer_wide": "yes" }]', 'rules[0].issuer_wide must be true or false.'],
    ['[{ "role": "ci", "conditions": null }]', 'rules[0].conditions must be an array of conditions.'],
    [
      '[{ "role": "ci", "conditions": [] }, { "role": "ci", "conditons": [] }]',
      'rules[1].conditons is not a key Forge knows: a rule takes role, issuer_wide and conditions.',
    ],
    ['[{ "role": "ci", "conditions": [{ "any_of": ["1"] }] }]', 'rules[0].conditions[0].claim is missing.'],
    [
      '[{ "role": "ci", "conditions": [{ "claim": "sub", "values": ["1"] }] }]',
      'rules[0].conditions[0].values is not a key Forge knows: a condition takes claim and any_of.',
    ],
    [
      '{ "config": { "rules": [{ "role": "ci", "conditions": [{ "claim": "sub", "any_of": "1" }] }] } }',
      'config.rules[0].conditions[0].any_of must be an array of strings.',
    ],
    [
      '[{ "role": "ci", "conditions": [{ "claim": "sub", "any_of": [1001] }] }]',
      'rules[0].conditions[0].any_of must be an array of strings.',
    ],
    [
      '[{ "role": "ci", "conditions": [{ "claim": "sub", "any_of": ["a", "b\\nc"] }] }]',
      'rules[0].conditions[0].any_of[1] holds a line break; a value is one line.',
    ],
    ['{ "role": "ci", "conditions": [{ "claim": 1 }] }', 'conditions[0].claim must be a string, the name of a claim.'],
  ])('refuses %s', (raw, error) => {
    expect(parseWifRulesJson(raw)).toEqual({ error })
  })
})

describe('OIDC federated credential', () => {
  const values = (overrides: Partial<RealmFormValues>): RealmFormValues => ({
    ...seedRealmFormValues(),
    issuer: 'https://login.microsoftonline.com/tenant/v2.0/',
    client_id: ' app-id ',
    ...overrides,
  })

  it('sends no secret and only a non-default audience', () => {
    const config = toRealmConfig(
      values({
        client_authentication: 'federated_credential',
        client_secret: 'typed before switching',
        assertion_audience: ' ',
      }),
    )
    expect(config).toMatchObject({ client_authentication: 'federated_credential' })
    expect(config).not.toHaveProperty('client_secret')
    expect(config).not.toHaveProperty('assertion_audience')
  })

  it('leaves the default client secret authentication implicit', () => {
    const config = toRealmConfig(values({ client_secret: 's3cret' }))
    expect(config).toMatchObject({ client_secret: 's3cret' })
    expect(config).not.toHaveProperty('client_authentication')
  })

  it('derives the subject as the server does', () => {
    expect(federatedSubject(' https://login.microsoftonline.com/t/v2.0/ ', ' app ')).toBe(
      'app@https://login.microsoftonline.com/t/v2.0',
    )
  })
})

describe('passwords from clients', () => {
  const stored = (kind: RealmView['kind'], config: RealmView['config']): RealmView => ({
    id: 1,
    kind,
    name: kind,
    enabled: true,
    priority: 1,
    config,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  })

  it('the local realm sends its flag, off until set', () => {
    expect(toRealmConfig(seedRealmFormValues(stored('local', {})))).toEqual({
      accept_client_passwords: false,
    })
    for (const accept of [true, false]) {
      const config = { accept_client_passwords: accept }
      expect(toRealmConfig(seedRealmFormValues(stored('local', config)))).toEqual(config)
    }
  })

  it('a forwarding realm sends it only when off, its default being on', () => {
    const base = { url: 'https://nexus.example.com/status' }
    expect(seedRealmFormValues(stored('credential_forwarding', base)).accept_client_passwords).toBe(
      true,
    )
    const closed = { ...base, accept_client_passwords: false }
    expect(toRealmConfig(seedRealmFormValues(stored('credential_forwarding', closed)))).toEqual(
      closed,
    )
    expect(
      toRealmConfig(
        seedRealmFormValues(stored('credential_forwarding', { ...base, accept_client_passwords: true })),
      ),
    ).toEqual(base)
  })
})

describe('kept password options', () => {
  const stored = (config: RealmView['config']): RealmView => ({
    id: 1,
    kind: 'credential_forwarding',
    name: 'nexus',
    enabled: true,
    priority: 1,
    config,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  })
  const base = { url: 'https://nexus.example.com/status' }

  it('round-trips both options and omits them when off', () => {
    for (const config of [
      base,
      { ...base, capture_password_hash: true },
      { ...base, capture_password_hash: true, captured_password_only: true },
    ]) {
      expect(toRealmConfig(seedRealmFormValues(stored(config)))).toEqual(config)
    }
  })

  it('never stops forwarding without keeping hashes', () => {
    const values = {
      ...seedRealmFormValues(
        stored({ ...base, capture_password_hash: true, captured_password_only: true }),
      ),
      capture_password_hash: false,
    }
    expect(toRealmConfig(values)).toEqual(base)
  })
})
