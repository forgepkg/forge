import { describe, expect, it } from 'vitest'

import type { RetentionPolicy } from '~/api/retention'
import {
  buildPolicy,
  describeReason,
  describeSchedule,
  draftFromPolicy,
  intervalFromSeconds,
  newRule,
  policyDeletes,
  policyShape,
  validateDraft,
} from './RetentionPolicyForm'

/** The retention policy form's model: shapes, round trips, checks. */
describe('retention policy model', () => {
  it('picks the policy shape of a repository', () => {
    expect(policyShape({ format: 'nuget', kind: 'hosted' })).toBe('package')
    expect(policyShape({ format: 'nuget', kind: 'proxy' })).toBe('proxy')
    expect(policyShape({ format: 'raw', kind: 'proxy' })).toBe('file')
    expect(policyShape({ format: 'docker', kind: 'hosted' })).toBe('image')
    expect(policyShape({ format: 'nuget', kind: 'group' })).toBeNull()
  })

  it('shows an interval in the largest unit that holds it', () => {
    expect(intervalFromSeconds(86400)).toEqual({ value: '1', unit: 'days' })
    expect(intervalFromSeconds(5400)).toEqual({ value: '90', unit: 'minutes' })
    expect(intervalFromSeconds(7200)).toEqual({ value: '2', unit: 'hours' })
    expect(intervalFromSeconds(90)).toEqual({ value: '90', unit: 'seconds' })
  })

  it('round-trips a stored policy, keeping fields the form does not know', () => {
    const stored = {
      version: 1,
      enabled: false,
      dry_run_only: false,
      min_run_interval_seconds: 5400,
      future_envelope_field: 'kept',
      rules: [
        {
          id: 'old',
          action: 'unlist',
          scope: 'hosted',
          release_type: 'prereleases',
          package_name_prefix: null,
          criteria: { keep_n_most_downloaded: 2, older_than_days: 30, future: 1 },
          future_rule_field: true,
        },
      ],
    } as unknown as RetentionPolicy
    const draft = draftFromPolicy('package', stored)
    expect(draft.interval).toBe('90')
    expect(draft.intervalUnit).toBe('minutes')
    expect(draft.rules[0].values['criteria.keep_n_most_downloaded']).toBe('2')
    expect(draft.rules[0].values.package_name_prefix).toBe('')
    expect(validateDraft('package', draft)).toBeNull()
    expect(buildPolicy('package', draft)).toEqual({
      version: 1,
      enabled: false,
      dry_run_only: false,
      min_run_interval_seconds: 5400,
      future_envelope_field: 'kept',
      rules: [
        {
          id: 'old',
          action: 'unlist',
          scope: 'hosted',
          release_type: 'prereleases',
          criteria: { keep_n_most_downloaded: 2, older_than_days: 30, future: 1 },
          future_rule_field: true,
        },
      ],
    })
  })

  it('starts a new policy as a dry run, with unique rule ids', () => {
    const draft = draftFromPolicy('file', null)
    expect(draft.dryRunOnly).toBe(true)
    expect(draft.rules[0].values.not_downloaded_for_days).toBe('90')
    expect(newRule('file', ['rule-2', 'keep-recent']).values.id).toBe('rule-3')
  })

  it('builds a budget-only policy and validates its low watermark', () => {
    const draft = draftFromPolicy('file', null)
    draft.rules = []
    draft.sizeBudgetMax = '2'
    draft.sizeBudgetTarget = '1.5'
    expect(draft.sizeBudgetUnit).toBe('GiB')
    expect(validateDraft('file', draft)).toBeNull()
    expect(buildPolicy('file', draft).size_budget).toEqual({
      max_bytes: 2 * 1024 ** 3,
      target_bytes: 1.5 * 1024 ** 3,
    })
    expect(draftFromPolicy('file', buildPolicy('file', draft)).sizeBudgetMax).toBe('2')

    draft.sizeBudgetUnit = 'GB'
    expect(buildPolicy('file', draft).size_budget).toEqual({
      max_bytes: 2_000_000_000,
      target_bytes: 1_500_000_000,
    })
    const reloaded = draftFromPolicy('file', buildPolicy('file', draft))
    expect([reloaded.sizeBudgetMax, reloaded.sizeBudgetTarget, reloaded.sizeBudgetUnit]).toEqual([
      '2',
      '1.5',
      'GB',
    ])

    draft.sizeBudgetTarget = '2.5'
    expect(validateDraft('file', draft)?.sizeBudgetTarget).toMatch(/must not exceed/)
    draft.sizeBudgetMax = '0'
    expect(validateDraft('file', draft)?.sizeBudgetMax).toMatch(/positive size/)

    const smallStored = {
      version: 1,
      size_budget: { max_bytes: 100, target_bytes: 0 },
      rules: [],
    } as unknown as RetentionPolicy
    const smallDraft = draftFromPolicy('file', smallStored)
    expect(smallDraft.sizeBudgetMax).not.toMatch(/[eE]/)
    expect(smallDraft.sizeBudgetTarget).toBe('0')
    expect(validateDraft('file', smallDraft)).toBeNull()
    expect(buildPolicy('file', smallDraft).size_budget).toEqual({
      max_bytes: 100,
      target_bytes: 0,
    })

    // A stored size reads back unchanged, in the unit that shows it shortest.
    for (const [bytes, unit] of [
      [2, 'GiB'],
      [10, 'GiB'],
      [123_456_789, 'GB'],
      [500 * 1000 ** 3, 'GB'],
      [500 * 1024 ** 3, 'GiB'],
    ] as const) {
      const stored = {
        version: 1,
        size_budget: { max_bytes: bytes, target_bytes: bytes },
        rules: [],
      } as unknown as RetentionPolicy
      const shown = draftFromPolicy('file', stored)
      expect(shown.sizeBudgetUnit).toBe(unit)
      expect(buildPolicy('file', shown).size_budget).toEqual({
        max_bytes: bytes,
        target_bytes: bytes,
      })
    }
  })

  it('refuses empty and duplicate ids, bad numbers and no rules', () => {
    const draft = draftFromPolicy('image', null)
    const second = newRule('image', [])
    second.values.id = draft.rules[0].values.id
    second.values.keep_last_n_tags = '0'
    const errors = validateDraft('image', {
      ...draft,
      interval: '1.5',
      rules: [draft.rules[0], second],
    })
    expect(errors?.interval).toMatch(/whole number/)
    expect(errors?.fields[second.key]).toEqual({
      id: 'Another rule has this id.',
      keep_last_n_tags: 'Enter a whole number of at least 1, or leave it empty.',
    })
    expect(validateDraft('image', { ...draft, rules: [] })?.rules).toMatch(/Add a rule/)
  })

  it('knows which policies remove content when they run', () => {
    const base = { version: 1, enabled: true, dry_run_only: false }
    const unlist = { id: 'a', action: 'unlist' as const, criteria: { older_than_days: 1 } }
    const remove = { ...unlist, action: 'hard_delete' as const }
    expect(policyDeletes('package', { ...base, rules: [unlist] })).toBe(false)
    expect(policyDeletes('package', { ...base, rules: [unlist, remove] })).toBe(true)
    expect(policyDeletes('package', { ...base, dry_run_only: true, rules: [remove] })).toBe(false)
    expect(policyDeletes('package', { ...base, enabled: false, rules: [remove] })).toBe(false)
    expect(policyDeletes('proxy', { ...base, rules: [remove] })).toBe(true)
  })

  it('says why a rule selected something', () => {
    expect(describeReason({ older_than_days: 1, not_downloaded_for_days: 30 })).toBe(
      'older than 1 day, not downloaded for 30 days',
    )
    expect(
      describeReason({
        rank: 4,
        keep_newest_per_directory: 3,
        older_than_days: null,
        deployed_at: '2026-01-01T00:00:00Z',
      }),
    ).toBe('not among the 3 newest in its directory')
    expect(describeReason({})).toBe('')
    expect(describeReason(null)).toBe('')
    expect(describeReason({ size_budget: 1024 ** 3, target_bytes: 512 * 1024 ** 2 })).toBe(
      'repository exceeds 1 GiB, target 0.5 GiB',
    )
  })

  it('round-trips a schedule, a time limit and the new rule fields', () => {
    const stored = {
      version: 1,
      enabled: true,
      dry_run_only: false,
      min_run_interval_seconds: 3600,
      schedule: '0 3 * * 1-5',
      schedule_timezone: 'Europe/Berlin',
      max_run_seconds: 7200,
      rules: [
        {
          id: 'ci',
          action: 'hard_delete',
          scope: 'hosted',
          release_type: 'snapshots',
          selector: 'ci-feeds',
          version_pattern: '*-ci.*',
          exclude_version_pattern: '*-ci.0',
          criteria: {
            prerelease_superseded_for_days: 14,
            unlisted_for_days: 90,
            max_versions_per_package: 20,
          },
        },
      ],
    } as unknown as RetentionPolicy
    const draft = draftFromPolicy('package', stored)
    expect(draft.scheduleMode).toBe('cron')
    expect([draft.schedule, draft.scheduleTimezone]).toEqual(['0 3 * * 1-5', 'Europe/Berlin'])
    expect([draft.maxRun, draft.maxRunUnit]).toEqual(['2', 'hours'])
    expect(draft.rules[0].values.selector).toBe('ci-feeds')
    expect(draft.rules[0].values['criteria.prerelease_superseded_for_days']).toBe('14')
    expect(validateDraft('package', draft)).toBeNull()
    expect(buildPolicy('package', draft)).toEqual(stored)

    // Back to an interval: the schedule goes, the time limit stays.
    const interval = buildPolicy('package', { ...draft, scheduleMode: 'interval' })
    expect(interval.schedule).toBeUndefined()
    expect(interval.schedule_timezone).toBeUndefined()
    expect(interval.max_run_seconds).toBe(7200)
    // Without a time zone or a limit, neither is sent; nor an empty selector.
    draft.scheduleTimezone = ' '
    draft.maxRun = ''
    draft.rules[0].values.selector = ''
    const plain = buildPolicy('package', draft)
    expect(plain.schedule_timezone).toBeUndefined()
    expect(plain.max_run_seconds).toBeUndefined()
    expect('selector' in plain.rules[0]).toBe(false)
  })

  it('checks a cron pattern and a time limit', () => {
    const draft = { ...draftFromPolicy('image', null), scheduleMode: 'cron' as const }
    expect(validateDraft('image', draft)?.schedule).toMatch(/5 fields/)
    for (const ok of ['0 3 * * *', '*/15  2-4 * * MON-FRI', '@daily']) {
      expect(validateDraft('image', { ...draft, schedule: ok })).toBeNull()
    }
    expect(validateDraft('image', { ...draft, schedule: '0 3 * *' })?.schedule).toBeDefined()
    const timed = { ...draft, schedule: '0 3 * * *', maxRunUnit: 'seconds' as const }
    expect(validateDraft('image', { ...timed, maxRun: '30' })?.maxRun).toMatch(/minute/)
    expect(validateDraft('image', { ...timed, maxRun: '60' })).toBeNull()
    expect(
      validateDraft('image', { ...timed, maxRun: '8', maxRunUnit: 'days' })?.maxRun,
    ).toMatch(/week/)
  })

  it('says why the new triggers selected a version, and when a policy runs', () => {
    expect(
      describeReason({ prerelease_superseded_for_days: 14, superseded_by: '2.3.0' }),
    ).toBe('superseded by 2.3.0 for over 14 days')
    expect(describeReason({ unlisted_for_days: 90 })).toBe('unlisted for 90 days')
    expect(describeReason({ max_versions_per_package: 3, rank: 5 })).toBe(
      'number 5 of its package, beyond the newest 3',
    )
    const base = { version: 1, rules: [] }
    expect(describeSchedule({ ...base, min_run_interval_seconds: 3600 })).toBe(
      'at most every 1 hour',
    )
    expect(
      describeSchedule({
        ...base,
        schedule: '0 3 * * *',
        schedule_timezone: 'Europe/Berlin',
        max_run_seconds: 5400,
      }),
    ).toBe('0 3 * * * (Europe/Berlin); a run stops after 90 minutes')
    expect(describeSchedule({ ...base, schedule: '@daily' })).toBe('@daily (UTC)')
  })
})
