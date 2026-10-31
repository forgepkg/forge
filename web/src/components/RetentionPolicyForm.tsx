import type { ReactNode } from 'react'

import type {
  DecisionReason,
  PreviewView,
  RetentionPolicy,
  RetentionRule,
} from '~/api/retention'
import {
  Button,
  Fieldset,
  SelectField,
  Switch,
  TextField,
} from '~/components/ui'

/**
 * The retention policy editor and its model. A repository's policy takes one
 * of four shapes, by its format and kind (`crates/core/src/retention/`):
 *
 *  - `package`: hosted NuGet and plugin-format repositories. Rules
 *    unlist or delete versions, with filters, protections and triggers.
 *  - `proxy`: the same formats' proxies. Rules (`scope: proxy_cached`) evict
 *    cached versions nobody pulled for a while; they stay listed.
 *  - `file`: raw repositories, hosted or proxy.
 *  - `image`: docker repositories, hosted or proxy.
 *
 * The form holds every value as typed (strings), and each rule keeps the JSON
 * it was loaded from (`base`), so a field this screen does not know survives
 * a save. `validateDraft` checks what the browser can; the server checks the
 * rest and its message is shown at the form.
 */

export type PolicyShape = 'package' | 'proxy' | 'file' | 'image'

/** The shape of a repository's policy; `null` for a group (no policy). */
export function policyShape(repo: {
  format: string
  kind: string
}): PolicyShape | null {
  if (repo.kind === 'group') return null
  if (repo.format === 'docker') return 'image'
  if (repo.format === 'raw') return 'file'
  return repo.kind === 'proxy' ? 'proxy' : 'package'
}

type FieldKind = 'count' | 'days' | 'text' | 'tags' | 'select' | 'selector'

interface FieldSpec {
  /** The field's place in the rule's JSON. */
  path: readonly string[]
  label: string
  kind: FieldKind
  description: ReactNode
  placeholder?: string
  options?: readonly { value: string; label: string }[]
}

interface FieldGroup {
  legend: string
  description?: string
  fields: FieldSpec[]
}

interface ShapeSpec {
  /** How the rules combine. */
  rulesNote: string
  /** The fields beside the rule id. */
  head: FieldSpec[]
  groups: FieldGroup[]
  /** The JSON a new rule starts from, before its fields. */
  base: Record<string, unknown>
  /** A new policy's first rule. */
  example: Record<string, string>
}

const RULE_ID: FieldSpec = {
  path: ['id'],
  label: 'Rule id',
  kind: 'text',
  description: 'Recorded on every audit row this rule produces.',
}

const RELEASE_TYPE: FieldSpec = {
  path: ['release_type'],
  label: 'Versions',
  kind: 'select',
  description:
    'As the format classes a version: a prerelease has a label after a dash, such as 2.0.0-beta.1; snapshots are builds such as Maven’s -SNAPSHOT ones.',
  options: [
    { value: 'any', label: 'Every version' },
    { value: 'releases', label: 'Releases only' },
    { value: 'prereleases', label: 'Prereleases only' },
    { value: 'snapshots', label: 'Snapshots only' },
  ],
}

const PACKAGE_PREFIX: FieldSpec = {
  path: ['package_name_prefix'],
  label: 'Package id prefix',
  kind: 'text',
  placeholder: 'acme.',
  description: 'Only packages whose id starts with this, ignoring case. Empty: every package.',
}

const SELECTOR: FieldSpec = {
  path: ['selector'],
  label: 'Content selector',
  kind: 'selector',
  description:
    'Only packages a content selector admits (Admin → Content selectors). Empty: every package.',
}

const VERSION_PATTERN: FieldSpec = {
  path: ['version_pattern'],
  label: 'Version pattern',
  kind: 'text',
  placeholder: '*-ci.*',
  description:
    'Only versions this glob matches, ignoring case; {*-ci.*,*-pr.*} for either. Empty: every version.',
}

const EXCLUDE_VERSION_PATTERN: FieldSpec = {
  path: ['exclude_version_pattern'],
  label: 'Except versions matching',
  kind: 'text',
  placeholder: '*-rc.*',
  description: 'Never the versions this glob matches.',
}

const PACKAGE_FILTERS = [
  RELEASE_TYPE,
  PACKAGE_PREFIX,
  SELECTOR,
  VERSION_PATTERN,
  EXCLUDE_VERSION_PATTERN,
]

const MAX_VERSIONS: FieldSpec = {
  path: ['criteria', 'max_versions_per_package'],
  label: 'More than N versions',
  kind: 'count',
  description:
    'Not among the newest N versions of its package (among the versions above), listed or not. Needs no age.',
}

const SHAPES: Record<PolicyShape, ShapeSpec> = {
  package: {
    rulesNote:
      'A version goes when any rule selects it. What any rule keeps is never unlisted or deleted, and when two rules select a version, deleting wins over unlisting.',
    head: [
      {
        path: ['action'],
        label: 'Action',
        kind: 'select',
        description: 'Unlisted versions stay downloadable by exact version; deleted ones are gone.',
        options: [
          { value: 'unlist', label: 'Unlist the version' },
          { value: 'hard_delete', label: 'Delete the version' },
        ],
      },
    ],
    groups: [
      { legend: 'Versions it looks at', fields: PACKAGE_FILTERS },
      {
        legend: 'Always keep',
        description:
          'Per package, among the versions above. A version any rule keeps is never unlisted or deleted, whatever selects it.',
        fields: [
          {
            path: ['criteria', 'keep_last_n'],
            label: 'Newest versions',
            kind: 'count',
            description: 'The newest N listed versions.',
          },
          {
            path: ['criteria', 'keep_n_most_downloaded'],
            label: 'Most recently downloaded',
            kind: 'count',
            description: 'The N versions downloaded last, listed or not.',
          },
        ],
      },
      {
        legend: 'Act on a version when all of these hold',
        fields: [
          {
            path: ['criteria', 'older_than_days'],
            label: 'Published more than (days)',
            kind: 'days',
            description: 'Days since the version was published.',
          },
          {
            path: ['criteria', 'not_downloaded_for_days'],
            label: 'Not downloaded for (days)',
            kind: 'days',
            description: 'A version never downloaded counts from its publication.',
          },
          {
            path: ['criteria', 'prerelease_superseded_for_days'],
            label: 'Superseded by a release for (days)',
            kind: 'days',
            description:
              'A prerelease, once a release that comes after it has been out this long: 2.3.0-ci.417 once 2.3.0 is.',
          },
          {
            path: ['criteria', 'unlisted_for_days'],
            label: 'Unlisted for (days)',
            kind: 'days',
            description:
              'Unlisted at least this long: with “Delete”, the second step after a rule that unlists.',
          },
          MAX_VERSIONS,
        ],
      },
    ],
    base: { action: 'hard_delete', scope: 'hosted', release_type: 'any', criteria: {} },
    example: {
      id: 'keep-recent',
      action: 'hard_delete',
      release_type: 'any',
      'criteria.keep_last_n': '10',
      'criteria.not_downloaded_for_days': '90',
    },
  },
  proxy: {
    rulesNote:
      'A cached version is evicted when any rule selects it. What any rule keeps is never evicted, so each package can keep a working set however long nobody pulls it.',
    head: [],
    groups: [
      { legend: 'Versions it looks at', fields: PACKAGE_FILTERS },
      {
        legend: 'Always keep',
        description:
          'Per package, among its cached versions the filters above admit. A version any rule keeps stays cached.',
        fields: [
          {
            path: ['criteria', 'keep_last_n'],
            label: 'Newest versions',
            kind: 'count',
            description: 'The newest N cached versions the upstream lists.',
          },
          {
            path: ['criteria', 'keep_n_most_downloaded'],
            label: 'Most recently pulled',
            kind: 'count',
            description: 'The N cached versions pulled last, listed or not.',
          },
        ],
      },
      {
        legend: 'Evict a cached version when',
        description:
          'An evicted version stays listed; its next pull fetches it from the upstream again.',
        fields: [
          {
            path: ['criteria', 'not_pulled_for_days'],
            label: 'Not pulled for (days)',
            kind: 'days',
            description: 'A version never pulled counts from when the proxy first saw it.',
          },
          {
            ...MAX_VERSIONS,
            description:
              'Not among the newest N cached versions of its package (among the versions above), however recently pulled.',
          },
        ],
      },
    ],
    base: {
      action: 'hard_delete',
      scope: 'proxy_cached',
      release_type: 'any',
      criteria: {},
    },
    example: {
      id: 'evict-cold',
      release_type: 'any',
      'criteria.keep_last_n': '3',
      'criteria.not_pulled_for_days': '90',
    },
  },
  file: {
    rulesNote:
      'A file goes when any rule selects it. What a rule keeps, it spares from that rule only.',
    head: [],
    groups: [
      {
        legend: 'Files it looks at',
        fields: [
          {
            path: ['path_prefix'],
            label: 'Path prefix',
            kind: 'text',
            placeholder: 'nightly/',
            description: 'Only files whose path starts with this. Empty: every file.',
          },
        ],
      },
      {
        legend: 'Always keep',
        fields: [
          {
            path: ['keep_newest_per_directory'],
            label: 'Newest files per directory',
            kind: 'count',
            description:
              'The N most recently deployed files of each directory. Alone, the rule deletes the others.',
          },
        ],
      },
      {
        legend: 'Delete a file when all of these hold',
        fields: [
          {
            path: ['older_than_days'],
            label: 'Deployed more than (days)',
            kind: 'days',
            description: 'Days since its content was deployed.',
          },
          {
            path: ['not_downloaded_for_days'],
            label: 'Not downloaded for (days)',
            kind: 'days',
            description: 'A file never downloaded counts from its deployment.',
          },
        ],
      },
    ],
    base: {},
    example: { id: 'keep-recent', not_downloaded_for_days: '90' },
  },
  image: {
    rulesNote:
      'A tag or manifest goes when any rule selects it. What a rule keeps, it spares from that rule only.',
    head: [],
    groups: [
      {
        legend: 'Images it looks at',
        fields: [
          {
            path: ['image_prefix'],
            label: 'Image prefix',
            kind: 'text',
            placeholder: 'team/',
            description: 'Only images whose name starts with this. Empty: every image.',
          },
          {
            path: ['tag_pattern'],
            label: 'Tag pattern',
            kind: 'text',
            placeholder: 'pr-*',
            description: 'Only tags this glob matches, as written. Empty: every tag.',
          },
          {
            path: ['exclude_tag_pattern'],
            label: 'Except tags matching',
            kind: 'text',
            placeholder: 'v*',
            description: 'Never the tags this glob matches.',
          },
        ],
      },
      {
        legend: 'Always keep',
        fields: [
          {
            path: ['keep_last_n_tags'],
            label: 'Newest tags',
            kind: 'count',
            description:
              'The N most recently pushed tags of each image. Alone, the rule deletes the others.',
          },
          {
            path: ['protected_tags'],
            label: 'Protected tags',
            kind: 'tags',
            placeholder: 'latest, release-*',
            description:
              'Never deleted by this rule: names or globs. Separate them with commas or spaces.',
          },
        ],
      },
      {
        legend: 'Delete a tag when all of these hold',
        fields: [
          {
            path: ['tag_older_than_days'],
            label: 'Pushed more than (days)',
            kind: 'days',
            description: 'Days since the tag was pushed.',
          },
          {
            path: ['tag_not_pulled_for_days'],
            label: 'Not pulled for (days)',
            kind: 'days',
            description: 'Its manifest was not pulled, or never since the push.',
          },
        ],
      },
      {
        legend: 'Untagged manifests',
        fields: [
          {
            path: ['delete_untagged_after_days'],
            label: 'Delete after (days) without a tag',
            kind: 'days',
            description:
              'The children of a kept index, and the signatures and SBOMs of a kept manifest, are kept with it.',
          },
        ],
      },
    ],
    base: {},
    example: {
      id: 'cleanup',
      keep_last_n_tags: '10',
      protected_tags: 'latest',
      tag_not_pulled_for_days: '90',
      delete_untagged_after_days: '7',
    },
  },
}

const UNIT_OPTIONS = (
  <>
    <option value="minutes">Minutes</option>
    <option value="hours">Hours</option>
    <option value="days">Days</option>
    <option value="seconds">Seconds</option>
  </>
)

function fieldsOf(shape: PolicyShape): FieldSpec[] {
  const spec = SHAPES[shape]
  return [RULE_ID, ...spec.head, ...spec.groups.flatMap((g) => g.fields)]
}

function keyOf(field: FieldSpec): string {
  return field.path.join('.')
}

export type IntervalUnit = 'minutes' | 'hours' | 'days' | 'seconds'

const UNIT_SECONDS: Record<IntervalUnit, number> = {
  days: 86400,
  hours: 3600,
  minutes: 60,
  seconds: 1,
}

/** A number of seconds in the largest unit that holds it exactly. */
export function intervalFromSeconds(seconds: number): {
  value: string
  unit: IntervalUnit
} {
  for (const unit of ['days', 'hours', 'minutes'] as const) {
    if (seconds > 0 && seconds % UNIT_SECONDS[unit] === 0) {
      return { value: String(seconds / UNIT_SECONDS[unit]), unit }
    }
  }
  return { value: String(seconds), unit: 'seconds' }
}

/** The units a size budget is entered in. */
export type SizeUnit = 'GB' | 'GiB'

const UNIT_BYTES: Record<SizeUnit, number> = {
  GB: 1000 ** 3,
  GiB: 1024 ** 3,
}

/** `bytes` in `unit`, as the shortest decimal that reads back to it. */
function amountIn(bytes: number, unit: SizeUnit): string {
  const amount = bytes / UNIT_BYTES[unit]
  const short = String(amount)
  // Tiny amounts print as `2e-9`, which the form does not take.
  return short.includes('e') ? amount.toFixed(30).replace(/\.?0+$/, '') : short
}

/** The unit that shows stored sizes in the fewest digits, GiB on a tie. */
function unitOf(sizes: number[]): SizeUnit {
  const digits = (unit: SizeUnit) =>
    sizes.reduce((n, bytes) => n + amountIn(bytes, unit).length, 0)
  return digits('GB') < digits('GiB') ? 'GB' : 'GiB'
}

/** `bytes` in `unit`, for reading: at most two decimals. */
export function formatBytes(bytes: number, unit: SizeUnit): string {
  const amount = (bytes / UNIT_BYTES[unit]).toLocaleString(undefined, {
    maximumFractionDigits: 2,
  })
  return `${amount} ${unit}`
}

/** One rule as the form holds it. */
export interface RuleDraft {
  /** Stable React key; not part of the policy. */
  key: number
  /** The rule's JSON as loaded (or a new rule's), under the edited fields. */
  base: Record<string, unknown>
  values: Record<string, string>
}

/** The whole form. */
export interface PolicyDraft {
  /** The policy's JSON as loaded, under the edited fields. */
  base: Record<string, unknown>
  enabled: boolean
  dryRunOnly: boolean
  /** Runs at most every `interval`, or at the times of a cron `schedule`. */
  scheduleMode: 'interval' | 'cron'
  interval: string
  intervalUnit: IntervalUnit
  /** A 5-field cron pattern, and its IANA time zone (empty: UTC). */
  schedule: string
  scheduleTimezone: string
  /** How long a run may take (empty: no limit), in `maxRunUnit`. */
  maxRun: string
  maxRunUnit: IntervalUnit
  /** The size budget's maximum and target, in `sizeBudgetUnit`. */
  sizeBudgetMax: string
  sizeBudgetTarget: string
  sizeBudgetUnit: SizeUnit
  rules: RuleDraft[]
}

let nextKey = 1

function getPath(obj: Record<string, unknown>, path: readonly string[]): unknown {
  let at: unknown = obj
  for (const part of path) {
    if (at === null || typeof at !== 'object') return undefined
    at = (at as Record<string, unknown>)[part]
  }
  return at
}

function setPath(
  obj: Record<string, unknown>,
  path: readonly string[],
  value: unknown,
): void {
  let at = obj
  for (const part of path.slice(0, -1)) {
    const next = at[part]
    if (next === null || typeof next !== 'object') at[part] = {}
    at = at[part] as Record<string, unknown>
  }
  const last = path[path.length - 1]
  if (value === undefined) delete at[last]
  else at[last] = value
}

function ruleFromJson(shape: PolicyShape, rule: Record<string, unknown>): RuleDraft {
  const values: Record<string, string> = {}
  for (const field of fieldsOf(shape)) {
    const v = getPath(rule, field.path)
    if (Array.isArray(v)) values[keyOf(field)] = v.join(', ')
    else if (v === null || v === undefined) values[keyOf(field)] = ''
    else values[keyOf(field)] = String(v)
  }
  return { key: nextKey++, base: structuredClone(rule), values }
}

/** A new rule of the shape, with a rule id no other rule has. */
export function newRule(shape: PolicyShape, taken: string[]): RuleDraft {
  const rule = ruleFromJson(shape, structuredClone(SHAPES[shape].base))
  let n = taken.length + 1
  while (taken.includes(`rule-${n}`)) n += 1
  rule.values.id = `rule-${n}`
  return rule
}

/**
 * The form for a stored policy, or for a new one: a first example rule, as a
 * dry run, so saving it unchanged removes nothing.
 */
export function draftFromPolicy(
  shape: PolicyShape,
  policy: RetentionPolicy | null,
): PolicyDraft {
  if (!policy) {
    const example = ruleFromJson(shape, structuredClone(SHAPES[shape].base))
    example.values = { ...example.values, ...SHAPES[shape].example }
    return {
      base: { version: 1 },
      enabled: true,
      dryRunOnly: true,
      scheduleMode: 'interval',
      interval: '1',
      intervalUnit: 'hours',
      schedule: '',
      scheduleTimezone: '',
      maxRun: '',
      maxRunUnit: 'hours',
      sizeBudgetMax: '',
      sizeBudgetTarget: '',
      sizeBudgetUnit: 'GiB',
      rules: [example],
    }
  }
  const { rules, ...base } = policy as RetentionPolicy & Record<string, unknown>
  const interval = intervalFromSeconds(policy.min_run_interval_seconds ?? 3600)
  const budget = policy.size_budget
  const sizes = budget ? [budget.max_bytes, budget.target_bytes ?? 0] : []
  const unit = unitOf(sizes)
  const maxRun =
    policy.max_run_seconds === undefined ? null : intervalFromSeconds(policy.max_run_seconds)
  return {
    base: structuredClone(base),
    enabled: policy.enabled ?? true,
    dryRunOnly: policy.dry_run_only ?? false,
    scheduleMode: policy.schedule ? 'cron' : 'interval',
    interval: interval.value,
    intervalUnit: interval.unit,
    schedule: policy.schedule ?? '',
    scheduleTimezone: policy.schedule_timezone ?? '',
    maxRun: maxRun?.value ?? '',
    maxRunUnit: maxRun?.unit ?? 'hours',
    sizeBudgetMax: budget ? amountIn(budget.max_bytes, unit) : '',
    sizeBudgetTarget:
      budget?.target_bytes === undefined ? '' : amountIn(budget.target_bytes, unit),
    sizeBudgetUnit: unit,
    rules: rules.map((r) => ruleFromJson(shape, r as unknown as Record<string, unknown>)),
  }
}

/** What is wrong with the form, field by field. */
export interface DraftErrors {
  interval?: string
  schedule?: string
  maxRun?: string
  sizeBudgetMax?: string
  sizeBudgetTarget?: string
  /** A message for the rules as a whole. */
  rules?: string
  /** Per rule key, per field key. */
  fields: Record<number, Record<string, string>>
}

const WHOLE = /^\d+$/
const DECIMAL = /^\d+(\.\d+)?$/
/** Five fields (the server checks each), or a nickname such as @daily. */
const CRON = /^(@[a-z]+|\S+(\s+\S+){4})$/i
/** The bounds of `max_run_seconds`: a minute and a week. */
const MIN_MAX_RUN = 60
const MAX_MAX_RUN = 7 * 86400

/** The browser's checks; `null` when the form can be sent. */
export function validateDraft(shape: PolicyShape, draft: PolicyDraft): DraftErrors | null {
  const errors: DraftErrors = { fields: {} }
  let failed = false
  const interval = draft.interval.trim()
  if (!WHOLE.test(interval) || Number(interval) < 1) {
    errors.interval = 'Enter a whole number of at least 1.'
    failed = true
  }
  if (draft.scheduleMode === 'cron' && !CRON.test(draft.schedule.trim())) {
    errors.schedule = 'Enter a cron pattern of 5 fields, such as 0 3 * * *.'
    failed = true
  }
  const maxRun = draft.maxRun.trim()
  if (maxRun !== '') {
    const seconds = Number(maxRun) * UNIT_SECONDS[draft.maxRunUnit]
    if (!WHOLE.test(maxRun) || seconds < MIN_MAX_RUN || seconds > MAX_MAX_RUN) {
      errors.maxRun = 'Enter a time between a minute and a week, or leave it empty.'
      failed = true
    }
  }
  const max = draft.sizeBudgetMax.trim()
  const target = draft.sizeBudgetTarget.trim()
  const validMax = DECIMAL.test(max) && Number(max) > 0
  if (max !== '' && !validMax) {
    errors.sizeBudgetMax = 'Enter a positive size, or leave it empty.'
    failed = true
  } else if (validMax && toBytes(max, draft.sizeBudgetUnit) > Number.MAX_SAFE_INTEGER) {
    errors.sizeBudgetMax = 'The maximum exceeds the supported byte range.'
    failed = true
  }
  if (target !== '') {
    if (!DECIMAL.test(target)) {
      errors.sizeBudgetTarget = 'Enter a size, or leave it empty.'
      failed = true
    } else if (!validMax) {
      errors.sizeBudgetTarget = 'Set a maximum size first.'
      failed = true
    } else if (Number(target) > Number(max)) {
      errors.sizeBudgetTarget = 'The target must not exceed the maximum.'
      failed = true
    }
  }
  if (draft.rules.length === 0 && !validMax) {
    errors.rules = 'Add a rule or set a size budget.'
    failed = true
  }
  const seen = new Set<string>()
  for (const rule of draft.rules) {
    const own: Record<string, string> = {}
    const id = rule.values.id.trim()
    if (id === '') own.id = 'Enter a rule id.'
    else if (seen.has(id)) own.id = 'Another rule has this id.'
    seen.add(id)
    for (const field of fieldsOf(shape)) {
      if (field.kind !== 'count' && field.kind !== 'days') continue
      const v = rule.values[keyOf(field)].trim()
      if (v !== '' && (!WHOLE.test(v) || Number(v) < 1)) {
        own[keyOf(field)] = 'Enter a whole number of at least 1, or leave it empty.'
      }
    }
    if (Object.keys(own).length > 0) {
      errors.fields[rule.key] = own
      failed = true
    }
  }
  return failed ? errors : null
}

/** `amount` of `unit` in whole bytes. */
function toBytes(amount: string, unit: SizeUnit): number {
  return Math.round(Number(amount) * UNIT_BYTES[unit])
}

/** The policy the form says, for a form `validateDraft` accepted. */
export function buildPolicy(shape: PolicyShape, draft: PolicyDraft): RetentionPolicy {
  const rules = draft.rules.map((rule) => {
    const json = structuredClone(rule.base)
    for (const field of fieldsOf(shape)) {
      const raw = rule.values[keyOf(field)].trim()
      let value: unknown
      if (field.kind === 'count' || field.kind === 'days') {
        value = raw === '' ? undefined : Number(raw)
      } else if (field.kind === 'tags') {
        const tags = raw.split(/[\s,]+/).filter((t) => t !== '')
        value = tags.length > 0 ? tags : undefined
      } else if ((field.kind === 'text' || field.kind === 'selector') && raw === '' && field !== RULE_ID) {
        value = undefined
      } else {
        value = raw
      }
      setPath(json, field.path, value)
    }
    return json as unknown as RetentionRule
  })
  const base = structuredClone(draft.base)
  if (draft.scheduleMode === 'cron') {
    base.schedule = draft.schedule.trim().replace(/\s+/g, ' ')
    const zone = draft.scheduleTimezone.trim()
    if (zone === '') delete base.schedule_timezone
    else base.schedule_timezone = zone
  } else {
    delete base.schedule
    delete base.schedule_timezone
  }
  const maxRun = draft.maxRun.trim()
  if (maxRun === '') delete base.max_run_seconds
  else base.max_run_seconds = Number(maxRun) * UNIT_SECONDS[draft.maxRunUnit]
  const max = draft.sizeBudgetMax.trim()
  const target = draft.sizeBudgetTarget.trim()
  if (max === '') {
    delete base.size_budget
  } else {
    base.size_budget = {
      max_bytes: toBytes(max, draft.sizeBudgetUnit),
      ...(target === '' ? {} : { target_bytes: toBytes(target, draft.sizeBudgetUnit) }),
    }
  }
  return {
    ...base,
    version: (draft.base.version as number | undefined) ?? 1,
    enabled: draft.enabled,
    dry_run_only: draft.dryRunOnly,
    min_run_interval_seconds:
      Number(draft.interval.trim()) * UNIT_SECONDS[draft.intervalUnit],
    rules,
  }
}

/** Whether runs of `policy` delete anything (rather than only unlist). */
export function policyDeletes(shape: PolicyShape, policy: RetentionPolicy): boolean {
  if (policy.enabled === false || policy.dry_run_only) return false
  if (policy.size_budget) return true
  if (shape !== 'package') return policy.rules.length > 0
  return policy.rules.some((r) => 'action' in r && r.action === 'hard_delete')
}

/** When a stored policy runs: its schedule, or its interval. */
export function describeSchedule(policy: RetentionPolicy): string {
  const limit =
    policy.max_run_seconds === undefined
      ? ''
      : `; a run stops after ${durationText(policy.max_run_seconds)}`
  if (policy.schedule) {
    return `${policy.schedule} (${policy.schedule_timezone ?? 'UTC'})${limit}`
  }
  return `at most every ${durationText(policy.min_run_interval_seconds ?? 3600)}${limit}`
}

function durationText(seconds: number): string {
  const { value, unit } = intervalFromSeconds(seconds)
  const n = Number(value)
  return `${n.toLocaleString()} ${n === 1 ? unit.replace(/s$/, '') : unit}`
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`
}

/** One sentence of what a preview found. */
export function summarizePreview(shape: PolicyShape, preview: PreviewView): string {
  const { evaluated, deleted, unlisted } = preview.counts
  let summary: string
  switch (shape) {
    case 'package':
      summary = `Of ${plural(evaluated, 'version')}, ${deleted.toLocaleString()} would be deleted and ${unlisted.toLocaleString()} unlisted.`
      break
    case 'proxy':
      summary = `Of ${plural(evaluated, 'cached version')}, ${deleted.toLocaleString()} would be evicted.`
      break
    case 'file':
      summary = `Of ${plural(evaluated, 'file')}, ${deleted.toLocaleString()} would be deleted.`
      break
    case 'image': {
      const tags = preview.image_decisions?.tags.length ?? 0
      const manifests = preview.image_decisions?.manifests.length ?? 0
      summary = `Of ${plural(evaluated, 'tag and manifest', 'tags and manifests')}, ${plural(tags, 'tag')} and ${plural(manifests, 'manifest')} would be deleted.`
      break
    }
  }
  if (preview.target_bytes !== undefined && preview.size_before !== undefined) {
    summary += ` Size would go from ${formatSize(preview.size_before)} to ${formatSize(preview.size_after ?? preview.size_before)} against a ${formatSize(preview.target_bytes)} target; ${preview.target_reached ? 'the target would be reached' : 'protected content would keep it above target'}.`
  }
  return summary
}

function days(n: number): string {
  return plural(n, 'day')
}

const REASONS: Record<string, (n: number, reason: DecisionReason) => string> = {
  older_than_days: (n) => `older than ${days(n)}`,
  not_downloaded_for_days: (n) => `not downloaded for ${days(n)}`,
  not_pulled_for_days: (n) => `not pulled for ${days(n)}`,
  prerelease_superseded_for_days: (n, r) =>
    typeof r.superseded_by === 'string'
      ? `superseded by ${r.superseded_by} for over ${days(n)}`
      : `superseded by a release for over ${days(n)}`,
  unlisted_for_days: (n) => `unlisted for ${days(n)}`,
  max_versions_per_package: (n, r) =>
    typeof r.rank === 'number'
      ? `number ${r.rank} of its package, beyond the newest ${n}`
      : `beyond the newest ${n} of its package`,
  keep_newest_per_directory: (n) => `not among the ${n} newest in its directory`,
  keep_last_n_tags: (n) => `not among the ${n} newest tags`,
  tag_older_than_days: (n) => `pushed over ${days(n)} ago`,
  tag_not_pulled_for_days: (n) => `not pulled for ${days(n)}`,
  delete_untagged_after_days: (n) => `untagged for ${days(n)}`,
  size_budget: (n) => `repository exceeds ${formatSize(n)}`,
  target_bytes: (n) => `target ${formatSize(n)}`,
  size_bytes: (n) => `${formatSize(n)} removed`,
}

function formatSize(bytes: number): string {
  return formatBytes(bytes, 'GiB')
}

/** Why a rule selected something, from a decision's or audit row's `reason`. */
export function describeReason(reason: DecisionReason | null | undefined): string {
  if (!reason) return ''
  return Object.entries(REASONS)
    .filter(([key]) => typeof reason[key] === 'number')
    .map(([key, phrase]) => phrase(reason[key] as number, reason))
    .join(', ')
}

/**
 * The policy editor: the envelope (enabled, dry run only, how often it runs)
 * and the ordered rules, each with the fields of the repository's shape.
 * Controlled: `onChange` gets the whole next draft.
 */
export function RetentionPolicyForm({
  shape,
  draft,
  errors,
  currentSizeBytes = 0,
  selectors,
  onChange,
}: {
  shape: PolicyShape
  draft: PolicyDraft
  errors: DraftErrors | null
  currentSizeBytes?: number
  /** The content selectors a rule may name; `undefined`: typed by name. */
  selectors?: string[]
  onChange: (draft: PolicyDraft) => void
}) {
  const spec = SHAPES[shape]
  const max = draft.sizeBudgetMax.trim()
  const maxBytes =
    DECIMAL.test(max) && Number(max) > 0 ? toBytes(max, draft.sizeBudgetUnit) : null

  function setRule(key: number, values: Record<string, string>) {
    onChange({
      ...draft,
      rules: draft.rules.map((r) => (r.key === key ? { ...r, values } : r)),
    })
  }

  function move(index: number, by: -1 | 1) {
    const rules = [...draft.rules]
    const [rule] = rules.splice(index, 1)
    rules.splice(index + by, 0, rule)
    onChange({ ...draft, rules })
  }

  return (
    <div className="fg-form">
      <div className="fg-fieldrow">
        <Switch
          label="Enabled"
          checked={draft.enabled}
          onChange={(enabled) => onChange({ ...draft, enabled })}
          description="A disabled policy is kept but never runs."
        />
        <Switch
          label="Dry run only"
          checked={draft.dryRunOnly}
          onChange={(dryRunOnly) => onChange({ ...draft, dryRunOnly })}
          description="Runs record in the audit log what they would remove, and remove nothing."
        />
      </div>
      <div className="fg-fieldrow">
        <SelectField
          label="When it runs"
          value={draft.scheduleMode}
          onChange={(e) =>
            onChange({
              ...draft,
              scheduleMode: e.target.value as PolicyDraft['scheduleMode'],
            })
          }
          description="On a schedule, the worker runs the policy at its times only, such as outside working hours."
        >
          <option value="interval">At most every…</option>
          <option value="cron">On a cron schedule</option>
        </SelectField>
        {draft.scheduleMode === 'interval' ? (
          <>
            <TextField
              label="Minimum time between runs"
              inputMode="numeric"
              mono
              value={draft.interval}
              onChange={(e) => onChange({ ...draft, interval: e.target.value })}
              error={errors?.interval}
              description="Run now does not wait for it. Runs are at least a minute apart."
            />
            <SelectField
              label="Unit"
              value={draft.intervalUnit}
              onChange={(e) =>
                onChange({ ...draft, intervalUnit: e.target.value as IntervalUnit })
              }
            >
              {UNIT_OPTIONS}
            </SelectField>
          </>
        ) : (
          <>
            <TextField
              label="Cron schedule"
              mono
              placeholder="0 3 * * *"
              value={draft.schedule}
              onChange={(e) => onChange({ ...draft, schedule: e.target.value })}
              error={errors?.schedule}
              description="Minute, hour, day of month, month, day of week: 0 3 * * * is 03:00 every day, 0 3 * * 6 Saturdays. Run now does not wait for it."
            />
            <TextField
              label="Time zone"
              optional
              mono
              placeholder="Europe/Berlin"
              value={draft.scheduleTimezone}
              onChange={(e) => onChange({ ...draft, scheduleTimezone: e.target.value })}
              description="An IANA time zone; UTC when empty. The schedule keeps its local time across daylight-saving changes."
            />
          </>
        )}
      </div>
      <div className="fg-fieldrow">
        <TextField
          label="Stop a run after"
          optional
          inputMode="numeric"
          mono
          value={draft.maxRun}
          onChange={(e) => onChange({ ...draft, maxRun: e.target.value })}
          error={errors?.maxRun}
          description="A run still going then stops before its next batch, and the next run goes on with the rest. Empty: no limit."
        />
        <SelectField
          label="Time unit"
          value={draft.maxRunUnit}
          onChange={(e) => onChange({ ...draft, maxRunUnit: e.target.value as IntervalUnit })}
        >
          {UNIT_OPTIONS}
        </SelectField>
      </div>

      <Fieldset
        legend="Size budget"
        description="After the rules run, delete least-recently used content until the repository reaches the target. This counts logical repository content, not deduplicated object-store usage."
      >
        <p className="fg-text">
          Current logical size: {formatBytes(currentSizeBytes, draft.sizeBudgetUnit)}
          {maxBytes !== null && ` of ${formatBytes(maxBytes, draft.sizeBudgetUnit)}`}
        </p>
        <div className="fg-fieldrow">
          <TextField
            label="Maximum size"
            optional
            mono
            inputMode="decimal"
            value={draft.sizeBudgetMax}
            onChange={(e) => onChange({ ...draft, sizeBudgetMax: e.target.value })}
            error={errors?.sizeBudgetMax}
            description="Eviction starts when the repository grows past this size."
          />
          <TextField
            label="Target size"
            optional
            mono
            inputMode="decimal"
            value={draft.sizeBudgetTarget}
            onChange={(e) => onChange({ ...draft, sizeBudgetTarget: e.target.value })}
            error={errors?.sizeBudgetTarget}
            description="Defaults to 90% of the maximum to avoid deleting content on every run."
          />
          <SelectField
            label="Size unit"
            value={draft.sizeBudgetUnit}
            onChange={(e) => onChange({ ...draft, sizeBudgetUnit: e.target.value as SizeUnit })}
          >
            <option value="GB">GB</option>
            <option value="GiB">GiB</option>
          </SelectField>
        </div>
      </Fieldset>

      <p className="fg-text">{spec.rulesNote}</p>
      {draft.rules.map((rule, i) => (
        <RuleFields
          key={rule.key}
          index={i}
          count={draft.rules.length}
          spec={spec}
          rule={rule}
          errors={errors?.fields[rule.key]}
          selectors={selectors}
          onChange={(values) => setRule(rule.key, values)}
          onMove={(by) => move(i, by)}
          onRemove={() =>
            onChange({ ...draft, rules: draft.rules.filter((r) => r.key !== rule.key) })
          }
        />
      ))}
      {errors?.rules && <p className="fg-field-error">{errors.rules}</p>}
      <div>
        <Button
          icon="Plus"
          onClick={() =>
            onChange({
              ...draft,
              rules: [
                ...draft.rules,
                newRule(
                  shape,
                  draft.rules.map((r) => r.values.id),
                ),
              ],
            })
          }
        >
          Add rule
        </Button>
      </div>
    </div>
  )
}

function RuleFields({
  index,
  count,
  spec,
  rule,
  errors,
  selectors,
  onChange,
  onMove,
  onRemove,
}: {
  index: number
  count: number
  spec: ShapeSpec
  rule: RuleDraft
  errors?: Record<string, string>
  selectors?: string[]
  onChange: (values: Record<string, string>) => void
  onMove: (by: -1 | 1) => void
  onRemove: () => void
}) {
  const n = index + 1
  return (
    <fieldset className="fg-fieldset grid gap-4 rounded-md border border-line p-4">
      <legend className="px-1">{`Rule ${n}`}</legend>
      <div className="flex flex-wrap items-start gap-4">
        <div className="fg-fieldrow min-w-0 flex-1">
          <Field
            field={RULE_ID}
            rule={rule}
            error={errors?.id}
            onChange={onChange}
          />
          {spec.head.map((f) => (
            <Field
              key={keyOf(f)}
              field={f}
              rule={rule}
              error={errors?.[keyOf(f)]}
              onChange={onChange}
            />
          ))}
        </div>
        <div className="flex gap-1">
          <Button
            size="sm"
            variant="ghost"
            icon="ArrowUp"
            iconOnly
            disabled={index === 0}
            onClick={() => onMove(-1)}
          >
            {`Move rule ${n} up`}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon="ArrowDown"
            iconOnly
            disabled={index === count - 1}
            onClick={() => onMove(1)}
          >
            {`Move rule ${n} down`}
          </Button>
          <Button size="sm" variant="ghost" icon="Trash" iconOnly onClick={onRemove}>
            {`Remove rule ${n}`}
          </Button>
        </div>
      </div>
      {spec.groups.map((group) => (
        <Fieldset key={group.legend} legend={group.legend} description={group.description}>
          <div className="fg-fieldrow">
            {group.fields.map((f) => (
              <Field
                key={keyOf(f)}
                field={f}
                rule={rule}
                error={errors?.[keyOf(f)]}
                selectors={selectors}
                onChange={onChange}
              />
            ))}
          </div>
        </Fieldset>
      ))}
    </fieldset>
  )
}

function Field({
  field,
  rule,
  error,
  selectors,
  onChange,
}: {
  field: FieldSpec
  rule: RuleDraft
  error?: string
  selectors?: string[]
  onChange: (values: Record<string, string>) => void
}) {
  const key = keyOf(field)
  const value = rule.values[key]
  const set = (v: string) => onChange({ ...rule.values, [key]: v })
  if (field.kind === 'selector' && selectors) {
    return (
      <SelectField
        label={field.label}
        value={value}
        onChange={(e) => set(e.target.value)}
        description={field.description}
      >
        <option value="">Every package</option>
        {selectors.map((name) => (
          <option key={name} value={name}>
            {name}
          </option>
        ))}
        {/* A selector deleted since stays as loaded; the server refuses it. */}
        {value && !selectors.includes(value) && <option value={value}>{value}</option>}
      </SelectField>
    )
  }
  if (field.kind === 'select') {
    return (
      <SelectField
        label={field.label}
        value={value}
        onChange={(e) => set(e.target.value)}
        description={field.description}
      >
        {field.options?.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
        {/* A value this screen does not offer stays as it was loaded. */}
        {value && !field.options?.some((o) => o.value === value) && (
          <option value={value}>{value}</option>
        )}
      </SelectField>
    )
  }
  const numeric = field.kind === 'count' || field.kind === 'days'
  return (
    <TextField
      label={field.label}
      optional={field !== RULE_ID}
      mono
      inputMode={numeric ? 'numeric' : undefined}
      placeholder={field.placeholder}
      value={value}
      onChange={(e) => set(e.target.value)}
      error={error}
      description={field.description}
    />
  )
}
