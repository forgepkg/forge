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

type FieldKind = 'count' | 'days' | 'text' | 'tags' | 'select'

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
  description: 'A prerelease has a label after a dash, such as 2.0.0-beta.1.',
  options: [
    { value: 'any', label: 'Every version' },
    { value: 'releases', label: 'Releases only' },
    { value: 'prereleases', label: 'Prereleases only' },
  ],
}

const PACKAGE_PREFIX: FieldSpec = {
  path: ['package_name_prefix'],
  label: 'Package id prefix',
  kind: 'text',
  placeholder: 'acme.',
  description: 'Only packages whose id starts with this, ignoring case. Empty: every package.',
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
      { legend: 'Versions it looks at', fields: [RELEASE_TYPE, PACKAGE_PREFIX] },
      {
        legend: 'Always keep',
        description:
          'Per package, among the versions above. A version any rule keeps is never unlisted or deleted.',
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
      { legend: 'Versions it looks at', fields: [RELEASE_TYPE, PACKAGE_PREFIX] },
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
            placeholder: 'latest, stable',
            description: 'Never deleted by this rule. Separate them with commas or spaces.',
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
  interval: string
  intervalUnit: IntervalUnit
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
      interval: '1',
      intervalUnit: 'hours',
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
  return {
    base: structuredClone(base),
    enabled: policy.enabled ?? true,
    dryRunOnly: policy.dry_run_only ?? false,
    interval: interval.value,
    intervalUnit: interval.unit,
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
  sizeBudgetMax?: string
  sizeBudgetTarget?: string
  /** A message for the rules as a whole. */
  rules?: string
  /** Per rule key, per field key. */
  fields: Record<number, Record<string, string>>
}

const WHOLE = /^\d+$/
const DECIMAL = /^\d+(\.\d+)?$/

/** The browser's checks; `null` when the form can be sent. */
export function validateDraft(shape: PolicyShape, draft: PolicyDraft): DraftErrors | null {
  const errors: DraftErrors = { fields: {} }
  let failed = false
  const interval = draft.interval.trim()
  if (!WHOLE.test(interval) || Number(interval) < 1) {
    errors.interval = 'Enter a whole number of at least 1.'
    failed = true
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
      } else if (field.kind === 'text' && raw === '' && field !== RULE_ID) {
        value = undefined
      } else {
        value = raw
      }
      setPath(json, field.path, value)
    }
    return json as unknown as RetentionRule
  })
  const base = structuredClone(draft.base)
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

const REASONS: Record<string, (n: number) => string> = {
  older_than_days: (n) => `older than ${days(n)}`,
  not_downloaded_for_days: (n) => `not downloaded for ${days(n)}`,
  not_pulled_for_days: (n) => `not pulled for ${days(n)}`,
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
    .map(([key, phrase]) => phrase(reason[key] as number))
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
  onChange,
}: {
  shape: PolicyShape
  draft: PolicyDraft
  errors: DraftErrors | null
  currentSizeBytes?: number
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
          <option value="minutes">Minutes</option>
          <option value="hours">Hours</option>
          <option value="days">Days</option>
          <option value="seconds">Seconds</option>
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
  onChange,
  onMove,
  onRemove,
}: {
  index: number
  count: number
  spec: ShapeSpec
  rule: RuleDraft
  errors?: Record<string, string>
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
  onChange,
}: {
  field: FieldSpec
  rule: RuleDraft
  error?: string
  onChange: (values: Record<string, string>) => void
}) {
  const key = keyOf(field)
  const value = rule.values[key]
  const set = (v: string) => onChange({ ...rule.values, [key]: v })
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
