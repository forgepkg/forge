import { useState } from 'react'

import type { SelectorView } from '~/api/rbac'
import { useSelectorMatch } from '~/queries/useRbac'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import {
  Description,
  Field,
  FieldGroup,
  Fieldset,
  Label,
  Legend,
} from '~/components/catalyst/fieldset'
import { Input } from '~/components/catalyst/input'
import { Text } from '~/components/catalyst/text'
import { InlineError } from '~/components/RbacLabels'

/** What the form emits: lists without blank entries. */
export interface SelectorFormValues {
  name: string
  description: string
  includes: string[]
  excludes: string[]
}

/**
 * The create / edit form of a content selector. Includes and excludes are
 * edited as lists of globs on the lowercased package name; a test box asks
 * the server whether a package name matches the patterns as they stand in
 * the form, saved or not. A selector's name cannot change once created.
 */
export function SelectorForm({
  mode,
  existing,
  submitting,
  serverError,
  onSubmit,
  onCancel,
}: {
  mode: 'create' | 'edit'
  existing?: SelectorView
  submitting: boolean
  serverError?: string | null
  onSubmit: (values: SelectorFormValues) => void
  onCancel: () => void
}) {
  const [name, setName] = useState(existing?.name ?? '')
  const [description, setDescription] = useState(existing?.description ?? '')
  const [includes, setIncludes] = useState<string[]>(
    existing ? [...existing.includes] : [''],
  )
  const [excludes, setExcludes] = useState<string[]>(
    existing ? [...existing.excludes] : [],
  )

  const cleanIncludes = clean(includes)
  const cleanExcludes = clean(excludes)

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    onSubmit({
      name: name.trim(),
      description: description.trim(),
      includes: cleanIncludes,
      excludes: cleanExcludes,
    })
  }

  return (
    <form onSubmit={submit} className="space-y-8">
      <FieldGroup>
        <Field>
          <Label>Name</Label>
          <Input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            readOnly={mode === 'edit'}
            aria-readonly={mode === 'edit' ? 'true' : undefined}
            placeholder="e.g. acme-packages"
          />
          {mode === 'edit' && (
            <Description>A selector&apos;s name cannot change.</Description>
          )}
        </Field>
        <Field>
          <Label>Description</Label>
          <Input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
      </FieldGroup>

      <PatternList
        legend="Includes"
        description="Package names to match, as globs (* matches any run of characters, ? one). Names are matched in lower case."
        patterns={includes}
        onChange={setIncludes}
        placeholder="acme.*"
      />
      {cleanIncludes.length === 0 && (
        <p
          role="status"
          className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-sm/6 text-amber-800 dark:bg-amber-500/10 dark:text-amber-300"
        >
          An empty include list matches <strong>every package</strong>: a grant
          scoped by this selector then covers all packages but the excluded
          ones.
        </p>
      )}

      <PatternList
        legend="Excludes"
        description="Package names never matched, even when an include matches them."
        patterns={excludes}
        onChange={setExcludes}
        placeholder="acme.internal.*"
      />

      <MatchTest includes={cleanIncludes} excludes={cleanExcludes} />

      {serverError && <InlineError>{serverError}</InlineError>}

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={submitting || !name.trim()}>
          {submitting
            ? 'Saving…'
            : mode === 'create'
              ? 'Create selector'
              : 'Save'}
        </Button>
        <Button type="button" plain onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  )
}

function clean(patterns: string[]): string[] {
  return patterns.map((p) => p.trim()).filter((p) => p !== '')
}

/** An editable list of glob patterns. */
function PatternList({
  legend,
  description,
  patterns,
  onChange,
  placeholder,
}: {
  legend: string
  description: string
  patterns: string[]
  onChange: (patterns: string[]) => void
  placeholder: string
}) {
  return (
    <Fieldset>
      <Legend>{legend}</Legend>
      <Text>{description}</Text>
      <div className="mt-3 space-y-2">
        {patterns.map((p, i) => (
          <div key={i} className="flex items-center gap-2">
            <Input
              type="text"
              aria-label={`${legend} pattern ${i + 1}`}
              value={p}
              placeholder={placeholder}
              onChange={(e) =>
                onChange(patterns.map((q, j) => (j === i ? e.target.value : q)))
              }
            />
            <Button
              type="button"
              plain
              aria-label={`Remove ${legend.toLowerCase()} pattern ${i + 1}`}
              onClick={() => onChange(patterns.filter((_, j) => j !== i))}
            >
              Remove
            </Button>
          </div>
        ))}
      </div>
      <Button
        type="button"
        outline
        className="mt-2"
        onClick={() => onChange([...patterns, ''])}
      >
        Add {legend.toLowerCase().replace(/s$/, '')} pattern
      </Button>
    </Fieldset>
  )
}

/** The test box: does a package name match the patterns in the form? */
function MatchTest({
  includes,
  excludes,
}: {
  includes: string[]
  excludes: string[]
}) {
  const [name, setName] = useState('')
  const match = useSelectorMatch(includes, excludes, name)

  return (
    <Field>
      <Label>Test a package name</Label>
      <div className="flex items-center gap-3">
        <Input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Acme.Core"
        />
        <span role="status" className="shrink-0">
          {name.trim() === '' ? null : match.isError ? (
            <Badge color="red">{match.error.body || 'invalid pattern'}</Badge>
          ) : match.data == null || match.isFetching ? (
            <span className="text-sm/6 text-zinc-500 dark:text-zinc-400">
              Checking…
            </span>
          ) : match.data.matches ? (
            <Badge color="emerald">matches</Badge>
          ) : (
            <Badge color="zinc">does not match</Badge>
          )}
        </span>
      </div>
      <Description>
        Checked against the patterns above as they stand, before they are
        saved.
      </Description>
    </Field>
  )
}
