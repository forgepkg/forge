import { useId, useState } from 'react'

import type { SelectorView } from '~/api/rbac'
import { useSelectorMatch } from '~/queries/useRbac'
import {
  Button,
  Fieldset,
  FormActions,
  Input,
  Notice,
  Panel,
  StatusBadge,
  TextField,
} from '~/components/ui'
import { InlineError } from '~/components/RbacLabels'

/** What the form emits: lists without blank entries. */
export interface SelectorFormValues {
  name: string
  description: string
  includes: string[]
  excludes: string[]
}

/**
 * The create / edit form of a content selector: a General panel (name and
 * description) and a Patterns panel, with the buttons at the end. Includes
 * and excludes are edited as lists of globs on the lowercased package name;
 * a test box asks the server whether a package name matches the patterns as
 * they stand in the form, saved or not. A selector's name cannot change once
 * created.
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
    <form onSubmit={submit} className="grid gap-6">
      <Panel title="General">
        <div className="fg-form">
          <TextField
            label="Name"
            type="text"
            mono
            value={name}
            onChange={(e) => setName(e.target.value)}
            readOnly={mode === 'edit'}
            aria-readonly={mode === 'edit' ? 'true' : undefined}
            placeholder="e.g. acme-packages"
            description={
              mode === 'edit' ? "A selector's name cannot change." : undefined
            }
          />
          <TextField
            label="Description"
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
      </Panel>

      <Panel
        title="Patterns"
        description="Excludes win over includes; an empty include list matches every package."
      >
        <div className="fg-form">
          <PatternList
            legend="Includes"
            description="Package names to match, as globs (* matches any run of characters, ? one). Names are matched in lower case."
            patterns={includes}
            onChange={setIncludes}
            placeholder="acme.*"
          />
          {cleanIncludes.length === 0 && <EveryPackageWarning />}
          <PatternList
            legend="Excludes"
            description="Package names never matched, even when an include matches them."
            patterns={excludes}
            onChange={setExcludes}
            placeholder="acme.internal.*"
          />
          <hr className="fg-divider" />
          <MatchTest includes={cleanIncludes} excludes={cleanExcludes} />
        </div>
      </Panel>

      {serverError && <InlineError>{serverError}</InlineError>}

      <FormActions>
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={submitting || !name.trim()}>
          {submitting
            ? 'Saving…'
            : mode === 'create'
              ? 'Create selector'
              : 'Save'}
        </Button>
      </FormActions>
    </form>
  )
}

function clean(patterns: string[]): string[] {
  return patterns.map((p) => p.trim()).filter((p) => p !== '')
}

/**
 * The warning that an empty include list matches every package, announced
 * politely (`role="status"`) since it comes and goes while the reader types.
 */
function EveryPackageWarning() {
  return (
    <Notice tone="warn" role="status">
      An empty include list matches <strong>every package</strong>: a grant
      scoped by this selector then covers all packages but the excluded ones.
    </Notice>
  )
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
    <Fieldset legend={legend} description={description}>
      {patterns.length > 0 && (
        <div className="grid gap-2">
          {patterns.map((p, i) => (
            <div key={i} className="flex items-center gap-2">
              <Input
                type="text"
                mono
                aria-label={`${legend} pattern ${i + 1}`}
                value={p}
                placeholder={placeholder}
                onChange={(e) =>
                  onChange(patterns.map((q, j) => (j === i ? e.target.value : q)))
                }
              />
              <Button
                variant="ghost"
                icon="X"
                iconOnly
                aria-label={`Remove ${legend.toLowerCase()} pattern ${i + 1}`}
                onClick={() => onChange(patterns.filter((_, j) => j !== i))}
              >
                Remove
              </Button>
            </div>
          ))}
        </div>
      )}
      <div>
        <Button size="sm" icon="Plus" onClick={() => onChange([...patterns, ''])}>
          Add {legend.toLowerCase().replace(/s$/, '')} pattern
        </Button>
      </div>
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
  const id = useId()
  const [name, setName] = useState('')
  const match = useSelectorMatch(includes, excludes, name)

  return (
    <div className="fg-field">
      <label htmlFor={id} className="fg-label">
        Test a package name
      </label>
      <div className="flex flex-wrap items-center gap-3">
        <Input
          id={id}
          type="text"
          mono
          className="min-w-0 flex-1"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Acme.Core"
          aria-describedby={`${id}-desc`}
        />
        <span role="status" className="shrink-0">
          {name.trim() === '' ? null : match.isError ? (
            <StatusBadge tone="danger">{match.error.body || 'invalid pattern'}</StatusBadge>
          ) : match.data == null || match.isFetching ? (
            <span className="fg-field-desc">Checking…</span>
          ) : match.data.matches ? (
            <StatusBadge tone="ok">matches</StatusBadge>
          ) : (
            <StatusBadge tone="neutral">does not match</StatusBadge>
          )}
        </span>
      </div>
      <p id={`${id}-desc`} className="fg-field-desc">
        Checked against the patterns above as they stand, before they are saved.
      </p>
    </div>
  )
}
