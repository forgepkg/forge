import type { TokenScope } from '~/api/tokens'
import { ACTIONS, type Action } from '~/api/rbac'
import { Checkbox, CheckboxField, CheckboxGroup } from '~/components/catalyst/checkbox'
import { Description, Fieldset, Label, Legend } from '~/components/catalyst/fieldset'
import { Radio, RadioField, RadioGroup } from '~/components/catalyst/radio'
import { Text } from '~/components/catalyst/text'
import { parseTokenScope } from '~/components/TokenBadges'

/**
 * The scope of a token being created or changed, as a form edits it. A scope
 * only narrows the owner's access: without one the token carries the owner's
 * read, write and delete (never admin) on every repository the owner can
 * reach.
 */
export interface ScopeDraft {
  /** `false`: the owner's read / write / delete; `true`: `actions` only. */
  limitActions: boolean
  actions: Action[]
  /** `false`: every repository the owner reaches; `true`: `repositories` only. */
  limitRepositories: boolean
  repositories: number[]
}

export const UNSCOPED: ScopeDraft = {
  limitActions: false,
  actions: ['read'],
  limitRepositories: false,
  repositories: [],
}

/** The draft of a stored scope (`null`, or one that does not parse: unscoped). */
export function draftFromScope(scope: unknown): ScopeDraft {
  const parsed = parseTokenScope(scope)
  if (parsed == null || parsed === 'invalid') return UNSCOPED
  return {
    limitActions: parsed.actions !== undefined,
    actions: (parsed.actions ?? ['read']) as Action[],
    limitRepositories: parsed.repositories !== undefined,
    repositories: parsed.repositories ?? [],
  }
}

/**
 * The scope to send: `null` for an unscoped token. `admin` is dropped with a
 * repository restriction, where the server would not keep it anyway.
 */
export function scopeFromDraft(draft: ScopeDraft): TokenScope | null {
  if (!draft.limitActions && !draft.limitRepositories) return null
  const scope: TokenScope = {}
  if (draft.limitActions) {
    scope.actions = ACTIONS.filter(
      (a) =>
        draft.actions.includes(a) &&
        !(a === 'admin' && draft.limitRepositories),
    )
  }
  if (draft.limitRepositories) scope.repositories = [...draft.repositories]
  return scope
}

/** Why the draft cannot be saved, or `null`. */
export function draftProblem(draft: ScopeDraft): string | null {
  if (draft.limitActions && (scopeFromDraft(draft)?.actions ?? []).length === 0) {
    return 'Choose at least one action.'
  }
  if (draft.limitRepositories && draft.repositories.length === 0) {
    return 'Choose at least one repository.'
  }
  return null
}

const ACTION_HELP: Record<Action, string> = {
  read: 'Download and browse packages and images.',
  write: 'Push packages and images.',
  delete: 'Delete (and, where allowed, overwrite) versions.',
  admin:
    'Call the admin API, when the owner is an administrator. Only with every repository.',
}

/**
 * The scope fields of a token form: which actions and which repositories.
 * `repositories` are those the picker offers (an admin sees all of them; a
 * user the ones they can read).
 */
export function TokenScopeFields({
  value,
  onChange,
  repositories,
}: {
  value: ScopeDraft
  onChange: (draft: ScopeDraft) => void
  repositories: ReadonlyArray<{ id: number; name: string }>
}) {
  function toggleAction(action: Action, on: boolean) {
    const actions = on
      ? [...value.actions, action]
      : value.actions.filter((a) => a !== action)
    onChange({ ...value, actions })
  }
  function toggleRepository(id: number, on: boolean) {
    const repos = on
      ? [...value.repositories, id]
      : value.repositories.filter((r) => r !== id)
    onChange({ ...value, repositories: repos })
  }
  // A scope may name a repository the picker does not offer (deleted, or no
  // longer readable): keep it listed so it is not dropped unseen.
  const offered = [...repositories].sort((a, b) => a.name.localeCompare(b.name))
  const unknown = value.repositories.filter(
    (id) => !repositories.some((r) => r.id === id),
  )

  return (
    <div className="grid gap-6 sm:grid-cols-2">
      <Fieldset>
        <Legend>Actions</Legend>
        <RadioGroup
          value={value.limitActions ? 'only' : 'owner'}
          onChange={(v) => onChange({ ...value, limitActions: v === 'only' })}
        >
          <RadioField>
            <Radio value="owner" />
            <Label>The owner&apos;s read, write and delete</Label>
            <Description>Never admin.</Description>
          </RadioField>
          <RadioField>
            <Radio value="only" />
            <Label>Only these actions</Label>
          </RadioField>
        </RadioGroup>
        {value.limitActions && (
          <CheckboxGroup className="mt-3 pl-6">
            {ACTIONS.map((action) => {
              const disabled = action === 'admin' && value.limitRepositories
              return (
                <CheckboxField key={action} disabled={disabled}>
                  <Checkbox
                    checked={value.actions.includes(action) && !disabled}
                    onChange={(c) => toggleAction(action, c)}
                  />
                  <Label>{action}</Label>
                  <Description>{ACTION_HELP[action]}</Description>
                </CheckboxField>
              )
            })}
          </CheckboxGroup>
        )}
      </Fieldset>

      <Fieldset>
        <Legend>Repositories</Legend>
        <RadioGroup
          value={value.limitRepositories ? 'only' : 'all'}
          onChange={(v) =>
            onChange({ ...value, limitRepositories: v === 'only' })
          }
        >
          <RadioField>
            <Radio value="all" />
            <Label>Every repository the owner can reach</Label>
          </RadioField>
          <RadioField>
            <Radio value="only" />
            <Label>Only these repositories</Label>
            <Description>
              A group reaches only the members also chosen here.
            </Description>
          </RadioField>
        </RadioGroup>
        {value.limitRepositories && (
          <div className="mt-3 max-h-60 overflow-y-auto pl-6">
            {offered.length === 0 && unknown.length === 0 ? (
              <Text>No repositories to choose from.</Text>
            ) : (
              <CheckboxGroup>
                {offered.map((r) => (
                  <CheckboxField key={r.id}>
                    <Checkbox
                      checked={value.repositories.includes(r.id)}
                      onChange={(c) => toggleRepository(r.id, c)}
                    />
                    <Label className="font-mono">{r.name}</Label>
                  </CheckboxField>
                ))}
                {unknown.map((id) => (
                  <CheckboxField key={id}>
                    <Checkbox
                      checked
                      onChange={(c) => toggleRepository(id, c)}
                    />
                    <Label>repository #{id}</Label>
                  </CheckboxField>
                ))}
              </CheckboxGroup>
            )}
          </div>
        )}
      </Fieldset>
    </div>
  )
}
