import type { TokenScope } from '~/api/tokens'
import { ACTIONS, type Action } from '~/api/rbac'
import { parseTokenScope } from '~/components/TokenBadges'
import { Checkbox, RadioGroup } from '~/components/ui'

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
 * The scope fields of a token form: which actions and which repositories,
 * side by side (stacked on narrow screens). Choosing "Only these …" opens
 * the checkboxes under it. `repositories` are those the picker offers (an
 * admin sees all of them; a user the ones they can read).
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
    <div className="fg-fieldrow">
      <div className="grid content-start gap-3">
        <RadioGroup
          legend="Actions"
          value={value.limitActions ? 'only' : 'owner'}
          onChange={(v) => onChange({ ...value, limitActions: v === 'only' })}
          options={[
            {
              value: 'owner',
              label: "The owner's read, write and delete",
              description: 'Never admin.',
            },
            { value: 'only', label: 'Only these actions' },
          ]}
        />
        {value.limitActions && (
          <div role="group" aria-label="Actions of the token" className="fg-choice-list pl-6">
            {ACTIONS.map((action) => {
              const disabled = action === 'admin' && value.limitRepositories
              return (
                <Checkbox
                  key={action}
                  label={action}
                  description={ACTION_HELP[action]}
                  checked={value.actions.includes(action) && !disabled}
                  disabled={disabled}
                  onChange={(c) => toggleAction(action, c)}
                />
              )
            })}
          </div>
        )}
      </div>

      <div className="grid content-start gap-3">
        <RadioGroup
          legend="Repositories"
          value={value.limitRepositories ? 'only' : 'all'}
          onChange={(v) => onChange({ ...value, limitRepositories: v === 'only' })}
          options={[
            { value: 'all', label: 'Every repository the owner can reach' },
            {
              value: 'only',
              label: 'Only these repositories',
              description: 'A group reaches only the members also chosen here.',
            },
          ]}
        />
        {value.limitRepositories && (
          <div
            role="group"
            aria-label="Repositories of the token"
            className="fg-choice-list max-h-60 overflow-y-auto pl-6"
          >
            {offered.length === 0 && unknown.length === 0 ? (
              <p className="fg-text">No repositories to choose from.</p>
            ) : (
              <>
                {offered.map((r) => (
                  <Checkbox
                    key={r.id}
                    label={r.name}
                    checked={value.repositories.includes(r.id)}
                    onChange={(c) => toggleRepository(r.id, c)}
                  />
                ))}
                {unknown.map((id) => (
                  <Checkbox
                    key={id}
                    label={`repository #${id}`}
                    checked
                    onChange={(c) => toggleRepository(id, c)}
                  />
                ))}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
