import { useState, type ReactNode } from 'react'

import type { CreateToken } from '~/api/tokens'
import { Button, Panel, TextField } from '~/components/ui'
import {
  draftProblem,
  scopeFromDraft,
  TokenScopeFields,
  UNSCOPED,
  type ScopeDraft,
} from '~/components/TokenScopeFields'

/**
 * The "New token" panel of the self-service and the admin token screens: a
 * name and the token's scope, with Create token at the end. It is a whole
 * panel (a `Panel` form), so callers place it as it is. An unscoped token is
 * sent without `scope`. `onSubmit` gets a `reset` to call once the token was
 * created.
 */
export function TokenCreateForm({
  repositories,
  submitting,
  placeholder,
  description = 'Name it after the machine or pipeline that uses it, so you know what breaks when you revoke it.',
  onSubmit,
}: {
  repositories: ReadonlyArray<{ id: number; name: string }>
  submitting: boolean
  placeholder: string
  description?: ReactNode
  onSubmit: (body: CreateToken, reset: () => void) => void
}) {
  const [name, setName] = useState('')
  const [scope, setScope] = useState<ScopeDraft>(UNSCOPED)
  const problem = draftProblem(scope)

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim() || problem) return
    const s = scopeFromDraft(scope)
    onSubmit({ name: name.trim(), ...(s ? { scope: s } : {}) }, () => {
      setName('')
      setScope(UNSCOPED)
    })
  }

  return (
    <Panel
      as="form"
      onSubmit={submit}
      title="New token"
      description={description}
      footer={
        <>
          {problem && <p className="fg-field-desc mr-auto self-center">{problem}</p>}
          <Button
            type="submit"
            variant="primary"
            icon="Plus"
            disabled={submitting || !name.trim() || !!problem}
          >
            {submitting ? 'Creating…' : 'Create token'}
          </Button>
        </>
      }
    >
      <div className="fg-form">
        <TextField
          label="Token name"
          type="text"
          mono
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={placeholder}
        />
      </div>
      <TokenScopeFields value={scope} onChange={setScope} repositories={repositories} />
    </Panel>
  )
}
