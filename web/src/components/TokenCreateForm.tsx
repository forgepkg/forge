import { useState } from 'react'

import type { CreateToken } from '~/api/tokens'
import { Button } from '~/components/catalyst/button'
import { Field, Label } from '~/components/catalyst/fieldset'
import { Input } from '~/components/catalyst/input'
import { Text } from '~/components/catalyst/text'
import {
  draftProblem,
  scopeFromDraft,
  TokenScopeFields,
  UNSCOPED,
  type ScopeDraft,
} from '~/components/TokenScopeFields'

/**
 * The create-token form of the self-service and the admin token screens: a
 * name and the token's scope. An unscoped token is sent without `scope`.
 * `onSubmit` gets a `reset` to call once the token was created.
 */
export function TokenCreateForm({
  repositories,
  submitting,
  placeholder,
  onSubmit,
}: {
  repositories: ReadonlyArray<{ id: number; name: string }>
  submitting: boolean
  placeholder: string
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
    <form
      onSubmit={submit}
      className="space-y-6 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <Field>
        <Label>Token name</Label>
        <Input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={placeholder}
        />
      </Field>
      <TokenScopeFields
        value={scope}
        onChange={setScope}
        repositories={repositories}
      />
      {problem && <Text>{problem}</Text>}
      <Button type="submit" disabled={submitting || !name.trim() || !!problem}>
        {submitting ? 'Creating…' : 'Create token'}
      </Button>
    </form>
  )
}
