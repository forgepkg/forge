import { useState, type ReactNode } from 'react'

import type { CreateToken } from '~/api/tokens'
import { Button, Panel, SelectField, TextField } from '~/components/ui'
import {
  draftProblem,
  scopeFromDraft,
  TokenScopeFields,
  UNSCOPED,
  type ScopeDraft,
} from '~/components/TokenScopeFields'

/**
 * The "New token" panel of the self-service and the admin token screens: a
 * name, expiry and scope, with Create token at the end. It is a whole panel
 * (a `Panel` form), so callers place it as it is. An unscoped token is sent
 * without `scope`, and a non-expiring token without `expires_at`. `onSubmit`
 * gets a `reset` to call once the token was created.
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
  const [expiry, setExpiry] = useState<ExpiryChoice>('90-days')
  const [customDate, setCustomDate] = useState('')
  const problem = draftProblem(scope)
  const customDateProblem =
    expiry === 'custom' && (!customDate || customDate <= minimumCustomDate())
      ? 'Choose a date in the future.'
      : null

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim() || problem || customDateProblem) return
    const s = scopeFromDraft(scope)
    onSubmit(
      {
        name: name.trim(),
        ...(expiry === 'never' ? {} : { expires_at: expiryDate(expiry, customDate) }),
        ...(s ? { scope: s } : {}),
      },
      () => {
        setName('')
        setScope(UNSCOPED)
        setExpiry('90-days')
        setCustomDate('')
      },
    )
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
            disabled={submitting || !name.trim() || !!problem || !!customDateProblem}
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
        <SelectField
          label="Token expiry"
          value={expiry}
          onChange={(e) => setExpiry(e.target.value as ExpiryChoice)}
          description={
            expiry === 'never'
              ? 'This token stays valid until it is revoked.'
              : 'Choose when this token stops working.'
          }
        >
          <option value="30-days">30 days</option>
          <option value="90-days">90 days</option>
          <option value="1-year">1 year</option>
          <option value="custom">Custom date</option>
          <option value="never">No expiry</option>
        </SelectField>
        {expiry === 'custom' && (
          <TextField
            label="Expiry date"
            type="date"
            value={customDate}
            min={minimumCustomDate()}
            onChange={(e) => setCustomDate(e.target.value)}
            error={customDateProblem ?? undefined}
          />
        )}
      </div>
      <TokenScopeFields value={scope} onChange={setScope} repositories={repositories} />
    </Panel>
  )
}

type ExpiryChoice = '30-days' | '90-days' | '1-year' | 'custom' | 'never'

function minimumCustomDate(): string {
  const tomorrow = new Date()
  tomorrow.setUTCDate(tomorrow.getUTCDate() + 1)
  return tomorrow.toISOString().slice(0, 10)
}

function expiryDate(choice: Exclude<ExpiryChoice, 'never'>, customDate: string): string {
  if (choice === 'custom') return `${customDate}T23:59:59.999Z`
  const date = new Date()
  if (choice === '1-year') date.setUTCFullYear(date.getUTCFullYear() + 1)
  else date.setUTCDate(date.getUTCDate() + (choice === '30-days' ? 30 : 90))
  return date.toISOString()
}
