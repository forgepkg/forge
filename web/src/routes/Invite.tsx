import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute, Link, useNavigate, useRouterState } from '@tanstack/react-router'

import {
  acceptInvitation,
  INVALID_INVITATION,
  invitationPasswordProblem,
  lookupInvitation,
  MIN_INVITATION_PASSWORD_CHARS,
} from '~/api/auth'
import { ApiError } from '~/lib/httpClient'
import { AuthCard } from '~/components/AuthCard'
import { Button, Icon, Notice, Skeleton, TextField } from '~/components/ui'

export const Route = createFileRoute('/invite')({
  component: Invite,
})

/** The server's reason for a refused request, or the generic answer. */
function reason(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 429) return 'Too many failed attempts. Try again in a few minutes.'
    try {
      const parsed = JSON.parse(e.body) as { error?: string }
      if (parsed.error) return parsed.error
    } catch {
      // Not JSON.
    }
    if (e.status === 400) return INVALID_INVITATION
  }
  return 'Could not reach the server. Try again.'
}

/**
 * An invited user's page (#322): the link `/invite#<token>` names the
 * account, and its user chooses the password (twice) here, then signs in.
 * The token rides in the fragment, which reaches no server log; the page
 * sends it in request bodies only. A link that does not work gets one
 * generic answer, which says nothing of the account.
 */
function Invite() {
  const token = useRouterState({ select: (s) => s.location.hash.replace(/^#/, '') })
  const navigate = useNavigate()
  const lookup = useQuery({
    queryKey: ['invitation', token],
    queryFn: () => lookupInvitation(token),
    enabled: token !== '',
    retry: false,
    staleTime: Infinity,
  })
  const accept = useMutation({
    mutationFn: (password: string) => acceptInvitation(token, password),
    onSuccess: ({ username }) =>
      void navigate({ to: '/login', search: { username, invited: true } }),
  })
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [problem, setProblem] = useState<string | null>(null)

  function submit(e: React.FormEvent) {
    e.preventDefault()
    const why = invitationPasswordProblem(password, confirm)
    setProblem(why)
    if (why) return
    accept.mutate(password)
  }

  const invalid = token === '' || lookup.isError

  return (
    <AuthCard
      title="Choose your password"
      subtitle={
        lookup.data && (
          <>
            For your Forge account <span className="fg-strong">{lookup.data.username}</span>
          </>
        )
      }
    >
      {invalid ? (
        <Notice
          tone="danger"
          action={
            <Link to="/login" className="fg-notice-action">
              Sign in
            </Link>
          }
        >
          {token === '' ? INVALID_INVITATION : reason(lookup.error)}
        </Notice>
      ) : !lookup.data ? (
        <Skeleton lines={2} label="Checking the invitation…" />
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-4" aria-label="Choose your password">
          <TextField
            label="Password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            description={`At least ${MIN_INVITATION_PASSWORD_CHARS} characters.`}
          />
          <TextField
            label="Password again"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
          {(problem || accept.isError) && (
            <p role="alert" className="fg-field-error">
              <Icon name="Alert" size={14} />
              <span>{problem ?? reason(accept.error)}</span>
            </p>
          )}
          <Button type="submit" variant="primary" block disabled={accept.isPending}>
            {accept.isPending ? 'Saving…' : 'Set password'}
          </Button>
        </form>
      )}
    </AuthCard>
  )
}
