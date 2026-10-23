import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute, Link, useNavigate, useRouterState } from '@tanstack/react-router'

import {
  acceptInvitation,
  INVALID_INVITATION,
  lookupInvitation,
  MIN_INVITATION_PASSWORD_CHARS,
} from '~/api/auth'
import { ApiError } from '~/lib/httpClient'
import { AuthLayout } from '~/components/catalyst/auth-layout'
import { Button } from '~/components/catalyst/button'
import { Description, Field, Label } from '~/components/catalyst/fieldset'
import { Heading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Text } from '~/components/catalyst/text'

export const Route = createFileRoute('/invite')({
  component: Invite,
})

/** The most bytes a chosen password has (the server's limit). */
const MAX_PASSWORD_BYTES = 1024

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
    if ([...password].length < MIN_INVITATION_PASSWORD_CHARS) {
      setProblem(`Choose at least ${MIN_INVITATION_PASSWORD_CHARS} characters.`)
      return
    }
    if (new TextEncoder().encode(password).length > MAX_PASSWORD_BYTES) {
      setProblem('That password is too long.')
      return
    }
    if (password !== confirm) {
      setProblem('The two passwords differ.')
      return
    }
    setProblem(null)
    accept.mutate(password)
  }

  const invalid = token === '' || lookup.isError

  return (
    <AuthLayout>
      <div className="w-full max-w-sm space-y-8">
        <div className="space-y-2 text-center">
          <Heading className="!text-2xl">Choose your password</Heading>
          {lookup.data && (
            <Text>
              For your Forge account{' '}
              <span className="font-medium text-zinc-950 dark:text-white">
                {lookup.data.username}
              </span>
            </Text>
          )}
        </div>

        {invalid ? (
          <div
            role="alert"
            className="space-y-1 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm/6 text-red-700 dark:text-red-400"
          >
            <p>{token === '' ? INVALID_INVITATION : reason(lookup.error)}</p>
            <Link to="/login" className="font-medium underline hover:no-underline">
              Sign in
            </Link>
          </div>
        ) : !lookup.data ? (
          <Text>Checking the invitation…</Text>
        ) : (
          <form onSubmit={submit} className="space-y-6" aria-label="Choose your password">
            <Field>
              <Label>Password</Label>
              <Input
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <Description>At least {MIN_INVITATION_PASSWORD_CHARS} characters.</Description>
            </Field>
            <Field>
              <Label>Password again</Label>
              <Input
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
            </Field>
            {(problem || accept.isError) && (
              <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
                {problem ?? reason(accept.error)}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={accept.isPending}>
              {accept.isPending ? 'Saving…' : 'Set password'}
            </Button>
          </form>
        )}
      </div>
    </AuthLayout>
  )
}
