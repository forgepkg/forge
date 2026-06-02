import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { createFileRoute, useRouter, useSearch } from '@tanstack/react-router'

import { fetchMe, meKeys } from '~/api/me'
import { ApiError } from '~/lib/httpClient'
import { clearToken, setToken } from '~/lib/auth'

interface LoginSearch {
  /** Where to return after a successful sign-in (set by the admin guard). */
  redirect?: string
  /** Set when the session expired mid-use (the guard / a 401 redirected here). */
  expired?: boolean
}

export const Route = createFileRoute('/login')({
  component: Login,
  validateSearch: (search: Record<string, unknown>): LoginSearch => ({
    redirect: typeof search.redirect === 'string' ? search.redirect : undefined,
    expired: search.expired === true || search.expired === 'true',
  }),
})

/**
 * Sign-in screen. Today (slice 1) the user pastes a registry token; we verify it
 * by calling `GET /admin/me` and only persist it once the API accepts it, so an
 * invalid token never poisons the stored credential. The OIDC button is a stub
 * for §12.2 — when sessions land, this screen swaps to an OIDC redirect and the
 * token field goes away, touching only this file plus `auth.ts`.
 */
function Login() {
  const router = useRouter()
  const queryClient = useQueryClient()
  const { redirect, expired } = useSearch({ from: '/login' })

  const [token, setTokenValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = token.trim()
    if (!trimmed) {
      setError('Enter a registry token.')
      return
    }
    setSubmitting(true)
    setError(null)
    // Store first so the verification request carries the credential, then roll
    // back if the API rejects it.
    setToken(trimmed)
    try {
      const me = await fetchMe()
      queryClient.setQueryData(meKeys.self(), me)
      void router.navigate({ to: redirect ?? '/' })
    } catch (err) {
      clearToken()
      queryClient.removeQueries({ queryKey: meKeys.self() })
      setError(
        err instanceof ApiError && err.isAuthError
          ? 'That token was not accepted. Check it and try again.'
          : 'Could not verify the token. Is the server reachable?',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6 py-12">
      <div className="mb-8 text-center">
        <h1 className="text-2xl font-semibold text-slate-900">envisia&nbsp;forge</h1>
        <p className="mt-1 text-sm text-slate-500">Sign in to the package registry</p>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
        {expired && (
          <p
            role="alert"
            className="mb-4 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800"
          >
            Your session expired. Sign in again to continue.
          </p>
        )}

        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="forge-token"
              className="block text-sm font-medium text-slate-700"
            >
              Registry token
            </label>
            <input
              id="forge-token"
              type="password"
              autoComplete="off"
              autoFocus
              value={token}
              onChange={(e) => setTokenValue(e.target.value)}
              placeholder="Paste your token"
              className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
            />
            <p className="mt-1 text-xs text-slate-500">
              Create a token from the Tokens screen, or use one provided out of band.
            </p>
          </div>

          {error && (
            <p role="alert" className="text-sm text-red-600">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-60"
          >
            {submitting ? 'Verifying…' : 'Sign in'}
          </button>
        </form>

        <div className="my-5 flex items-center gap-3 text-xs uppercase tracking-wide text-slate-400">
          <span className="h-px flex-1 bg-slate-200" />
          or
          <span className="h-px flex-1 bg-slate-200" />
        </div>

        <button
          type="button"
          disabled
          title="Available once OIDC sessions ship (§12.2)"
          className="w-full cursor-not-allowed rounded border border-slate-300 px-3 py-2 text-sm font-medium text-slate-400"
        >
          Sign in with OIDC (coming soon)
        </button>
      </div>
    </div>
  )
}
