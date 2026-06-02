import { queryOptions } from '@tanstack/react-query'

import { httpClient, ApiError } from '~/lib/httpClient'

/**
 * `GET /admin/me` — the authenticated principal's identity + capability flags.
 * Mirrors the Rust `MeView` DTO (`crates/server/src/me.rs`). Drives nav
 * rendering + admin route gating.
 */
export interface MeUser {
  id: number
  username: string
  is_admin: boolean
  active: boolean
}

export interface Me {
  user: MeUser
  is_admin: boolean
  capabilities: string[]
}

/** Query-key factory for the current-user resource. */
export const meKeys = {
  self: () => ['me'] as const,
}

/** Fetch the current principal. Throws `ApiError(401)` when unauthenticated. */
export function fetchMe(): Promise<Me> {
  return httpClient.get<Me>('/admin/me')
}

/**
 * Shared TanStack Query options for the current-principal resource. Reused by
 * the `useMe` hook (rendering) and the router's admin `beforeLoad` guard
 * (`queryClient.ensureQueryData`), so both consult the same cache entry and an
 * auth failure (401/403) is never retried.
 */
export const meQueryOptions = queryOptions<Me, ApiError>({
  queryKey: meKeys.self(),
  queryFn: fetchMe,
  retry: (failureCount, error) => {
    if (error instanceof ApiError && error.isAuthError) return false
    return failureCount < 2
  },
})
