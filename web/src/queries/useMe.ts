import { useQuery } from '@tanstack/react-query'

import { meQueryOptions } from '~/api/me'

/**
 * The current principal (`GET /admin/me`).
 *
 * Uses `useQuery` (not suspense) so the 401 -> login flow stays simple, and
 * never retries auth failures (401/403): a missing/invalid credential is a
 * terminal state the UI handles by routing to login, not by retrying. Shares
 * its cache entry + retry policy with the admin route guard via
 * `meQueryOptions`.
 */
export function useMe() {
  return useQuery(meQueryOptions)
}
