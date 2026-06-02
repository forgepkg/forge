import { useQuery } from '@tanstack/react-query'

import { fetchMe, meKeys, type Me } from '~/api/me'
import { ApiError } from '~/lib/httpClient'

/**
 * The current principal (`GET /admin/me`).
 *
 * Uses `useQuery` (not suspense) so the 401 -> login flow stays simple, and
 * never retries auth failures (401/403): a missing/invalid credential is a
 * terminal state the UI handles by routing to login, not by retrying.
 */
export function useMe() {
  return useQuery<Me, ApiError>({
    queryKey: meKeys.self(),
    queryFn: fetchMe,
    retry: (failureCount, error) => {
      if (error instanceof ApiError && error.isAuthError) return false
      return failureCount < 2
    },
  })
}
