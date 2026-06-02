import { QueryClient } from '@tanstack/react-query'

import { ApiError } from './httpClient'

/**
 * The app-wide TanStack Query client. Auth failures (401/403) are never
 * retried — they are terminal states the UI resolves by routing to login.
 */
export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        retry: (failureCount, error) => {
          if (error instanceof ApiError && error.isAuthError) return false
          return failureCount < 2
        },
      },
    },
  })
}
