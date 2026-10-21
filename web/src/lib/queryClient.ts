import { QueryClient } from '@tanstack/react-query'

import { ApiError } from './httpClient'

/**
 * The app-wide TanStack Query client. Auth failures (401/403) are never
 * retried — they are terminal states the UI resolves by routing to login.
 * Neither is a 503 carrying `Retry-After` (an offline repository): the server
 * says when to come back, and retrying within seconds only delays the
 * message.
 */
export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        retry: (failureCount, error) => {
          if (error instanceof ApiError && error.isAuthError) return false
          if (
            error instanceof ApiError &&
            error.status === 503 &&
            error.retryAfterSeconds !== undefined
          ) {
            return false
          }
          return failureCount < 2
        },
      },
    },
  })
}
