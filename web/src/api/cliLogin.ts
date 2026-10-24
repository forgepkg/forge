import { queryOptions } from '@tanstack/react-query'

import { ApiError, httpClient } from '~/lib/httpClient'

/**
 * A command-line client's pending web login (`npm login`, which opens
 * `/cli-login/<secret>` in the browser): what the signed-in user approves or
 * refuses. The secret in the URL is the request's only handle.
 */
export interface CliLoginRequest {
  /** The client that asked: `npm`. */
  client: string
  /** The repository it signs in to. */
  repository: string
  /** The host name the client reported, if any. */
  hostname: string | null
  /** Where the request came from. */
  client_ip: string | null
  created_at: string
  expires_at: string
}

export const cliLoginKeys = {
  request: (secret: string) => ['cli-login', secret] as const,
}

function path(secret: string): string {
  return `/auth/cli-login/${encodeURIComponent(secret)}`
}

/** `GET /auth/cli-login/{secret}`; 404 once it is decided, expired or unknown. */
export function fetchCliLogin(secret: string, signal?: AbortSignal): Promise<CliLoginRequest> {
  return httpClient.get<CliLoginRequest>(path(secret), { signal })
}

export function cliLoginQueryOptions(secret: string) {
  return queryOptions<CliLoginRequest, ApiError>({
    queryKey: cliLoginKeys.request(secret),
    queryFn: ({ signal }) => fetchCliLogin(secret, signal),
    // A decided request is gone: never refetch it behind the user's back.
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    retry: false,
  })
}

/**
 * `POST /auth/cli-login/{secret}` — sign the client in as the current user
 * (`approve`), or refuse it. The client collects its token on its next poll.
 */
export function decideCliLogin(secret: string, approve: boolean): Promise<void> {
  return httpClient.post<void>(path(secret), { approve })
}
