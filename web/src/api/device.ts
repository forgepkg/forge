import { queryOptions } from '@tanstack/react-query'

import { ApiError, httpClient } from '~/lib/httpClient'

/**
 * The device login (RFC 8628): a command-line client (`forge login`,
 * `docker-credential-forge`, `nuget-plugin-forge`) shows its user a code and
 * the address of the `/device` page, where the signed-in user enters the code,
 * checks what asks for what, and approves or denies it. The client polls the
 * server and receives a token once approved.
 *
 * The code goes in request bodies, never in an API path:
 *  - `POST /auth/device/lookup` answers the pending request a code names
 *    (404 when none is pending: mistyped, expired or answered already);
 *  - `POST /auth/device/decide` approves or denies it (204, or 404).
 * Both answer 400 for something that cannot be a code and 429 after too many
 * wrong codes from the network or the session.
 */

/** What the token of an approved request may do. */
export interface DeviceScope {
  /** The highest level it keeps; `null`: the user's levels. */
  level: 'read' | 'write' | 'delete' | null
  /** The repositories it reaches, by name; empty: every one the user may. */
  repositories: string[]
}

/** A pending device login, as the `/device` page shows it. */
export interface DeviceRequest {
  /** The code as the client's terminal shows it (`BCDF-GHJK`). */
  user_code: string
  client_id: string
  /** The client's name (`Docker credential helper`). */
  client_name: string | null
  /** `null`: the token carries the user's rights. */
  scope: DeviceScope | null
  /** Where the client asked from. */
  client_ip: string | null
  created_at: string
  expires_at: string
}

/** The code alphabet: consonants only, no look-alikes. */
const CODE_LETTERS = /^[BCDFGHJKLMNPQRSTVWXZ]{8}$/

/**
 * `raw` as a code (`BCDF-GHJK`): in any case, with or without the hyphen and
 * spaces. `null` when it cannot be one.
 */
export function normalizeUserCode(raw: string): string | null {
  const letters = raw.replace(/[\s-]/g, '').toUpperCase()
  if (!CODE_LETTERS.test(letters)) return null
  return `${letters.slice(0, 4)}-${letters.slice(4)}`
}

export const deviceKeys = {
  /** A lookup of `code`; each `attempt` is one of its own. */
  request: (code: string, attempt: number) => ['device', code, attempt] as const,
}

/** `POST /auth/device/lookup`. */
export function lookupDeviceCode(code: string, signal?: AbortSignal): Promise<DeviceRequest> {
  return httpClient.post<DeviceRequest>('/auth/device/lookup', { user_code: code }, { signal })
}

/**
 * The lookup of `code`. Entering the code again is another `attempt`, so a
 * code that was not found is looked up again rather than answered from the
 * failed lookup.
 */
export function deviceRequestQueryOptions(code: string, attempt = 0) {
  return queryOptions<DeviceRequest, ApiError>({
    queryKey: deviceKeys.request(code, attempt),
    queryFn: ({ signal }) => lookupDeviceCode(code, signal),
    // Each lookup counts against the wrong-code limit, and a decided request
    // is gone: never refetch behind the user's back.
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: false,
  })
}

/**
 * `POST /auth/device/decide` — sign the client in as the current user
 * (`approve`), or deny it. The client collects its token on its next poll.
 */
export function decideDeviceCode(code: string, approve: boolean): Promise<void> {
  return httpClient.post<void>('/auth/device/decide', { user_code: code, approve })
}
