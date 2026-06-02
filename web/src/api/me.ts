import { httpClient } from '~/lib/httpClient'

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
