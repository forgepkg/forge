import { httpClient } from '~/lib/httpClient'

/**
 * Admin auth settings API (`/admin/settings/auth`): the sign-in and
 * anonymous-access policy, kept in the database and applied by every
 * instance without a restart.
 *
 *  - `GET` answers every setting.
 *  - `PUT` changes the fields the body names (the others keep their value)
 *    and answers the settings as stored. A wrong value is a 400 whose body
 *    says what is wrong.
 */

/** Who is served without credentials. */
export type AnonymousMode = 'off' | 'allowlist' | 'all'

/** What the login screen asks for first. */
export type LoginMode = 'identifier_first' | 'combined'

/** The settings (`GET /admin/settings/auth`). */
export interface AuthSettings {
  anonymous_mode: AnonymousMode
  /** `loopback`, `private`, `local`, CIDRs and single addresses. */
  anonymous_ip_allowlist: string[]
  login_mode: LoginMode
  /** Accept a user's password over HTTP Basic on the feeds. */
  allow_password_basic: boolean
  session_idle_ttl_seconds: number
  session_absolute_ttl_seconds: number
  /** `0` turns the lockout off. */
  login_max_failures: number
  login_failure_window_seconds: number
}

/** `PUT /admin/settings/auth` body: the fields to change. */
export type AuthSettingsUpdate = Partial<AuthSettings>

/**
 * Retention for every repository and instance
 * (`/admin/settings/retention`), in the same way: `GET` answers both
 * settings, `PUT` changes the fields it names.
 */
export interface RetentionSettings {
  /**
   * Off, no retention run starts (scheduled or asked for with Run now) and a
   * run in progress stops before its next batch. Policies and previews keep
   * working.
   */
  runs_enabled: boolean
  /** How long audit rows are kept; `0` keeps them all. */
  audit_retention_seconds: number
}

/** `PUT /admin/settings/retention` body: the fields to change. */
export type RetentionSettingsUpdate = Partial<RetentionSettings>

/** Query keys of the settings. */
export const settingsKeys = {
  auth: () => ['settings', 'auth'] as const,
  retention: () => ['settings', 'retention'] as const,
}

/** `GET /admin/settings/auth`. */
export function fetchAuthSettings(signal?: AbortSignal): Promise<AuthSettings> {
  return httpClient.get<AuthSettings>('/admin/settings/auth', { signal })
}

/** `PUT /admin/settings/auth` — change the fields `body` names. */
export function updateAuthSettings(body: AuthSettingsUpdate): Promise<AuthSettings> {
  return httpClient.put<AuthSettings>('/admin/settings/auth', body)
}

/** `GET /admin/settings/retention`. */
export function fetchRetentionSettings(signal?: AbortSignal): Promise<RetentionSettings> {
  return httpClient.get<RetentionSettings>('/admin/settings/retention', { signal })
}

/** `PUT /admin/settings/retention` — change the fields `body` names. */
export function updateRetentionSettings(
  body: RetentionSettingsUpdate,
): Promise<RetentionSettings> {
  return httpClient.put<RetentionSettings>('/admin/settings/retention', body)
}
