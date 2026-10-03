import { httpClient } from '~/lib/httpClient'

/**
 * Admin auth-realm CRUD API (§12.7).
 *
 * Types mirror the Rust DTOs:
 *
 *  - `RealmView` is the redacted response shape: secret config fields
 *    (`client_secret`, `key_pepper`) are never returned; instead the config
 *    carries `client_secret_set` / `key_pepper_set` booleans.
 *  - `GET /admin/realms` returns a bare array ordered by `priority`
 *    (lower = tried/listed first).
 *  - `POST /admin/realms` appends at the end of the order; creating
 *    `kind: "local"` is rejected (built-in singleton).
 *  - `PATCH /admin/realms/{id}`: omitting (or blanking) a secret keeps the
 *    stored one — the write-only contract.
 *  - `DELETE /admin/realms/{id}` is 400 for the local realm (disable instead).
 *  - `PUT /admin/realms/order` must contain **every** realm id exactly once.
 */

/** Realm kinds. */
export type RealmKind = 'local' | 'oidc' | 'credential_forwarding' | 'workload_identity'

/** OIDC realm config (redacted on read: `client_secret` -> `client_secret_set`). */
export interface OidcRealmConfig {
  issuer: string
  client_id: string
  /** SECRET — write-only; required on create, omit to keep on update. */
  client_secret?: string
  /** Read-side redaction flag: a secret is stored. */
  client_secret_set?: boolean
  scopes?: string[]
  clock_skew_seconds?: number
  allow_http_issuer?: boolean
  username_claim?: string
  email_claim?: string
  display_name_claim?: string
  auto_provision?: boolean
  link_existing_by_username?: boolean
  admin_groups?: string[]
  admin_claim?: string
  /** Email domains routed to this IdP by identifier-first. */
  login_domains?: string[]
  /** Allow-gate: claim name -> allowed values (e.g. `{ tid: ['<tenant>'] }`). */
  required_claims?: Record<string, string[]>
  button_label?: string | null
}

/** Credential-forwarding realm config (redacted: `key_pepper` -> `key_pepper_set`). */
export interface CredentialForwardingConfig {
  url: string
  method?: string
  success_status?: number[]
  reject_status?: number[]
  connect_timeout_ms?: number
  request_timeout_ms?: number
  required_groups?: string[]
  groups_path?: string
  /** JSON path naming the account the upstream authenticated (e.g. `login`). */
  identity_path?: string
  admin_group?: string
  auto_provision?: boolean
  positive_ttl_secs?: number
  negative_ttl_secs?: number
  /** SECRET — write-only; required on create, omit to keep on update. */
  key_pepper?: string
  /** Read-side redaction flag: a pepper is stored. */
  key_pepper_set?: boolean
}

/**
 * A condition within a workload-identity rule: the named claim's value must
 * equal one of `any_of`.
 */
export interface WorkloadIdentityCondition {
  claim: string
  any_of: string[]
}

/**
 * A workload-identity rule: grants `role` when ALL `conditions` match (AND).
 * At least one condition is required; catch-all trust is rejected.
 */
export interface WorkloadIdentityRule {
  role: string
  conditions?: WorkloadIdentityCondition[]
}

/**
 * Workload-identity-federation (WIF) realm config. The issuer JWKS is public,
 * so — unlike oidc/credential_forwarding — there are no write-only secrets and
 * no read-side redaction.
 */
export interface WorkloadIdentityConfig {
  issuer: string
  allowed_audiences: string[]
  allow_http_issuer?: boolean
  clock_skew_seconds?: number
  max_token_age_seconds?: number
  allowed_authorized_parties?: string[]
  positive_cache_seconds?: number
  rules: WorkloadIdentityRule[]
}

/** Kind-specific config; `local` has none. */
export type RealmConfig =
  | OidcRealmConfig
  | CredentialForwardingConfig
  | WorkloadIdentityConfig
  | Record<string, never>

/** Redacted realm view (`GET /admin/realms[/{id}]`). */
export interface RealmView {
  id: number
  kind: RealmKind
  name: string
  enabled: boolean
  priority: number
  config: RealmConfig
  created_at: string
  updated_at: string
}

/** `POST /admin/realms` request body. */
export interface CreateRealm {
  kind: RealmKind
  name: string
  enabled?: boolean
  config: RealmConfig
}

/** `PATCH /admin/realms/{id}` request body (all fields optional). */
export interface UpdateRealm {
  name?: string
  enabled?: boolean
  config?: RealmConfig
}

/**
 * Query-key factory for the realm resource. Arrays from one factory so list /
 * detail invalidation share stable, structured keys.
 */
export const realmKeys = {
  all: () => ['realms'] as const,
  list: () => ['realms', 'list'] as const,
  detail: (id: number) => ['realms', 'detail', id] as const,
}

/** `GET /admin/realms` — bare array, ordered by priority. */
export function fetchRealms(signal?: AbortSignal): Promise<RealmView[]> {
  return httpClient.get<RealmView[]>('/admin/realms', { signal })
}

/** `GET /admin/realms/{id}` — one (redacted) realm. */
export function fetchRealm(id: number, signal?: AbortSignal): Promise<RealmView> {
  return httpClient.get<RealmView>(`/admin/realms/${id}`, { signal })
}

/** `POST /admin/realms` — create a realm (201; appended at end of order). */
export function createRealm(body: CreateRealm): Promise<RealmView> {
  return httpClient.post<RealmView>('/admin/realms', body)
}

/** `PATCH /admin/realms/{id}` — partial update (write-only secrets). */
export function updateRealm(id: number, body: UpdateRealm): Promise<RealmView> {
  return httpClient.patch<RealmView>(`/admin/realms/${id}`, body)
}

/** `DELETE /admin/realms/{id}` — delete (400 for the built-in local realm). */
export function deleteRealm(id: number): Promise<void> {
  return httpClient.delete<void>(`/admin/realms/${id}`)
}

/** `PUT /admin/realms/order` — full new priority order (every id once). */
export function reorderRealms(order: number[]): Promise<RealmView[]> {
  return httpClient.put<RealmView[]>('/admin/realms/order', { order })
}
