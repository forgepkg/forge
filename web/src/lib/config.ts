/**
 * Runtime configuration for the SPA.
 *
 * The browser talks to the Rust HTTP API **directly** (single origin in
 * production). `apiBase` is therefore an empty string by default, producing
 * **relative** URLs (`/admin/me`, `/browse/packages`) — there is structurally
 * no way to introduce a Node proxy.
 *
 * `VITE_FORGE_API_BASE` may set an absolute base for the cross-origin dev
 * variant (running Vite on a different port than the Rust server without the
 * dev proxy). Leave it unset to use the recommended single-origin dev proxy
 * (see `vite.config.ts`).
 */
export const config = {
  /** API base URL. Empty string => same-origin relative URLs. */
  apiBase: (import.meta.env.VITE_FORGE_API_BASE ?? '').replace(/\/$/, ''),
} as const

/** Join the API base with a path, yielding a relative URL when base is empty. */
export function apiUrl(path: string): string {
  const p = path.startsWith('/') ? path : `/${path}`
  return `${config.apiBase}${p}`
}
