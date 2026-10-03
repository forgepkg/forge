/**
 * Full-page navigation (used for OIDC redirects, which must leave the SPA so
 * the server can 302 to the IdP). A one-line indirection because jsdom's
 * `window.location` is non-configurable and cannot be mocked directly in
 * tests.
 */
export function assignLocation(url: string): void {
  window.location.assign(url)
}

/** Reload the current document (same indirection, for the stale-chunk reload). */
export function reloadDocument(): void {
  window.location.reload()
}
