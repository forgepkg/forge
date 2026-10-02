/**
 * Post-login return-to handling (`/login?redirect=...`).
 *
 * The target comes from the URL, so it is untrusted: only a same-origin app
 * path is honoured, mirroring the server's `sanitize_redirect_to` (one leading
 * `/`, not `//` or `/\`, no scheme, no backslash / whitespace / control
 * characters); anything else becomes `/`.
 *
 * The admin screens moved from `/admin/*` (which is the admin REST API) to
 * `/manage/*`; a return-to saved before the move is mapped to its new path so
 * it lands on the screen instead of on raw JSON.
 */

/** The admin UI's path prefix (the admin REST API keeps `/admin`). */
export const ADMIN_UI_PREFIX = '/manage'

/** Map a former admin-UI path (`/admin`, `/admin/...`) to `/manage...`. */
export function legacyAdminToManage(path: string): string {
  return /^\/admin(?=$|[/?#])/.test(path)
    ? `${ADMIN_UI_PREFIX}${path.slice('/admin'.length)}`
    : path
}

/**
 * Sanitize a requested post-login target into a safe same-origin app path
 * (`/` when absent or unsafe), with legacy admin-UI paths mapped to
 * `/manage`.
 */
export function safeReturnTo(raw: string | null | undefined): string {
  const candidate = raw?.trim()
  if (!candidate || !candidate.startsWith('/')) return '/'
  if (candidate[1] === '/' || candidate[1] === '\\') return '/'
  // eslint-disable-next-line no-control-regex
  if (/[\\\s\u0000-\u001f\u007f]/.test(candidate)) return '/'
  if (candidate.includes('://')) return '/'
  return legacyAdminToManage(candidate)
}
