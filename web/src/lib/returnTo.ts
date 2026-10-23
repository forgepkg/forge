/**
 * Post-login return-to handling (`/login?redirect=...`).
 *
 * The target comes from the URL, so it is untrusted: only a same-origin app
 * path is honoured, mirroring the server's `sanitize_redirect_to` (one leading
 * `/`, not `//` or `/\`, no scheme, no backslash / whitespace / control
 * characters); anything else becomes `/`.
 */

/**
 * Sanitize a requested post-login target into a safe same-origin app path
 * (`/` when absent or unsafe).
 */
export function safeReturnTo(raw: string | null | undefined): string {
  const candidate = raw?.trim()
  if (!candidate || !candidate.startsWith('/')) return '/'
  if (candidate[1] === '/' || candidate[1] === '\\') return '/'
  // eslint-disable-next-line no-control-regex
  if (/[\\\s\u0000-\u001f\u007f]/.test(candidate)) return '/'
  if (candidate.includes('://')) return '/'
  return candidate
}
