import { useState } from 'react'

/**
 * Renders a freshly-issued secret (a token plaintext) **once**, with a copy
 * affordance and a prominent warning that it cannot be retrieved again. This
 * mirrors the slice-1 backend behavior: `POST /admin/users/{id}/tokens` returns
 * the plaintext exactly once (`CreatedToken.token`); the value is never written
 * into a query cache nor re-fetched, so the caller holds it in transient state
 * and renders it here until the user dismisses it.
 *
 * The copy button uses the async Clipboard API when available (an external
 * browser system, so the `navigator.clipboard.writeText` call is gated behind a
 * feature check and degrades to a manual-copy hint on failure).
 */
export function ShowOnceSecret({
  secret,
  label = 'Secret',
  onDismiss,
}: {
  secret: string
  label?: string
  onDismiss?: () => void
}) {
  const [copied, setCopied] = useState(false)
  const [copyFailed, setCopyFailed] = useState(false)

  async function copy() {
    setCopyFailed(false)
    try {
      await navigator.clipboard.writeText(secret)
      setCopied(true)
    } catch {
      // Clipboard unavailable (insecure context, permission denied): tell the
      // user to copy manually rather than silently doing nothing.
      setCopyFailed(true)
    }
  }

  return (
    <div
      role="alert"
      className="space-y-3 rounded-lg border border-amber-300 bg-amber-50 p-4"
    >
      <div>
        <p className="font-medium text-amber-900">{label} created</p>
        <p className="mt-1 text-sm text-amber-800">
          Copy it now — this is the only time it is shown. It cannot be
          retrieved again.
        </p>
      </div>
      <div className="flex items-center gap-2">
        <code className="flex-1 overflow-x-auto rounded border border-amber-300 bg-white px-3 py-2 font-mono text-sm text-slate-900">
          {secret}
        </code>
        <button
          type="button"
          onClick={() => void copy()}
          className="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
        {onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            className="rounded border border-amber-300 px-3 py-2 text-sm font-medium text-amber-900 hover:bg-amber-100"
          >
            Dismiss
          </button>
        )}
      </div>
      {copyFailed && (
        <p className="text-sm text-amber-800">
          Could not access the clipboard — select the value above and copy it
          manually.
        </p>
      )}
    </div>
  )
}
