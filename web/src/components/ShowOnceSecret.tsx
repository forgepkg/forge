import { useState } from 'react'

import { Button } from '~/components/catalyst/button'

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
      className="space-y-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4"
    >
      <div>
        <p className="font-medium text-amber-800 dark:text-amber-300">
          {label} created
        </p>
        <p className="mt-1 text-sm/6 text-amber-700 dark:text-amber-400">
          Copy it now — this is the only time it is shown. It cannot be
          retrieved again.
        </p>
      </div>
      <div className="flex items-center gap-2">
        <code className="flex-1 overflow-x-auto rounded-lg border border-amber-500/30 bg-white px-3 py-2 font-mono text-sm text-zinc-950 dark:bg-zinc-900 dark:text-white">
          {secret}
        </code>
        <Button onClick={() => void copy()}>{copied ? 'Copied' : 'Copy'}</Button>
        {onDismiss && (
          <Button outline onClick={onDismiss}>
            Dismiss
          </Button>
        )}
      </div>
      {copyFailed && (
        <p className="text-sm/6 text-amber-700 dark:text-amber-400">
          Could not access the clipboard — select the value above and copy it
          manually.
        </p>
      )}
    </div>
  )
}
