import { Button } from '~/components/catalyst/button'

/**
 * Generic error panel with an optional retry. Used by every data screen so the
 * failure UX is consistent (plan §UX). `message` is the human-readable summary;
 * pass the API error's message when available.
 */
export function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
}: {
  title?: string
  message?: string
  onRetry?: () => void
}) {
  return (
    <div
      role="alert"
      className="rounded-xl border border-red-500/25 bg-red-500/5 p-5 dark:bg-red-500/10"
    >
      <p className="font-medium text-red-700 dark:text-red-400">{title}</p>
      {message && (
        <p className="mt-1 text-sm/6 text-red-600/90 dark:text-red-400/80">
          {message}
        </p>
      )}
      {onRetry && (
        <Button outline className="mt-3" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  )
}
