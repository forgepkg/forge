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
      className="rounded-lg border border-rose-200 bg-rose-50 p-5 text-rose-800"
    >
      <p className="font-medium">{title}</p>
      {message && <p className="mt-1 text-sm text-rose-700">{message}</p>}
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded border border-rose-300 bg-white px-3 py-1.5 text-sm font-medium text-rose-800 hover:bg-rose-100"
        >
          Retry
        </button>
      )}
    </div>
  )
}
