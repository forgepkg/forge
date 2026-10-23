import { Button, Notice } from '~/components/ui'

/**
 * Generic error notice with an optional retry. Used by every data screen so
 * the failure UX is consistent. `message` is the human-readable summary;
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
    <Notice
      tone="danger"
      title={title}
      action={
        onRetry && (
          <Button size="sm" icon="Refresh" onClick={onRetry}>
            Retry
          </Button>
        )
      }
    >
      {message}
    </Notice>
  )
}

/**
 * An offline hosted or group repository (`isRepositoryOffline`): says so
 * instead of showing the server's status line.
 */
export function RepositoryOfflineState({ onRetry }: { onRetry?: () => void }) {
  return (
    <ErrorState
      title="Repository offline"
      message="This repository is offline for maintenance. Try again later."
      onRetry={onRetry}
    />
  )
}
