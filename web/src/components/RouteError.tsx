import { useEffect, useState } from 'react'
import { ErrorComponent, type ErrorComponentProps } from '@tanstack/react-router'

import { isChunkLoadError, reloadOnceForStaleChunk } from '~/lib/chunkReload'
import { reloadDocument } from '~/lib/navigation'
import { Text } from '~/components/catalyst/text'
import { ErrorState } from './ErrorState'

/**
 * The router's default error component (`defaultErrorComponent`).
 *
 * A failed lazy-chunk load — typically a tab opened before a deploy asking for
 * chunk names that no longer exist — reloads the document once to pick up the
 * new build (see `chunkReload.ts`); if that was already tried moments ago it
 * explains the situation and offers a manual reload instead of looping. Any
 * other error renders TanStack Router's stock error component, as before.
 */
export function RouteError(props: ErrorComponentProps) {
  const stale = isChunkLoadError(props.error)
  const [reloading, setReloading] = useState(false)

  // Reloading is a side effect on the browser (an external system), so it
  // runs after commit, not during render.
  useEffect(() => {
    if (stale && reloadOnceForStaleChunk()) setReloading(true)
  }, [stale])

  if (!stale) return <ErrorComponent {...props} />
  if (reloading) return <Text>Loading the latest version of Forge…</Text>
  return (
    <ErrorState
      title="This page could not be loaded"
      message="Forge may have been updated since this tab was opened. Reload the page to continue."
      onRetry={reloadDocument}
    />
  )
}
