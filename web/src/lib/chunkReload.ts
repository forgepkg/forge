import { reloadDocument } from './navigation'

/**
 * Recovery from a stale lazy chunk after a deploy.
 *
 * Route components are code-split (`autoCodeSplitting`), and every build gives
 * the chunks new content-hashed names. A tab opened before a deploy still asks
 * for the old names, which the server now answers with a 404 (L11): the
 * dynamic `import()` (or Vite's CSS/JS preload of its dependencies) rejects.
 * Reloading the document fetches the new `index.html` (served `no-cache`) and
 * with it the current chunk names.
 *
 * The reload happens **at most once per {@link RELOAD_WINDOW_MS}**, recorded in
 * `sessionStorage`, so a chunk that is genuinely missing (a broken deploy)
 * shows an error instead of reloading forever.
 */

const RELOAD_KEY = 'forge.chunk-reload-at'

/** A second chunk failure within this window does not reload again. */
export const RELOAD_WINDOW_MS = 10_000

/**
 * Whether `error` is a failed load of a code-split chunk: the browsers'
 * dynamic-import messages (Chrome, Firefox, Safari) and Vite's preload error.
 */
export function isChunkLoadError(error: unknown): boolean {
  const message =
    error instanceof Error
      ? error.message
      : typeof (error as { message?: unknown })?.message === 'string'
        ? (error as { message: string }).message
        : ''
  return (
    message.startsWith('Failed to fetch dynamically imported module') ||
    message.startsWith('error loading dynamically imported module') ||
    message.startsWith('Importing a module script failed') ||
    message.startsWith('Unable to preload CSS')
  )
}

/**
 * Reload the document to pick up a new deploy, unless that was already tried
 * within the last {@link RELOAD_WINDOW_MS}. Returns whether a reload was
 * started. Without usable `sessionStorage` the guard cannot be recorded, so
 * it never reloads (better an error than a loop).
 */
export function reloadOnceForStaleChunk(now: number = Date.now()): boolean {
  try {
    const last = Number(sessionStorage.getItem(RELOAD_KEY) ?? 0)
    if (Number.isFinite(last) && now - last < RELOAD_WINDOW_MS) return false
    sessionStorage.setItem(RELOAD_KEY, String(now))
  } catch {
    return false
  }
  reloadDocument()
  return true
}

/**
 * Install the window-level half: Vite dispatches `vite:preloadError` when a
 * lazy chunk or one of its preloaded dependencies fails to load. The error
 * still propagates to the router (whose error component handles it the same
 * way), so nothing is swallowed if the reload is refused. Returns an
 * uninstall function.
 */
export function installChunkReloadHandler(): () => void {
  const onPreloadError = () => {
    reloadOnceForStaleChunk()
  }
  window.addEventListener('vite:preloadError', onPreloadError)
  return () => window.removeEventListener('vite:preloadError', onPreloadError)
}
