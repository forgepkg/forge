import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { reloadDocument } from './navigation'
import {
  RELOAD_WINDOW_MS,
  installChunkReloadHandler,
  isChunkLoadError,
  reloadOnceForStaleChunk,
} from './chunkReload'
import { RouteError } from '~/components/RouteError'

// jsdom's location.reload is not mockable; mock the one-line indirection.
vi.mock('./navigation', () => ({ reloadDocument: vi.fn(), assignLocation: vi.fn() }))

/**
 * Stale lazy chunk recovery (L11): a chunk the server no longer has (404
 * since the last deploy) reloads the document once — never in a loop.
 */
describe('chunk reload', () => {
  beforeEach(() => {
    sessionStorage.clear()
    vi.mocked(reloadDocument).mockReset()
  })
  afterEach(() => sessionStorage.clear())

  it('recognizes the browsers\' dynamic-import failures and Vite preload errors', () => {
    for (const message of [
      'Failed to fetch dynamically imported module: https://forge/assets/List-abc.js',
      'error loading dynamically imported module: https://forge/assets/List-abc.js',
      'Importing a module script failed.',
      'Unable to preload CSS for /assets/List-abc.css',
    ]) {
      expect(isChunkLoadError(new TypeError(message))).toBe(true)
    }
    expect(isChunkLoadError(new Error('API 500: boom'))).toBe(false)
    expect(isChunkLoadError(undefined)).toBe(false)
  })

  it('reloads once, then not again within the window', () => {
    const t0 = 1_000_000
    expect(reloadOnceForStaleChunk(t0)).toBe(true)
    expect(reloadOnceForStaleChunk(t0 + 1_000)).toBe(false)
    expect(reloadDocument).toHaveBeenCalledTimes(1)
    // A later deploy, long after the first reload, may reload again.
    expect(reloadOnceForStaleChunk(t0 + RELOAD_WINDOW_MS + 1)).toBe(true)
    expect(reloadDocument).toHaveBeenCalledTimes(2)
  })

  it('reloads on a vite:preloadError event', () => {
    const uninstall = installChunkReloadHandler()
    window.dispatchEvent(new Event('vite:preloadError', { cancelable: true }))
    window.dispatchEvent(new Event('vite:preloadError', { cancelable: true }))
    expect(reloadDocument).toHaveBeenCalledTimes(1)
    uninstall()
  })

  it('the route error component reloads for a stale chunk, once', () => {
    const error = new TypeError(
      'Failed to fetch dynamically imported module: https://forge/assets/Edit-old.js',
    )
    const { unmount } = render(<RouteError error={error} reset={() => {}} />)
    expect(reloadDocument).toHaveBeenCalledTimes(1)
    expect(screen.getByText(/loading the latest version/i)).toBeInTheDocument()
    unmount()

    // The reload did not help (the chunk is really gone): explain, don't loop.
    render(<RouteError error={error} reset={() => {}} />)
    expect(reloadDocument).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('alert')).toHaveTextContent(/could not be loaded/i)
  })

  it('the route error component does not reload for other errors', () => {
    render(<RouteError error={new Error('API 500: boom')} reset={() => {}} />)
    expect(reloadDocument).not.toHaveBeenCalled()
  })
})
