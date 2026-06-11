/**
 * Theme management — the single module that knows how light/dark mode works.
 *
 * The preference (`'light' | 'dark' | 'system'`, default `system`) lives in
 * localStorage under `forge.theme`; the *effect* is the `.dark` class on
 * `<html>` (see the `@custom-variant dark` in styles.css) plus the matching
 * `color-scheme`, so native form controls and scrollbars follow along. An
 * inline script in index.html applies the same logic before first paint to
 * avoid a flash; this module owns every change after that, including following
 * OS changes live while the preference is `system`.
 */

const THEME_KEY = 'forge.theme'

export type Theme = 'light' | 'dark' | 'system'

const subscribers = new Set<() => void>()

function notify(): void {
  for (const fn of subscribers) fn()
}

/** Subscribe to preference changes (for the toggle UI). Returns unsubscribe. */
export function onThemeChange(listener: () => void): () => void {
  subscribers.add(listener)
  return () => {
    subscribers.delete(listener)
  }
}

/** The stored preference (default `system`). */
export function getTheme(): Theme {
  try {
    const raw = localStorage.getItem(THEME_KEY)
    if (raw === 'light' || raw === 'dark') return raw
  } catch {
    /* no storage: behave as system */
  }
  return 'system'
}

function systemPrefersDark(): boolean {
  return (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  )
}

/** Whether the given preference resolves to dark right now. */
export function resolvesDark(theme: Theme): boolean {
  return theme === 'dark' || (theme === 'system' && systemPrefersDark())
}

/** Apply a preference to the document (class + color-scheme). */
function apply(theme: Theme): void {
  const dark = resolvesDark(theme)
  document.documentElement.classList.toggle('dark', dark)
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
}

/** Persist + apply a preference and notify the toggle UI. */
export function setTheme(theme: Theme): void {
  try {
    if (theme === 'system') localStorage.removeItem(THEME_KEY)
    else localStorage.setItem(THEME_KEY, theme)
  } catch {
    /* storage unavailable: still apply for this page */
  }
  apply(theme)
  notify()
}

/**
 * One-time startup wiring (called from main.tsx): re-apply the stored
 * preference (the index.html bootstrap already did, but this keeps a single
 * source of truth) and follow live OS changes while in `system`.
 */
export function initTheme(): void {
  apply(getTheme())
  if (typeof window.matchMedia === 'function') {
    window
      .matchMedia('(prefers-color-scheme: dark)')
      .addEventListener('change', () => {
        if (getTheme() === 'system') {
          apply('system')
          notify()
        }
      })
  }
}
