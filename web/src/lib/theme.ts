/**
 * Theme management — the single module that knows how the themes work.
 *
 * The design system has three themes: `light` (everything light),
 * `dark-rail` (light content with a dark grey rail and dark code blocks) and
 * `dark`. The preference is one of those or `system` (the default), which
 * follows `prefers-color-scheme` between `light` and `dark`. It lives in
 * localStorage under `forge.theme`; the *effect* is `data-theme` on `<html>`
 * (the selector of the tokens in styles/tokens.css) plus the matching
 * `color-scheme`, so native form controls and scrollbars follow along. An
 * inline script in index.html applies the same logic before first paint to
 * avoid a flash; this module owns every change after that, including following
 * OS changes live while the preference is `system`.
 */

const THEME_KEY = 'forge.theme'

export type Theme = 'light' | 'dark-rail' | 'dark' | 'system'

/** A theme the document can show: a preference with `system` resolved. */
export type ResolvedTheme = Exclude<Theme, 'system'>

/** The choices, in the order the theme menu offers them. */
export const THEMES: { value: Theme; label: string }[] = [
  { value: 'system', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark-rail', label: 'Light with dark rail' },
  { value: 'dark', label: 'Dark' },
]

const subscribers = new Set<() => void>()

function notify(): void {
  for (const fn of subscribers) fn()
}

/** Subscribe to preference changes (for the theme menu). Returns unsubscribe. */
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
    if (raw === 'light' || raw === 'dark-rail' || raw === 'dark') return raw
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

/** The theme a preference shows right now. */
export function resolveTheme(theme: Theme): ResolvedTheme {
  if (theme !== 'system') return theme
  return systemPrefersDark() ? 'dark' : 'light'
}

/** Whether the given preference resolves to the dark theme right now. */
export function resolvesDark(theme: Theme): boolean {
  return resolveTheme(theme) === 'dark'
}

/** Apply a preference to the document (`data-theme` + color-scheme). */
function apply(theme: Theme): void {
  const resolved = resolveTheme(theme)
  document.documentElement.dataset.theme = resolved
  document.documentElement.style.colorScheme = resolved === 'dark' ? 'dark' : 'light'
}

/** Persist + apply a preference and notify the theme menu. */
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
