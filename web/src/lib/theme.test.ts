import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getTheme, initTheme, resolvesDark, setTheme } from './theme'

/**
 * Behavior tests for the theme module: the preference round-trips through
 * localStorage, `.dark` lands on <html>, and `system` follows the (mocked)
 * prefers-color-scheme media query.
 */
describe('theme', () => {
  /** Install a matchMedia stub reporting the given system preference. */
  function mockSystemDark(dark: boolean) {
    vi.stubGlobal(
      'matchMedia',
      vi.fn().mockImplementation((query: string) => ({
        matches: dark && query.includes('prefers-color-scheme: dark'),
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      })),
    )
  }

  beforeEach(() => {
    localStorage.clear()
    document.documentElement.classList.remove('dark')
    mockSystemDark(false)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    localStorage.clear()
    document.documentElement.classList.remove('dark')
  })

  it('defaults to system', () => {
    expect(getTheme()).toBe('system')
  })

  it('setTheme(dark) persists and applies the dark class', () => {
    setTheme('dark')
    expect(getTheme()).toBe('dark')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(document.documentElement.style.colorScheme).toBe('dark')
  })

  it('setTheme(light) clears the dark class even on a dark OS', () => {
    mockSystemDark(true)
    setTheme('light')
    expect(document.documentElement.classList.contains('dark')).toBe(false)
    expect(document.documentElement.style.colorScheme).toBe('light')
  })

  it('setTheme(system) removes the stored preference and follows the OS', () => {
    setTheme('dark')
    mockSystemDark(true)
    setTheme('system')
    expect(localStorage.getItem('forge.theme')).toBeNull()
    expect(getTheme()).toBe('system')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })

  it('resolvesDark mirrors the preference + OS state', () => {
    expect(resolvesDark('dark')).toBe(true)
    expect(resolvesDark('light')).toBe(false)
    expect(resolvesDark('system')).toBe(false)
    mockSystemDark(true)
    expect(resolvesDark('system')).toBe(true)
  })

  it('initTheme applies the stored preference on startup', () => {
    localStorage.setItem('forge.theme', 'dark')
    initTheme()
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })
})
