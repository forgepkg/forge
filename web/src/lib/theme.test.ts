import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getTheme, initTheme, resolveTheme, resolvesDark, setTheme } from './theme'

/**
 * Behavior tests for the theme module: the preference round-trips through
 * localStorage, `data-theme` lands on <html>, and `system` follows the
 * (mocked) prefers-color-scheme media query between light and dark.
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

  const shown = () => document.documentElement.dataset.theme

  beforeEach(() => {
    localStorage.clear()
    delete document.documentElement.dataset.theme
    mockSystemDark(false)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    localStorage.clear()
    delete document.documentElement.dataset.theme
  })

  it('defaults to system', () => {
    expect(getTheme()).toBe('system')
  })

  it('setTheme(dark) persists and applies the dark theme', () => {
    setTheme('dark')
    expect(getTheme()).toBe('dark')
    expect(shown()).toBe('dark')
    expect(document.documentElement.style.colorScheme).toBe('dark')
  })

  it('setTheme(light) shows the light theme even on a dark OS', () => {
    mockSystemDark(true)
    setTheme('light')
    expect(shown()).toBe('light')
    expect(document.documentElement.style.colorScheme).toBe('light')
  })

  it('setTheme(dark-rail) persists the light theme with the dark rail', () => {
    mockSystemDark(true)
    setTheme('dark-rail')
    expect(getTheme()).toBe('dark-rail')
    expect(localStorage.getItem('forge.theme')).toBe('dark-rail')
    expect(shown()).toBe('dark-rail')
    // The content stays light: native controls render light.
    expect(document.documentElement.style.colorScheme).toBe('light')
  })

  it('setTheme(system) removes the stored preference and follows the OS', () => {
    setTheme('dark')
    mockSystemDark(true)
    setTheme('system')
    expect(localStorage.getItem('forge.theme')).toBeNull()
    expect(getTheme()).toBe('system')
    expect(shown()).toBe('dark')
  })

  it('ignores an unknown stored value', () => {
    localStorage.setItem('forge.theme', 'sepia')
    expect(getTheme()).toBe('system')
  })

  it('resolveTheme and resolvesDark mirror the preference + OS state', () => {
    expect(resolvesDark('dark')).toBe(true)
    expect(resolvesDark('light')).toBe(false)
    expect(resolvesDark('dark-rail')).toBe(false)
    expect(resolveTheme('system')).toBe('light')
    mockSystemDark(true)
    expect(resolvesDark('system')).toBe(true)
    expect(resolveTheme('system')).toBe('dark')
  })

  it('initTheme applies the stored preference on startup', () => {
    localStorage.setItem('forge.theme', 'dark-rail')
    initTheme()
    expect(shown()).toBe('dark-rail')
  })
})
