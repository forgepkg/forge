import { describe, expect, it } from 'vitest'

import { formatAge } from './age'

describe('formatAge', () => {
  const now = Date.parse('2026-11-03T12:00:00Z')

  it('says how long ago a time was, in the largest unit that fits', () => {
    expect(formatAge('2026-11-03T11:59:30Z', now)).toBe('just now')
    expect(formatAge('2026-11-03T11:55:00Z', now)).toBe('5 min ago')
    expect(formatAge('2026-11-03T09:00:00Z', now)).toBe('3 h ago')
    expect(formatAge('2026-11-02T00:00:00Z', now)).toBe('36 h ago')
    expect(formatAge('2026-10-31T12:00:00Z', now)).toBe('3 d ago')
  })

  it('takes a time ahead of the clock for now, and refuses what does not parse', () => {
    expect(formatAge('2026-11-03T12:05:00Z', now)).toBe('just now')
    expect(formatAge('yesterday', now)).toBeNull()
  })
})
