import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { DelayBadge } from './DelayBadge'

/**
 * DelayBadge unit behavior: hosted/group versions (`status = null`) render
 * nothing; `available` and `delayed_until` render their respective badges, and
 * a future `delayedUntil` is summarized as an ETA.
 */
describe('DelayBadge', () => {
  it('renders nothing for a hosted/group version (null status)', () => {
    const { container } = render(<DelayBadge status={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders an available badge', () => {
    render(<DelayBadge status="available" />)
    expect(screen.getByText('available')).toBeInTheDocument()
  })

  it('renders a delayed badge with an ETA for a future timestamp', () => {
    const future = new Date(Date.now() + 90 * 60_000).toISOString()
    render(<DelayBadge status="delayed_until" delayedUntil={future} />)
    // "delayed · in 1h 30m" — assert the prefix and that an ETA is shown.
    expect(screen.getByText(/delayed/)).toBeInTheDocument()
    expect(screen.getByText(/in 1h/)).toBeInTheDocument()
  })

  it('renders a plain delayed badge without an ETA when none is given', () => {
    render(<DelayBadge status="delayed_until" />)
    expect(screen.getByText('delayed')).toBeInTheDocument()
  })

  it('names the override that exempts the package', () => {
    render(
      <DelayBadge
        status="available"
        delay={{ delay_seconds: 0, source: { kind: 'selector', name: 'trusted-vendors' } }}
      />,
    )
    expect(screen.getByText('no delay: trusted-vendors')).toBeInTheDocument()
  })

  it('says when a version was released early', () => {
    render(
      <DelayBadge
        status="available"
        releasedAt="2026-11-02T10:00:00Z"
        delay={{ delay_seconds: 3600, source: { kind: 'default' } }}
      />,
    )
    expect(screen.getByText('released early')).toBeInTheDocument()
  })

  it('names the override that holds a delayed version back in its title', () => {
    render(
      <DelayBadge
        status="delayed_until"
        delay={{ delay_seconds: 1_209_600, source: { kind: 'pattern', pattern: 'risky.*' } }}
      />,
    )
    expect(screen.getByText('delayed')).toHaveAttribute(
      'title',
      expect.stringContaining('14 d delay: risky.*'),
    )
  })
})
