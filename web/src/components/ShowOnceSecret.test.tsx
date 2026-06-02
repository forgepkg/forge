import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ShowOnceSecret } from './ShowOnceSecret'

/**
 * ShowOnceSecret unit behavior: it renders the plaintext with a copy affordance
 * and a "shown only once" warning. The copy button writes to the clipboard when
 * available and flips its label; if the clipboard is unavailable it surfaces a
 * manual-copy hint rather than failing silently.
 */
describe('ShowOnceSecret', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('shows the secret and a one-time warning', () => {
    render(<ShowOnceSecret secret="abc123" label="Token" />)
    expect(screen.getByText('abc123')).toBeInTheDocument()
    expect(screen.getByText('Token created')).toBeInTheDocument()
    expect(screen.getByText(/only time it is shown/i)).toBeInTheDocument()
  })

  it('copies to the clipboard and flips the button label', async () => {
    // jsdom provides no real clipboard; ensure one exists, then spy on it.
    if (!navigator.clipboard) {
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText: () => Promise.resolve() },
        configurable: true,
      })
    }
    const writeText = vi
      .spyOn(navigator.clipboard, 'writeText')
      .mockResolvedValue(undefined)

    render(<ShowOnceSecret secret="abc123" />)

    // fireEvent (not userEvent) so the test's own clipboard spy is exercised
    // rather than userEvent's installed clipboard.
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))

    expect(writeText).toHaveBeenCalledWith('abc123')
    expect(
      await screen.findByRole('button', { name: 'Copied' }),
    ).toBeInTheDocument()
  })

  it('surfaces a manual-copy hint when the clipboard write fails', async () => {
    if (!navigator.clipboard) {
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText: () => Promise.resolve() },
        configurable: true,
      })
    }
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(
      new Error('denied'),
    )

    render(<ShowOnceSecret secret="abc123" />)

    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))

    expect(await screen.findByText(/copy it\s+manually/i)).toBeInTheDocument()
  })

  it('invokes onDismiss', async () => {
    const onDismiss = vi.fn()
    const user = userEvent.setup()
    render(<ShowOnceSecret secret="abc123" onDismiss={onDismiss} />)

    await user.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(onDismiss).toHaveBeenCalledOnce()
  })
})
