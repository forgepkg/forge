import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import { CommandSnippet, CopyButton } from './CopyButton'

/**
 * Copy affordances: the command snippet and the compact digest button write
 * their value to the clipboard and acknowledge it; a failing clipboard is
 * reported rather than ignored. (`fireEvent`, not userEvent, so the test's
 * own clipboard spy is exercised — as in `ShowOnceSecret.test.tsx`.)
 */
function stubClipboard() {
  if (!navigator.clipboard) {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: () => Promise.resolve() },
      configurable: true,
    })
  }
  return vi.spyOn(navigator.clipboard, 'writeText')
}

describe('CommandSnippet', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('shows the command and copies it', async () => {
    const writeText = stubClipboard().mockResolvedValue(undefined)
    render(
      <CommandSnippet
        label="Log in"
        command="docker login forge.example.com"
        copyLabel="Copy login command"
      />,
    )

    expect(screen.getByText('docker login forge.example.com')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Copy login command' }))

    expect(writeText).toHaveBeenCalledWith('docker login forge.example.com')
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument()
  })

  it('surfaces a manual-copy hint when the clipboard write fails', async () => {
    stubClipboard().mockRejectedValue(new Error('denied'))
    render(<CommandSnippet command="docker pull x" />)

    fireEvent.click(screen.getByRole('button', { name: 'Copy command' }))

    expect(await screen.findByText(/copy\s+it manually/i)).toBeInTheDocument()
  })
})

describe('CopyButton', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('copies the full value behind a compact button', async () => {
    const writeText = stubClipboard().mockResolvedValue(undefined)
    render(<CopyButton value="sha256:abc" label="Copy digest" />)

    fireEvent.click(screen.getByRole('button', { name: 'Copy digest' }))

    expect(writeText).toHaveBeenCalledWith('sha256:abc')
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument()
  })
})
