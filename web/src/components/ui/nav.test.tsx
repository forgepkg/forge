import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { Menu, menuDirection } from './nav'

describe('menuDirection', () => {
  const base = { menuHeight: 120, viewportHeight: 800 }

  it('opens downward when the list fits below the button', () => {
    expect(menuDirection({ ...base, preferred: 'down', anchorTop: 100, anchorBottom: 130 })).toBe(
      'down',
    )
  })

  it('opens upward when the list does not fit below and there is more room above', () => {
    expect(menuDirection({ ...base, preferred: 'down', anchorTop: 700, anchorBottom: 730 })).toBe(
      'up',
    )
  })

  it('stays downward when neither side fits but below has more room', () => {
    expect(
      menuDirection({
        menuHeight: 300,
        viewportHeight: 400,
        preferred: 'down',
        anchorTop: 150,
        anchorBottom: 180,
      }),
    ).toBe('down')
  })

  it('keeps a preferred upward direction when the list fits above', () => {
    expect(menuDirection({ ...base, preferred: 'up', anchorTop: 700, anchorBottom: 730 })).toBe('up')
  })

  it('turns a preferred upward list downward when it does not fit above', () => {
    expect(menuDirection({ ...base, preferred: 'up', anchorTop: 40, anchorBottom: 70 })).toBe('down')
  })
})

describe('Menu', () => {
  // jsdom lays nothing out: give the button a rectangle and the list a size.
  let buttonTop = 100
  beforeEach(() => {
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (
      this: HTMLElement,
    ) {
      if (this.tagName !== 'BUTTON') return new DOMRect(0, 0, 0, 0)
      return new DOMRect(900, buttonTop, 30, 30)
    })
    vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockImplementation(function (
      this: HTMLElement,
    ) {
      return this.getAttribute('role') === 'menu' ? 120 : 0
    })
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockImplementation(function (
      this: HTMLElement,
    ) {
      return this.getAttribute('role') === 'menu' ? 240 : 0
    })
  })
  afterEach(() => {
    vi.restoreAllMocks()
    buttonTop = 100
  })

  function renderMenu(onEdit = vi.fn()) {
    render(
      <div>
        <Menu
          label="Actions for acme"
          iconOnly
          items={[
            { label: 'Edit', onSelect: onEdit },
            { divider: true },
            { label: 'Delete', danger: true },
          ]}
        />
        <button type="button">After</button>
      </div>,
    )
    return screen.getByRole('button', { name: 'Actions for acme' })
  }

  it('renders the list outside the menu, below a button with room under it', async () => {
    const button = renderMenu()
    await userEvent.click(button)
    const menu = screen.getByRole('menu')
    expect(button.closest('.fg-menu')?.contains(menu)).toBe(false)
    expect(menu.parentElement).toBe(document.body)
    expect(menu.dataset.direction).toBe('down')
    expect(menu.style.top).toBe('134px')
    // Aligned to the button's right edge: 930 - 240.
    expect(menu.style.left).toBe('690px')
  })

  it('opens upward when the button is near the bottom of the viewport', async () => {
    buttonTop = window.innerHeight - 40
    const button = renderMenu()
    await userEvent.click(button)
    const menu = screen.getByRole('menu')
    expect(menu.dataset.direction).toBe('up')
    expect(menu.style.top).toBe('')
    expect(menu.style.bottom).toBe('44px')
  })

  it('treats a click in the list as inside and a click elsewhere as outside', async () => {
    const onEdit = vi.fn()
    const button = renderMenu(onEdit)
    await userEvent.click(button)
    fireEvent.mouseDown(screen.getByRole('menuitem', { name: 'Edit' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('menuitem', { name: 'Edit' }))
    expect(onEdit).toHaveBeenCalledOnce()
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()

    await userEvent.click(button)
    fireEvent.mouseDown(document.body)
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('keeps the keyboard behaviour', async () => {
    const button = renderMenu()
    button.focus()
    await userEvent.keyboard('{ArrowDown}')
    expect(screen.getByRole('menuitem', { name: 'Edit' })).toHaveFocus()
    await userEvent.keyboard('{ArrowDown}')
    expect(screen.getByRole('menuitem', { name: 'Delete' })).toHaveFocus()
    await userEvent.keyboard('{Home}')
    expect(screen.getByRole('menuitem', { name: 'Edit' })).toHaveFocus()
    await userEvent.keyboard('{End}')
    expect(screen.getByRole('menuitem', { name: 'Delete' })).toHaveFocus()
    await userEvent.keyboard('{Escape}')
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(button).toHaveFocus()

    // Tab leaves the list for what follows the button, Shift+Tab for the button.
    await userEvent.keyboard('{ArrowDown}')
    await userEvent.tab()
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'After' })).toHaveFocus()

    button.focus()
    await userEvent.keyboard('{ArrowDown}')
    await userEvent.tab({ shift: true })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(button).toHaveFocus()
  })
})
