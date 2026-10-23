import {
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from 'react'
import { Link } from '@tanstack/react-router'
import clsx from 'clsx'

import { Button, RouterAnchor, isAppPath, type ButtonVariant } from './button'
import { Icon, type IconName } from './icons'

/** One step of a breadcrumb trail; the last one is the current page. */
export interface Crumb {
  label: string
  to?: string
  params?: Record<string, string>
  search?: Record<string, unknown>
}

/** Where the screen sits: Repositories / nuget-internal / Acme.Core. */
export function PathCrumbs({ items, className }: { items: Crumb[]; className?: string }) {
  return (
    <nav aria-label="Breadcrumb" className={clsx('fg-crumbs', className)}>
      <ol>
        {items.map((item, i) => {
          const last = i === items.length - 1
          return (
            <li key={`${item.label}-${i}`}>
              {i > 0 && (
                <span className="fg-crumbs-sep" aria-hidden="true">
                  /
                </span>
              )}
              {last || !item.to ? (
                <span
                  className="fg-crumbs-current"
                  aria-current={last ? 'page' : undefined}
                >
                  {item.label}
                </span>
              ) : (
                <Link to={item.to} params={item.params} search={item.search}>
                  {item.label}
                </Link>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

/** Move focus among a group's buttons with the arrow keys, Home and End. */
function rovingKeys(e: KeyboardEvent<HTMLElement>, onPick: (index: number) => void) {
  const buttons = Array.from(
    e.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'),
  )
  const at = buttons.indexOf(document.activeElement as HTMLButtonElement)
  if (at < 0) return
  let next = at
  if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (at + 1) % buttons.length
  else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp')
    next = (at - 1 + buttons.length) % buttons.length
  else if (e.key === 'Home') next = 0
  else if (e.key === 'End') next = buttons.length - 1
  else return
  e.preventDefault()
  buttons[next].focus()
  onPick(next)
}

export interface TabItem<T extends string> {
  id: T
  label: ReactNode
  count?: number | string
}

/**
 * Parallel views of one object, the selected one underlined in heat
 * (package: Versions · Dependencies; image: Tags · Manifests). Controlled.
 */
export function Tabs<T extends string>({
  items,
  value,
  onChange,
  label,
  idPrefix,
  className,
}: {
  items: TabItem<T>[]
  value: T
  onChange: (id: T) => void
  label?: string
  /** With a prefix, tab `x` controls the element with id `${idPrefix}-x`. */
  idPrefix?: string
  className?: string
}) {
  return (
    <div
      className={clsx('fg-tabs', className)}
      role="tablist"
      aria-label={label}
      onKeyDown={(e) => rovingKeys(e, (i) => onChange(items[i].id))}
    >
      {items.map((it) => {
        const on = it.id === value
        return (
          <button
            key={it.id}
            type="button"
            role="tab"
            id={idPrefix ? `${idPrefix}-tab-${it.id}` : undefined}
            aria-controls={idPrefix ? `${idPrefix}-${it.id}` : undefined}
            aria-selected={on}
            tabIndex={on ? 0 : -1}
            className="fg-tab"
            onClick={() => onChange(it.id)}
          >
            {it.label}
            {it.count !== undefined && <span className="fg-tab-count">{it.count}</span>}
          </button>
        )
      })}
    </div>
  )
}

/**
 * Two to five mutually exclusive views of the same list (a format filter, a
 * kind filter). Controlled.
 */
export function SegmentedControl<T extends string>({
  items,
  value,
  onChange,
  label,
  className,
}: {
  items: { id: T; label: ReactNode; icon?: IconName; count?: number | string }[]
  value: T
  onChange: (id: T) => void
  label: string
  className?: string
}) {
  return (
    <div
      className={clsx('fg-seg', className)}
      role="radiogroup"
      aria-label={label}
      onKeyDown={(e) => rovingKeys(e, (i) => onChange(items[i].id))}
    >
      {items.map((it) => {
        const on = it.id === value
        return (
          <button
            key={it.id}
            type="button"
            role="radio"
            aria-checked={on}
            tabIndex={on ? 0 : -1}
            className={clsx('fg-seg-item', on && 'is-on')}
            onClick={() => onChange(it.id)}
          >
            {it.icon && <Icon name={it.icon} size={15} />}
            {it.label}
            {it.count !== undefined && <span className="fg-seg-count">{it.count}</span>}
          </button>
        )
      })}
    </div>
  )
}

/**
 * The range shown, the page, and previous / next, over a `{ total }` result.
 * Disabled at the ends so the caller never requests an out-of-range page.
 */
export function Paginator({
  skip,
  take,
  total,
  onSkipChange,
  className,
}: {
  skip: number
  take: number
  total: number
  onSkipChange: (nextSkip: number) => void
  className?: string
}) {
  const from = total ? skip + 1 : 0
  const to = Math.min(skip + take, total)
  const page = Math.floor(skip / take) + 1
  const pages = Math.max(1, Math.ceil(total / take))
  return (
    <nav className={clsx('fg-pager', className)} aria-label="Pagination">
      <span className="fg-pager-range">
        {total === 0 ? (
          'No results'
        ) : (
          <>
            Showing <strong>{`${from}–${to}`}</strong> of <strong>{total}</strong>
          </>
        )}
      </span>
      <span className="fg-pager-btns">
        <span className="fg-pager-page">{`Page ${page} of ${pages}`}</span>
        <Button
          size="sm"
          icon="ChevronLeft"
          iconOnly
          disabled={skip <= 0}
          onClick={() => onSkipChange(Math.max(0, skip - take))}
        >
          Previous page
        </Button>
        <Button
          size="sm"
          icon="ChevronRight"
          iconOnly
          disabled={skip + take >= total}
          onClick={() => onSkipChange(skip + take)}
        >
          Next page
        </Button>
      </span>
    </nav>
  )
}

export type MenuItem =
  | { divider: true }
  | {
      divider?: false
      label: string
      icon?: IconName
      description?: string
      /** A path inside the SPA, or an external URL. */
      href?: string
      onSelect?: () => void
      danger?: boolean
      disabled?: boolean
      /** Makes the item a radio item (`menuitemradio`), checked or not. */
      checked?: boolean
    }

/**
 * A button that opens a short list of actions (row actions, the "more" of a
 * page header, the theme switch). The destructive item goes last, after a
 * divider, marked `danger`; it opens a confirmation, never deletes at once.
 *
 * Keyboard: Enter, Space or ArrowDown open it on the first item; the arrow
 * keys, Home and End move; Escape closes and returns focus to the button.
 */
export function Menu({
  items,
  label = 'More actions',
  icon,
  iconOnly = false,
  variant,
  size,
  align = 'end',
  direction = 'down',
  buttonClassName,
  className,
}: {
  items: MenuItem[]
  label?: string
  icon?: IconName
  iconOnly?: boolean
  variant?: ButtonVariant
  size?: 'sm' | 'md'
  align?: 'start' | 'end'
  direction?: 'down' | 'up'
  buttonClassName?: string
  className?: string
}) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const button = useRef<HTMLButtonElement>(null)
  const pop = useRef<HTMLDivElement>(null)
  const menuId = useId()

  // Close on a click outside (an external system: the document's events).
  useEffect(() => {
    if (!open) return
    function onDown(e: MouseEvent) {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  // Focus the first item once the list is open.
  useEffect(() => {
    if (open) pop.current?.querySelector<HTMLElement>('[role^="menuitem"]')?.focus()
  }, [open])

  function close(refocus: boolean) {
    setOpen(false)
    if (refocus) button.current?.focus()
  }

  function onListKey(e: KeyboardEvent<HTMLDivElement>) {
    const all = Array.from(
      e.currentTarget.querySelectorAll<HTMLElement>(
        '[role^="menuitem"]:not([aria-disabled="true"])',
      ),
    )
    const at = all.indexOf(document.activeElement as HTMLElement)
    let next = -1
    if (e.key === 'ArrowDown') next = (at + 1) % all.length
    else if (e.key === 'ArrowUp') next = (at - 1 + all.length) % all.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = all.length - 1
    else if (e.key === 'Escape') {
      e.preventDefault()
      close(true)
      return
    } else if (e.key === 'Tab') {
      close(false)
      return
    }
    if (next >= 0) {
      e.preventDefault()
      all[next]?.focus()
    }
  }

  return (
    <div
      ref={root}
      className={clsx(
        'fg-menu',
        align === 'start' ? 'fg-menu--start' : 'fg-menu--end',
        direction === 'up' && 'fg-menu--up',
        className,
      )}
    >
      <Button
        ref={button}
        variant={variant ?? (iconOnly ? 'ghost' : 'secondary')}
        size={size ?? (iconOnly ? 'sm' : 'md')}
        icon={icon ?? (iconOnly ? 'More' : undefined)}
        iconEnd={iconOnly ? undefined : 'ChevronDown'}
        iconOnly={iconOnly}
        className={buttonClassName}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen(!open)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' && !open) {
            e.preventDefault()
            setOpen(true)
          }
        }}
      >
        {label}
      </Button>
      {open && (
        <div
          ref={pop}
          id={menuId}
          role="menu"
          aria-label={label}
          className="fg-menu-pop"
          onKeyDown={onListKey}
        >
          {items.map((it, i) => {
            if (it.divider) {
              return <div key={i} role="separator" className="fg-menu-sep" />
            }
            const role = it.checked === undefined ? 'menuitem' : 'menuitemradio'
            const body = (
              <>
                {it.icon ? (
                  <Icon name={it.icon} size={16} />
                ) : (
                  <span className="fg-menu-noicon" />
                )}
                <span className="fg-menu-label">
                  {it.label}
                  {it.description && <span className="fg-menu-desc">{it.description}</span>}
                </span>
              </>
            )
            const common = {
              role,
              tabIndex: -1,
              'aria-checked': it.checked,
              'aria-disabled': it.disabled || undefined,
              className: clsx('fg-menu-item', it.danger && 'is-danger'),
              onClick: () => {
                if (it.disabled) return
                close(!it.href)
                it.onSelect?.()
              },
            }
            if (it.href && !it.disabled) {
              return isAppPath(it.href) ? (
                <RouterAnchor key={i} to={it.href} {...common}>
                  {body}
                </RouterAnchor>
              ) : (
                <a key={i} href={it.href} {...common}>
                  {body}
                </a>
              )
            }
            return (
              <button key={i} type="button" {...common}>
                {body}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
