import { forwardRef, type ComponentPropsWithoutRef, type ReactNode } from 'react'
import { createLink } from '@tanstack/react-router'
import clsx from 'clsx'

import { Icon, type IconName } from './icons'

const Anchor = forwardRef<HTMLAnchorElement, ComponentPropsWithoutRef<'a'>>(
  function Anchor(props, ref) {
    return <a {...props} ref={ref} />
  },
)

/**
 * A router link rendered as a plain `<a>`, for components addressed with an
 * `href` string (a button that navigates, a menu item, a breadcrumb). The
 * typed `Link` of `@tanstack/react-router` stays the tool of choice for app
 * code that knows its route.
 */
export const RouterAnchor = createLink(Anchor)

/** Whether `href` is a path inside the SPA (else a plain `<a>` is rendered). */
export function isAppPath(href: string): boolean {
  return href.startsWith('/') && !href.startsWith('//')
}

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-solid'

interface ButtonOwnProps {
  /**
   * `primary` (the one thing the view is for; one per view), `secondary`
   * (the default), `ghost` (cancel, row actions), `danger` (starts a
   * destructive action), `danger-solid` (only its confirm step).
   */
  variant?: ButtonVariant
  /** `sm` (28px) in table rows and panel headers; `md` (36px) elsewhere. */
  size?: 'sm' | 'md'
  icon?: IconName
  iconEnd?: IconName
  /** Show only the icon; the label becomes the accessible name and tooltip. */
  iconOnly?: boolean
  block?: boolean
  className?: string
  children?: ReactNode
}

export type ButtonProps = ButtonOwnProps &
  (
    | ({ href: string } & Omit<ComponentPropsWithoutRef<'a'>, 'href' | 'className' | 'children'>)
    | ({ href?: undefined } & Omit<ComponentPropsWithoutRef<'button'>, 'className' | 'children'>)
  )

/**
 * The action control: a `<button type="button">` (pass `type="submit"` in a
 * form), or a link when `href` is set. Label it with a verb in sentence case.
 *
 * A link to a path inside the SPA navigates with the router; one with
 * `download` or `target` (a file the server serves, such as `/raw/…`), or to
 * another origin, is a plain `<a>`.
 */
export const Button = forwardRef<HTMLButtonElement | HTMLAnchorElement, ButtonProps>(
  function Button(props, ref) {
    const {
      variant = 'secondary',
      size = 'md',
      icon,
      iconEnd,
      iconOnly = false,
      block = false,
      className,
      children,
      ...rest
    } = props
    const iconSize = size === 'sm' ? 14 : 16
    const classes = clsx(
      'fg-btn',
      `fg-btn--${variant}`,
      `fg-btn--${size}`,
      iconOnly && 'fg-btn--icon',
      block && 'fg-btn--block',
      className,
    )
    const a11y: { 'aria-label'?: string; title?: string } = {}
    if (iconOnly) {
      const label =
        (rest as { 'aria-label'?: string })['aria-label'] ??
        (typeof children === 'string' ? children : undefined)
      a11y['aria-label'] = label
      a11y.title = (rest as { title?: string }).title ?? label
    }
    const content = (
      <>
        {icon && <Icon name={icon} size={iconSize} />}
        {!iconOnly && children !== undefined && <span>{children}</span>}
        {iconEnd && !iconOnly && <Icon name={iconEnd} size={iconSize} />}
      </>
    )
    if (rest.href !== undefined) {
      const { href, ...anchor } = rest
      if (isAppPath(href) && anchor.download === undefined && anchor.target === undefined) {
        return (
          <RouterAnchor
            {...anchor}
            {...a11y}
            to={href}
            ref={ref as React.Ref<HTMLAnchorElement>}
            className={classes}
          >
            {content}
          </RouterAnchor>
        )
      }
      return (
        <a
          {...anchor}
          {...a11y}
          href={href}
          ref={ref as React.Ref<HTMLAnchorElement>}
          className={classes}
        >
          {content}
        </a>
      )
    }
    const { type = 'button', ...button } = rest
    return (
      <button
        {...button}
        {...a11y}
        type={type}
        ref={ref as React.Ref<HTMLButtonElement>}
        className={classes}
      >
        {content}
      </button>
    )
  },
)
