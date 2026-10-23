import { useId, type FormEvent, type ReactNode } from 'react'
import clsx from 'clsx'

import { FormatTag, KindBadge } from './badges'
import { Icon, type IconName } from './icons'
import { PathCrumbs, type Crumb } from './nav'

/**
 * The top of every screen: breadcrumbs, the one title, a description, a meta
 * line (kind and format badges, short facts joined by dots) and the screen's
 * actions on the right (at most one primary).
 */
export function PageHeader({
  title,
  icon,
  crumbs,
  description,
  kind,
  format,
  meta,
  actions,
  children,
  className,
}: {
  title: ReactNode
  icon?: IconName
  crumbs?: Crumb[]
  description?: ReactNode
  kind?: string
  format?: string
  meta?: ReactNode[]
  actions?: ReactNode
  /** Extra items at the end of the meta line (badges). */
  children?: ReactNode
  className?: string
}) {
  const facts = (meta ?? []).filter((m) => m !== null && m !== undefined && m !== false)
  const hasMeta = kind || format || facts.length > 0 || children
  return (
    <header className={clsx('fg-pagehead', className)}>
      {crumbs && crumbs.length > 0 && <PathCrumbs items={crumbs} />}
      <div className="fg-pagehead-row">
        <div className="fg-pagehead-main">
          <div className="fg-pagehead-titlerow">
            {icon && (
              <span className="fg-pagehead-icon">
                <Icon name={icon} size={20} />
              </span>
            )}
            <h1 className="fg-pagehead-title">{title}</h1>
          </div>
          {description && <p className="fg-pagehead-desc">{description}</p>}
          {hasMeta && (
            <div className="fg-pagehead-meta">
              {kind && <KindBadge kind={kind} />}
              {format && <FormatTag format={format} />}
              {facts.map((m, i) => (
                <span key={i} className="fg-pagehead-fact">
                  {m}
                </span>
              ))}
              {children}
            </div>
          )}
        </div>
        {actions && <div className="fg-pagehead-actions">{actions}</div>}
      </div>
    </header>
  )
}

/**
 * A bordered surface with a heading row: the block every screen is built
 * from. `flush` drops the body padding so a table runs edge to edge; `footer`
 * holds a form's buttons. As a `form`, pass `as="form"` and `onSubmit`.
 * Panels stack in one column; never nest them.
 */
export function Panel({
  title,
  count,
  description,
  actions,
  footer,
  flush = false,
  as = 'section',
  onSubmit,
  noValidate,
  id,
  className,
  children,
}: {
  title?: ReactNode
  count?: number | string
  description?: ReactNode
  actions?: ReactNode
  footer?: ReactNode
  flush?: boolean
  as?: 'section' | 'form' | 'div'
  onSubmit?: (e: FormEvent<HTMLFormElement>) => void
  noValidate?: boolean
  id?: string
  className?: string
  children?: ReactNode
}) {
  const headingId = useId()
  const head = title || actions
  const props = {
    id,
    className: clsx('fg-panel', flush && 'fg-panel--flush', className),
    'aria-labelledby': title ? headingId : undefined,
  }
  const content = (
    <>
      {head && (
        <div className="fg-panel-head">
          <div className="fg-panel-heading">
            {title && (
              <h2 className="fg-panel-title">
                {/* The region is named by the title alone, not its count. */}
                <span id={headingId}>{title}</span>
                {count !== undefined && (
                  <>
                    {' '}
                    <span className="fg-panel-count">{count}</span>
                  </>
                )}
              </h2>
            )}
            {description && <div className="fg-panel-desc">{description}</div>}
          </div>
          {actions && <div className="fg-panel-actions">{actions}</div>}
        </div>
      )}
      <div className="fg-panel-body">{children}</div>
      {footer && <div className="fg-panel-foot">{footer}</div>}
    </>
  )
  if (as === 'form') {
    return (
      <form {...props} onSubmit={onSubmit} noValidate={noValidate}>
        {content}
      </form>
    )
  }
  if (as === 'div') return <div {...props}>{content}</div>
  return <section {...props}>{content}</section>
}

/**
 * The detail-screen layout: the main column, and a 340px side column for
 * install commands and facts, which moves under the main column on narrow
 * screens.
 */
export function Columns({
  children,
  aside,
  asideLabel,
}: {
  children: ReactNode
  aside?: ReactNode
  asideLabel?: string
}) {
  return (
    <div className="fg-cols">
      <div className="fg-cols-main">{children}</div>
      {aside && (
        <aside className="fg-cols-side" aria-label={asideLabel}>
          {aside}
        </aside>
      )}
    </div>
  )
}

/** One screen: the page header and the panels under it. */
export function Page({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx('fg-page', className)}>{children}</div>
}

/** A bar of filters and search at the top of a flush panel. */
export function Toolbar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx('fg-toolbar', className)}>{children}</div>
}

/** A form's buttons: the primary last, aligned to the end. */
export function FormActions({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return <div className={clsx('fg-actions fg-actions--end', className)}>{children}</div>
}
