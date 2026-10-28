import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'
import clsx from 'clsx'

import { Button, type ButtonVariant } from './button'
import { Icon, type IconName } from './icons'

type NoticeTone = 'info' | 'warn' | 'danger' | 'ok'

const TONE_ICON: Record<NoticeTone, IconName> = {
  info: 'Info',
  warn: 'Alert',
  danger: 'Alert',
  ok: 'CheckCircle',
}

/**
 * An inline message where the problem is: info, warn, danger or ok. warn and
 * danger are announced to screen readers (`role="alert"`), the others are a
 * `status`; `role` overrides that (a degraded state that needs no action).
 * `action` is a button or link at the end.
 */
export function Notice({
  tone = 'info',
  title,
  children,
  action,
  role,
  className,
}: {
  tone?: NoticeTone
  title?: ReactNode
  children?: ReactNode
  action?: ReactNode
  role?: 'alert' | 'status'
  className?: string
}) {
  return (
    <div
      className={clsx('fg-notice', `fg-notice--${tone}`, className)}
      role={role ?? (tone === 'danger' || tone === 'warn' ? 'alert' : 'status')}
    >
      <Icon name={TONE_ICON[tone]} size={16} />
      <div className="fg-notice-text">
        {title && <p className="fg-notice-title">{title}</p>}
        {children && <div className="fg-notice-body">{children}</div>}
      </div>
      {action}
    </div>
  )
}

/**
 * What is missing, why, and what to do next: nothing yet, nothing matches,
 * or no access ("Ask an administrator to grant you access."). `bordered=
 * {false}` inside a panel.
 */
export function EmptyState({
  title,
  children,
  icon = 'Package',
  action,
  bordered = true,
  className,
}: {
  title: ReactNode
  children?: ReactNode
  icon?: IconName
  action?: ReactNode
  bordered?: boolean
  className?: string
}) {
  return (
    <div className={clsx('fg-empty', !bordered && 'fg-empty--plain', className)}>
      <span className="fg-empty-icon" aria-hidden="true">
        <Icon name={icon} size={20} />
      </span>
      <p className="fg-empty-title">{title}</p>
      {children && <div className="fg-empty-text">{children}</div>}
      {action && <div className="fg-empty-action">{action}</div>}
    </div>
  )
}

type ToastTone = 'ok' | 'danger' | 'warn' | 'info'

interface ToastMessage {
  id: number
  tone: ToastTone
  title: string
  body?: ReactNode
}

const ToastContext = createContext<((t: Omit<ToastMessage, 'id'>) => void) | null>(null)

/**
 * Short confirmations floating at the bottom right after an action finishes
 * elsewhere on the screen ("Repository saved"). One at a time; each closes
 * after 6 seconds or with its close button. Not for errors the reader must
 * act on (use a `Notice`), nor for copies (those confirm in place).
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<ToastMessage | null>(null)
  const next = useRef(0)
  const show = useCallback((t: Omit<ToastMessage, 'id'>) => {
    next.current += 1
    setToast({ ...t, id: next.current })
  }, [])

  // Close after a while (a timer, cleaned up when the toast changes).
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 6000)
    return () => clearTimeout(t)
  }, [toast])

  return (
    <ToastContext.Provider value={show}>
      {children}
      <div className="fg-toasts" aria-live="polite">
        {toast && (
          <div key={toast.id} className={clsx('fg-toast', `fg-toast--${toast.tone}`)} role="status">
            <span className="fg-toast-icon">
              <Icon name={TONE_ICON[toast.tone]} size={16} />
            </span>
            <div className="fg-toast-text">
              <p className="fg-toast-title">{toast.title}</p>
              {toast.body && <div className="fg-toast-body">{toast.body}</div>}
            </div>
            <button
              type="button"
              className="fg-toast-close"
              aria-label="Dismiss"
              onClick={() => setToast(null)}
            >
              <Icon name="X" size={14} />
            </button>
          </div>
        )}
      </div>
    </ToastContext.Provider>
  )
}

/** Show a toast; a no-op outside a `ToastProvider` (tests of one component). */
export function useToast(): (t: Omit<ToastMessage, 'id'>) => void {
  const show = useContext(ToastContext)
  return useMemo(() => show ?? (() => {}), [show])
}

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * A modal for a decision that needs full attention: confirming a delete,
 * revoking a token. The confirm button names the object ("Delete
 * nuget-legacy"); a destructive one is `danger-solid`, the only solid red.
 *
 * Focus moves into the dialog and stays there; Escape, the close button, the
 * scrim and Cancel call `onClose`, and focus returns where it was.
 */
export function Dialog({
  open,
  onClose,
  title,
  description,
  icon,
  tone = 'neutral',
  children,
  confirmLabel,
  confirmVariant = 'primary',
  confirmIcon,
  confirmDisabled = false,
  onConfirm,
  cancelLabel = 'Cancel',
  footer,
  wide = false,
}: {
  open: boolean
  onClose: () => void
  title: ReactNode
  description?: ReactNode
  icon?: IconName
  tone?: 'neutral' | 'danger' | 'warn'
  children?: ReactNode
  confirmLabel?: string
  confirmVariant?: ButtonVariant
  confirmIcon?: IconName
  confirmDisabled?: boolean
  onConfirm?: () => void
  cancelLabel?: string
  /** Replaces the default Cancel / confirm buttons. */
  footer?: ReactNode
  /** Room for a body to edit (a JSON document), not only to confirm. */
  wide?: boolean
}) {
  const titleId = useId()
  const descId = useId()
  const box = useRef<HTMLDivElement>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  // Move focus in on open, trap Tab inside, close on Escape, and give focus
  // back on close: the document's keyboard events are an external system.
  useEffect(() => {
    if (!open) return
    const before = document.activeElement as HTMLElement | null
    // The first control of the body (a confirm field), else the first button.
    const first =
      box.current?.querySelector('.fg-dialog-body')?.querySelector<HTMLElement>(FOCUSABLE) ??
      box.current?.querySelector<HTMLElement>('.fg-dialog-foot button')
    first?.focus()
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault()
        onCloseRef.current()
        return
      }
      if (e.key !== 'Tab' || !box.current) return
      const all = Array.from(box.current.querySelectorAll<HTMLElement>(FOCUSABLE))
      if (all.length === 0) return
      const firstEl = all[0]
      const lastEl = all[all.length - 1]
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault()
        lastEl.focus()
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault()
        firstEl.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      before?.focus?.()
    }
  }, [open])

  if (!open) return null
  return createPortal(
    <div className="fg-dialog-layer">
      <div className="fg-dialog-scrim" aria-hidden="true" onClick={onClose} />
      <div
        ref={box}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        className={clsx('fg-dialog', wide && 'fg-dialog--wide')}
      >
        <div className="fg-dialog-head">
          {icon && (
            <span className={clsx('fg-dialog-icon', `fg-dialog-icon--${tone}`)}>
              <Icon name={icon} size={18} />
            </span>
          )}
          <div className="fg-dialog-heading">
            <h2 id={titleId} className="fg-dialog-title">
              {title}
            </h2>
            {description && (
              <div id={descId} className="fg-dialog-desc">
                {description}
              </div>
            )}
          </div>
          <button type="button" className="fg-dialog-close" aria-label="Close" onClick={onClose}>
            <Icon name="X" size={16} />
          </button>
        </div>
        {children && <div className="fg-dialog-body">{children}</div>}
        <div className="fg-dialog-foot">
          {footer ?? (
            <>
              <Button onClick={onClose}>{cancelLabel}</Button>
              {confirmLabel && (
                <Button
                  variant={confirmVariant}
                  icon={confirmIcon}
                  disabled={confirmDisabled}
                  onClick={onConfirm}
                >
                  {confirmLabel}
                </Button>
              )}
            </>
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}
