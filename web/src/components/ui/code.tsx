import { useEffect, useId, useState, type ReactNode } from 'react'
import clsx from 'clsx'

import { Button } from './button'
import { Icon } from './icons'

/**
 * Copy-to-clipboard for values the reader pastes elsewhere: a command, a
 * digest, a URL, a new token.
 *
 * The async Clipboard API is an external browser system: the write is
 * attempted on click and a failure (insecure context, permission denied) is
 * reported instead of silently doing nothing. "Copied" reverts after a moment,
 * and as soon as the value changes (another tag selected), so it never vouches
 * for a value that was not copied.
 */
export function useCopy(value: string) {
  // The value last copied (not a boolean): a new value is "not copied" yet.
  const [copiedValue, setCopiedValue] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)

  // Revert the "Copied" acknowledgement after a moment (a timer, cleaned up).
  useEffect(() => {
    if (copiedValue === null) return
    const t = setTimeout(() => setCopiedValue(null), 1600)
    return () => clearTimeout(t)
  }, [copiedValue])

  async function copy() {
    setFailed(false)
    try {
      await navigator.clipboard.writeText(value)
      setCopiedValue(value)
    } catch {
      setFailed(true)
    }
  }

  return { copied: copiedValue === value, failed, copy }
}

/**
 * A compact icon button copying `value` (table cells, digests). `label` names
 * what is copied for assistive technology, e.g. "Copy digest"; it reads
 * "Copied" once the write succeeded.
 */
export function CopyButton({
  value,
  label = 'Copy',
  variant,
  withText = false,
  className,
}: {
  value: string
  label?: string
  variant?: 'code'
  withText?: boolean
  className?: string
}) {
  const { copied, failed, copy } = useCopy(value)
  const title = failed
    ? 'Could not access the clipboard. Copy the value manually.'
    : copied
      ? 'Copied'
      : label
  return (
    <button
      type="button"
      onClick={() => void copy()}
      aria-label={copied ? 'Copied' : label}
      title={title}
      className={clsx('fg-copy', variant && `fg-copy--${variant}`, className)}
    >
      <Icon name={copied ? 'Check' : failed ? 'Alert' : 'Copy'} size={14} />
      {copied ? (
        <span className="fg-copy-done">Copied</span>
      ) : withText ? (
        <span>Copy</span>
      ) : null}
    </button>
  )
}

/** Highlight `<placeholders>` (or the given strings) in a command or file. */
function highlight(text: string, placeholders?: string[]): ReactNode[] {
  const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = placeholders?.length
    ? new RegExp(`(${placeholders.map(escape).join('|')})`)
    : /(<[A-Za-z0-9_.-]+>)/
  return text.split(re).map((part, i) => {
    const hit = placeholders?.length
      ? placeholders.includes(part)
      : /^<[A-Za-z0-9_.-]+>$/.test(part)
    return hit ? (
      <span key={i} className="fg-code-ph">
        {part}
      </span>
    ) : (
      part
    )
  })
}

/**
 * One command to copy, with a label above it and its `<placeholders>`
 * highlighted. It wraps, never scrolls sideways. `prompt={false}` drops the
 * `$` for lines that are not shell commands.
 */
export function CommandSnippet({
  command,
  label,
  copyLabel = 'Copy command',
  prompt = true,
  className,
}: {
  command: string
  label?: ReactNode
  copyLabel?: string
  prompt?: boolean
  className?: string
}) {
  const { copied, failed, copy } = useCopy(command)
  return (
    <div className={clsx('fg-snippet', className)}>
      {label && <div className="fg-snippet-label">{label}</div>}
      <div className="fg-snippet-box">
        <code className={clsx('fg-snippet-code', prompt && 'fg-snippet-code--prompt')}>
          {highlight(command)}
        </code>
        <button
          type="button"
          onClick={() => void copy()}
          aria-label={copied ? 'Copied' : copyLabel}
          title={copied ? 'Copied' : copyLabel}
          className="fg-copy fg-copy--code"
        >
          <Icon name={copied ? 'Check' : 'Copy'} size={14} />
          {copied && <span className="fg-copy-done">Copied</span>}
        </button>
      </div>
      {failed && (
        <p className="fg-field-desc">
          Could not access the clipboard. Select the command and copy it manually.
        </p>
      )}
    </div>
  )
}

/**
 * A multi-line file with a title bar (usually the file name) and a copy
 * button: a `NuGet.config`, a `PackageReference`, a Helm `values.yaml`.
 */
export function CodeBlock({
  code,
  title,
  copyLabel = 'Copy code',
  placeholders = ['<username>', '<token>'],
  className,
}: {
  code: string
  title?: ReactNode
  copyLabel?: string
  placeholders?: string[]
  className?: string
}) {
  const { copied, failed, copy } = useCopy(code)
  return (
    <figure className={clsx('fg-codeblock', className)}>
      <figcaption className="fg-codeblock-head">
        <span className="fg-codeblock-title">{title}</span>
        <button
          type="button"
          onClick={() => void copy()}
          aria-label={copied ? 'Copied' : copyLabel}
          title={copied ? 'Copied' : copyLabel}
          className="fg-copy fg-copy--code"
        >
          <Icon name={copied ? 'Check' : 'Copy'} size={14} />
          {copied ? <span className="fg-copy-done">Copied</span> : <span>Copy</span>}
        </button>
      </figcaption>
      <pre className="fg-codeblock-pre">
        <code>{highlight(code, placeholders)}</code>
      </pre>
      {failed && (
        <p className="fg-field-desc px-3 pb-2">
          Could not access the clipboard. Select the text and copy it manually.
        </p>
      )}
    </figure>
  )
}

/**
 * A read-only value with a Copy button attached: a repository URL, a registry
 * host, an OIDC redirect URI. The value selects itself on focus.
 */
export function CopyField({
  value,
  label,
  description,
  copyLabel,
  className,
}: {
  value: string
  label?: ReactNode
  description?: ReactNode
  copyLabel?: string
  className?: string
}) {
  const id = useId()
  const { copied, failed, copy } = useCopy(value)
  const name = copyLabel ?? (typeof label === 'string' ? `Copy ${label}` : 'Copy value')
  return (
    <div className={clsx('fg-field', className)}>
      {label && (
        <label htmlFor={id} className="fg-label">
          {label}
        </label>
      )}
      <div className="fg-copyfield">
        <input
          id={id}
          className="fg-input fg-input--mono fg-copyfield-input"
          readOnly
          value={value}
          onFocus={(e) => e.target.select()}
        />
        <button
          type="button"
          className="fg-copyfield-btn"
          onClick={() => void copy()}
          aria-label={copied ? 'Copied' : name}
        >
          <Icon name={copied ? 'Check' : 'Copy'} size={15} />
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      {failed ? (
        <p className="fg-field-desc">Could not access the clipboard. Copy the value manually.</p>
      ) : (
        description && <p className="fg-field-desc">{description}</p>
      )}
    </div>
  )
}

/**
 * A secret that was just created (an API token), shown once with Copy and,
 * given `onDismiss`, Dismiss. The value is held in transient state by the
 * caller and never cached or fetched again.
 */
export function SecretOnce({
  value,
  label = 'Secret',
  onDismiss,
  dismissLabel = 'Dismiss',
  className,
}: {
  value: string
  label?: string
  onDismiss?: () => void
  dismissLabel?: string
  className?: string
}) {
  const { copied, failed, copy } = useCopy(value)
  return (
    <div className={clsx('fg-secret', className)} role="alert">
      <div className="fg-secret-head">
        <span className="fg-secret-icon">
          <Icon name="Key" size={16} />
        </span>
        <div>
          <p className="fg-secret-title">{label} created</p>
          <p className="fg-secret-text">
            Copy it now. This is the only time it is shown; it cannot be retrieved again.
          </p>
        </div>
      </div>
      <div className="fg-secret-row">
        <code className="fg-secret-value">{value}</code>
        <Button variant="primary" icon={copied ? 'Check' : 'Copy'} onClick={() => void copy()}>
          {copied ? 'Copied' : 'Copy'}
        </Button>
        {onDismiss && <Button onClick={onDismiss}>{dismissLabel}</Button>}
      </div>
      {failed && (
        <p className="fg-secret-text">
          Could not access the clipboard. Select the value above and copy it manually.
        </p>
      )}
    </div>
  )
}

/** Inline code in running text: a field name, a path, a header. */
export function Code({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={clsx('fg-code-inline', className)}>{children}</code>
}
