import { useEffect, useState } from 'react'
import clsx from 'clsx'

import { Button } from '~/components/catalyst/button'

/**
 * Copy-to-clipboard affordances for values the user pastes elsewhere: a
 * `docker login` / `docker pull` command, a manifest digest.
 *
 * Like `ShowOnceSecret`, the async Clipboard API is an external browser
 * system: the write is attempted on click and a failure (insecure context,
 * permission denied) is reported instead of silently doing nothing. "Copied"
 * reverts after a moment, and as soon as the value changes (another tag
 * selected), so it never vouches for a value that was not copied.
 */
function useCopy(value: string) {
  // The value last copied (not a boolean): a new value is "not copied" yet.
  const [copiedValue, setCopiedValue] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)

  // Revert the "Copied" acknowledgement after a moment (a timer, cleaned up).
  useEffect(() => {
    if (copiedValue === null) return
    const t = setTimeout(() => setCopiedValue(null), 2000)
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
 * A compact icon button copying `value` (table cells). `label` names what is
 * copied for assistive technology, e.g. "Copy digest".
 */
export function CopyButton({
  value,
  label = 'Copy',
  className,
}: {
  value: string
  label?: string
  className?: string
}) {
  const { copied, failed, copy } = useCopy(value)
  const title = failed
    ? 'Could not access the clipboard — copy the value manually'
    : copied
      ? 'Copied'
      : label
  return (
    <button
      type="button"
      onClick={() => void copy()}
      aria-label={copied ? 'Copied' : label}
      title={title}
      className={clsx(
        className,
        'inline-flex shrink-0 items-center rounded-md p-1 text-zinc-400 transition hover:bg-zinc-950/5 hover:text-zinc-700 focus-visible:outline-2 focus-visible:outline-blue-500 dark:text-zinc-500 dark:hover:bg-white/5 dark:hover:text-zinc-200',
        failed && 'text-red-500 dark:text-red-400',
      )}
    >
      {copied ? <CheckIcon /> : <ClipboardIcon />}
    </button>
  )
}

/**
 * A one-line shell command in a code box with a "Copy" button. `label`, when
 * given, captions the box; `copyLabel` is the copy button's accessible name
 * (default "Copy command").
 */
export function CommandSnippet({
  command,
  label,
  copyLabel = 'Copy command',
}: {
  command: string
  label?: string
  copyLabel?: string
}) {
  const { copied, failed, copy } = useCopy(command)
  return (
    <div className="space-y-1.5">
      {label && (
        <p className="text-sm/6 font-medium text-zinc-950 dark:text-white">
          {label}
        </p>
      )}
      <div className="flex items-center gap-2">
        <code className="flex-1 overflow-x-auto rounded-lg border border-zinc-950/10 bg-zinc-950/[2.5%] px-3 py-2 font-mono text-sm whitespace-nowrap text-zinc-950 dark:border-white/10 dark:bg-white/5 dark:text-white">
          {command}
        </code>
        <Button
          outline
          onClick={() => void copy()}
          aria-label={copied ? 'Copied' : copyLabel}
        >
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      {failed && (
        <p className="text-sm/6 text-red-600 dark:text-red-400">
          Could not access the clipboard — select the command above and copy
          it manually.
        </p>
      )}
    </div>
  )
}

function ClipboardIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4">
      <path
        fillRule="evenodd"
        d="M13.887 3.182c.396.037.79.08 1.183.128C16.194 3.45 17 4.414 17 5.517V16.75A2.25 2.25 0 0 1 14.75 19h-9.5A2.25 2.25 0 0 1 3 16.75V5.517c0-1.103.806-2.068 1.93-2.207.393-.048.787-.09 1.183-.128A3.001 3.001 0 0 1 9 1h2c1.373 0 2.531.923 2.887 2.182ZM7.5 4A1.5 1.5 0 0 1 9 2.5h2A1.5 1.5 0 0 1 12.5 4v.5h-5V4Z"
        clipRule="evenodd"
      />
    </svg>
  )
}

function CheckIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4 text-emerald-600 dark:text-emerald-400">
      <path
        fillRule="evenodd"
        d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z"
        clipRule="evenodd"
      />
    </svg>
  )
}
