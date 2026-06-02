import clsx from 'clsx'

/**
 * Colored badge for a repository kind (`hosted` | `proxy` | `group`). Unknown
 * kinds fall back to a neutral style so a future kind never renders untyped.
 */
const KIND_STYLES: Record<string, string> = {
  hosted: 'bg-sky-100 text-sky-800',
  proxy: 'bg-amber-100 text-amber-800',
  group: 'bg-violet-100 text-violet-800',
}

export function RepoKindBadge({ kind }: { kind: string }) {
  return (
    <span
      className={clsx(
        'inline-block rounded px-1.5 py-0.5 text-xs font-medium',
        KIND_STYLES[kind] ?? 'bg-slate-100 text-slate-700',
      )}
    >
      {kind}
    </span>
  )
}
