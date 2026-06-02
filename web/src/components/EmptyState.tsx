import type { ReactNode } from 'react'

/**
 * Neutral empty-result placeholder. Rendered when a query succeeds but returns
 * no rows (no search hits, a package with no visible versions, etc.).
 */
export function EmptyState({
  title,
  children,
}: {
  title: string
  children?: ReactNode
}) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-white p-8 text-center">
      <p className="font-medium text-slate-700">{title}</p>
      {children && <p className="mt-1 text-sm text-slate-500">{children}</p>}
    </div>
  )
}
