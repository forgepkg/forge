import type { ReactNode } from 'react'

import { Text } from '~/components/catalyst/text'

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
    <div className="rounded-xl border border-dashed border-zinc-950/15 p-10 text-center dark:border-white/15">
      <p className="font-medium text-zinc-950 dark:text-white">{title}</p>
      {children && <Text className="mt-1">{children}</Text>}
    </div>
  )
}
