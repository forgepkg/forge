import type { ReactNode } from 'react'

import { EmptyState as UiEmptyState, type IconName } from '~/components/ui'

/**
 * Empty-result placeholder. Rendered when a query succeeds but returns no
 * rows (no search hits, a package with no visible versions, etc.): it names
 * what is missing and who can change it.
 */
export function EmptyState({
  title,
  icon,
  action,
  bordered,
  children,
}: {
  title: string
  icon?: IconName
  action?: ReactNode
  bordered?: boolean
  children?: ReactNode
}) {
  return (
    <UiEmptyState title={title} icon={icon} action={action} bordered={bordered}>
      {children}
    </UiEmptyState>
  )
}
