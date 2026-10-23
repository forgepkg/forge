import { PathCrumbs, type Crumb } from '~/components/ui'

export type { Crumb }

/**
 * Folder-view breadcrumb trail. Items with a `to` render as router links;
 * the final item is the current location and renders as plain text.
 */
export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return <PathCrumbs items={items} />
}
