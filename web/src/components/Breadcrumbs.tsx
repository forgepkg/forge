import { Fragment } from 'react'
import { Link } from '@tanstack/react-router'

/**
 * Folder-view breadcrumb trail. Items with a `to` render as router links (the
 * common targets are static paths or params-resolved strings); the final item
 * is the current location and renders as plain emphasized text.
 */
export interface Crumb {
  label: string
  to?: string
  params?: Record<string, string>
}

export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav
      aria-label="Breadcrumb"
      className="flex items-center gap-1.5 text-sm/6 text-zinc-500 dark:text-zinc-400"
    >
      {items.map((item, idx) => (
        <Fragment key={`${item.label}-${idx}`}>
          {idx > 0 && (
            <svg
              aria-hidden="true"
              viewBox="0 0 20 20"
              fill="currentColor"
              className="h-3.5 w-3.5 shrink-0 text-zinc-400 dark:text-zinc-500"
            >
              <path
                fillRule="evenodd"
                d="M7.21 14.77a.75.75 0 0 1 .02-1.06L11.168 10 7.23 6.29a.75.75 0 1 1 1.04-1.08l4.5 4.25a.75.75 0 0 1 0 1.08l-4.5 4.25a.75.75 0 0 1-1.06-.02Z"
                clipRule="evenodd"
              />
            </svg>
          )}
          {item.to ? (
            <Link
              to={item.to}
              params={item.params}
              className="hover:text-zinc-950 hover:underline dark:hover:text-white"
            >
              {item.label}
            </Link>
          ) : (
            <span className="font-medium text-zinc-950 dark:text-white">
              {item.label}
            </span>
          )}
        </Fragment>
      ))}
    </nav>
  )
}
