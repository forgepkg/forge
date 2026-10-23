import type { ReactNode } from 'react'

import { Logo } from '~/components/ui'

/**
 * The page of the screens before sign-in (signing in, choosing a password
 * from an invitation): the lockup above one card with the screen's title and
 * a line under it, and the host the browser talks to below, so the reader
 * can tell which Forge this is.
 */
export function AuthCard({
  title,
  subtitle,
  children,
}: {
  title: string
  subtitle?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="flex min-h-dvh flex-col items-center gap-7 bg-ground px-4 pt-16 pb-8 text-ink">
      <Logo size={34} />
      <main className="flex w-full max-w-[400px] flex-col gap-6 rounded-lg border border-line bg-surface p-8 shadow-lg max-sm:p-6">
        <div className="flex flex-col gap-1">
          <h1 className="m-0 text-2xl leading-8 font-semibold tracking-[-0.01em]">{title}</h1>
          {subtitle && <p className="fg-text">{subtitle}</p>}
        </div>
        {children}
      </main>
      <p className="fg-text fg-text--small">{window.location.host}</p>
    </div>
  )
}
