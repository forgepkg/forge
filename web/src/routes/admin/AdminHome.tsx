import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/_app/admin/')({
  component: AdminHome,
})

/**
 * Admin landing (placeholder). Only reachable once the `AdminLayout` guard has
 * confirmed `is_admin`. Phases 4–5 add the repositories / users / tokens
 * management screens beneath the admin layout.
 */
function AdminHome() {
  return (
    <section className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Administration</h1>
        <p className="mt-1 text-slate-600">
          Manage repositories, users, and tokens. (Screens land in Phases 4–5.)
        </p>
      </div>
      <ul className="grid gap-3 sm:grid-cols-3">
        <li className="rounded-lg border border-slate-200 bg-white p-4 text-slate-400">
          Repositories
        </li>
        <li className="rounded-lg border border-slate-200 bg-white p-4 text-slate-400">
          Users
        </li>
        <li className="rounded-lg border border-slate-200 bg-white p-4 text-slate-400">
          Tokens
        </li>
      </ul>
    </section>
  )
}
