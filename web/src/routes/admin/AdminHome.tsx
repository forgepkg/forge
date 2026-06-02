import { createFileRoute, Link } from '@tanstack/react-router'

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
        <li>
          <Link
            to="/admin/repositories"
            className="block rounded-lg border border-slate-200 bg-white p-4 font-medium text-sky-700 hover:border-slate-300 hover:bg-slate-50"
          >
            Repositories
          </Link>
        </li>
        <li className="rounded-lg border border-slate-200 bg-white p-4 text-slate-400">
          Users (Phase 5)
        </li>
        <li className="rounded-lg border border-slate-200 bg-white p-4 text-slate-400">
          Tokens (Phase 5)
        </li>
      </ul>
    </section>
  )
}
