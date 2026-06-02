import { createFileRoute, Link } from '@tanstack/react-router'

export const Route = createFileRoute('/_app/admin/')({
  component: AdminHome,
})

/**
 * Admin landing (placeholder). Only reachable once the `AdminLayout` guard has
 * confirmed `is_admin`. Links to the repositories and users (incl. per-user
 * token) management screens.
 */
function AdminHome() {
  return (
    <section className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Administration</h1>
        <p className="mt-1 text-slate-600">
          Manage repositories, users, and their API tokens.
        </p>
      </div>
      <ul className="grid gap-3 sm:grid-cols-2">
        <li>
          <Link
            to="/admin/repositories"
            className="block rounded-lg border border-slate-200 bg-white p-4 font-medium text-sky-700 hover:border-slate-300 hover:bg-slate-50"
          >
            Repositories
          </Link>
        </li>
        <li>
          <Link
            to="/admin/users"
            className="block rounded-lg border border-slate-200 bg-white p-4 font-medium text-sky-700 hover:border-slate-300 hover:bg-slate-50"
          >
            Users &amp; tokens
          </Link>
        </li>
      </ul>
    </section>
  )
}
