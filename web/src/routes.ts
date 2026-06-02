import { index, layout, rootRoute, route } from '@tanstack/virtual-file-routes'

/**
 * Virtual file routes (TanStack Router convention):
 * route components live in `src/routes/` and the tree is declared *here*, then
 * generated into `src/routeTree.gen.ts` by `@tanstack/router-plugin`. Do not
 * hand-author route files or the generated tree.
 *
 * Phase 2 (plan §5) lands the auth layer + app shell + admin route gate:
 *
 *   root.tsx
 *     /login            -> Login.tsx           (token paste; OIDC stub for §12.2)
 *     layout 'app'      -> AppLayout.tsx        (nav shell + current user)
 *       index           -> Browse.tsx          (browse placeholder; Phase 3)
 *       /admin          -> AdminLayout.tsx      (beforeLoad: require is_admin)
 *         index         -> admin/AdminHome.tsx  (admin landing placeholder)
 *
 * Browse and the admin sub-screens (repositories/users/tokens) are filled in by
 * Phases 3–5; the structure here is what those phases extend.
 */
export const routes = rootRoute('root.tsx', [
  route('/login', 'Login.tsx'),
  layout('app', 'AppLayout.tsx', [
    index('Browse.tsx'),
    route('/packages/$repo/$id', 'PackageDetail.tsx'),
    route('/admin', 'AdminLayout.tsx', [
      index('admin/AdminHome.tsx'),
      route('/repositories', 'admin/repositories/List.tsx'),
      route('/repositories/new', 'admin/repositories/Create.tsx'),
      route('/repositories/$repo', 'admin/repositories/Edit.tsx'),
      route(
        '/repositories/$repo/members',
        'admin/repositories/GroupMembers.tsx',
      ),
    ]),
  ]),
])
