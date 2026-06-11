import { index, layout, rootRoute, route } from '@tanstack/virtual-file-routes'

/**
 * Virtual file routes (TanStack Router convention):
 * route components live in `src/routes/` and the tree is declared *here*, then
 * generated into `src/routeTree.gen.ts` by `@tanstack/router-plugin`. Do not
 * hand-author route files or the generated tree.
 *
 * Structure:
 *
 *   root.tsx
 *     /login            -> Login.tsx            (user+password or realm login)
 *     layout 'app'      -> AppLayout.tsx        (login-gated nav shell)
 *       index           -> Browse.tsx           (folder view root: repositories)
 *       /repos/$repo    -> RepoBrowse.tsx       (per-repo packages + search)
 *       /packages/...   -> PackageDetail.tsx    (versions + dependencies)
 *       /tokens         -> Tokens.tsx           (self-service registry tokens)
 *       /admin          -> AdminLayout.tsx      (beforeLoad: require is_admin)
 */
export const routes = rootRoute('root.tsx', [
  route('/login', 'Login.tsx'),
  layout('app', 'AppLayout.tsx', [
    index('Browse.tsx'),
    route('/repos/$repo', 'RepoBrowse.tsx'),
    route('/packages/$repo/$id', 'PackageDetail.tsx'),
    route('/tokens', 'Tokens.tsx'),
    route('/admin', 'AdminLayout.tsx', [
      index('admin/AdminHome.tsx'),
      route('/repositories', 'admin/repositories/List.tsx'),
      route('/repositories/new', 'admin/repositories/Create.tsx'),
      route('/repositories/$repo', 'admin/repositories/Edit.tsx'),
      route(
        '/repositories/$repo/members',
        'admin/repositories/GroupMembers.tsx',
      ),
      route('/users', 'admin/users/List.tsx'),
      route('/users/$userId', 'admin/users/Edit.tsx'),
      route('/realms', 'admin/realms/List.tsx'),
      route('/realms/new', 'admin/realms/Create.tsx'),
      route('/realms/$realmId', 'admin/realms/Edit.tsx'),
    ]),
  ]),
])
