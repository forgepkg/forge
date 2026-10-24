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
 *     /invite           -> Invite.tsx           (an invited user chooses a password;
 *                                                the token is the URL fragment)
 *     layout 'app'      -> AppLayout.tsx        (login-gated nav shell)
 *       index           -> Browse.tsx           (folder view root: repositories)
 *       /repos/$repo    -> RepoBrowse.tsx       (per-repo packages or images + search;
 *                                                a raw repository's file tree)
 *       /packages/...   -> PackageDetail.tsx    (versions + dependencies)
 *       /images/$repo/$ -> ImageDetail.tsx      (docker image: tags + manifests;
 *                                                the splat is the image name,
 *                                                which may contain `/`)
 *       /tokens         -> Tokens.tsx           (self-service registry tokens)
 *       /cli-login/$secret -> CliLogin.tsx      (approve a command-line client's
 *                                                web login: `npm login`)
 *       /manage         -> AdminLayout.tsx      (beforeLoad: require is_admin)
 *
 * The admin screens live under `/manage/*`, NOT `/admin/*`: `/admin/*` is the
 * admin REST API, which the server routes before the SPA fallback, so a UI
 * route there would answer a refresh / bookmark / deep link with raw JSON
 * (or a 404/405). The server 302-redirects a browser navigation to a former
 * `/admin/...` UI path to its `/manage/...` equivalent (`web_ui.rs`).
 */
export const routes = rootRoute('root.tsx', [
  route('/login', 'Login.tsx'),
  route('/invite', 'Invite.tsx'),
  layout('app', 'AppLayout.tsx', [
    index('Browse.tsx'),
    route('/repos/$repo', 'RepoBrowse.tsx'),
    route('/packages/$repo/$id', 'PackageDetail.tsx'),
    route('/images/$repo/$', 'ImageDetail.tsx'),
    route('/tokens', 'Tokens.tsx'),
    route('/cli-login/$secret', 'CliLogin.tsx'),
    route('/manage', 'AdminLayout.tsx', [
      index('admin/AdminHome.tsx'),
      route('/repositories', 'admin/repositories/List.tsx'),
      route('/repositories/new', 'admin/repositories/Create.tsx'),
      route('/repositories/$repo', 'admin/repositories/Edit.tsx'),
      route(
        '/repositories/$repo/members',
        'admin/repositories/GroupMembers.tsx',
      ),
      route('/repositories/$repo/import', 'admin/repositories/Import.tsx'),
      route(
        '/repositories/$repo/retention',
        'admin/repositories/Retention.tsx',
      ),
      route('/users', 'admin/users/List.tsx'),
      route('/users/new', 'admin/users/Create.tsx'),
      route('/users/$userId', 'admin/users/Edit.tsx'),
      route('/roles', 'admin/roles/List.tsx'),
      route('/roles/$roleId', 'admin/roles/Edit.tsx'),
      route('/content-selectors', 'admin/selectors/List.tsx'),
      route('/content-selectors/new', 'admin/selectors/Create.tsx'),
      route('/content-selectors/$selectorId', 'admin/selectors/Edit.tsx'),
      route('/realms', 'admin/realms/List.tsx'),
      route('/realms/new', 'admin/realms/Create.tsx'),
      route('/realms/$realmId', 'admin/realms/Edit.tsx'),
      route('/settings', 'admin/settings/Settings.tsx'),
      route('/settings/email', 'admin/settings/Email.tsx'),
      route('/settings/retention', 'admin/settings/RetentionSettings.tsx'),
      route('/system', 'admin/system/System.tsx'),
    ]),
  ]),
])
