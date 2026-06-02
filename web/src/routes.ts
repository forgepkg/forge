import { index, rootRoute } from '@tanstack/virtual-file-routes'

/**
 * Virtual file routes (TanStack Router convention):
 * route components live in `src/routes/` and the tree is declared *here*, then
 * generated into `src/routeTree.gen.ts` by `@tanstack/router-plugin`. Do not
 * hand-author route files or the generated tree.
 *
 * Phase 1 ships only the app shell + a placeholder home route that proves the
 * single-origin serving + `GET /admin/me` round-trip. The full IA (login,
 * browse, package detail, admin areas) lands in later phases per the plan §5.
 */
export const routes = rootRoute('root.tsx', [
  //
  index('Home.tsx'),
])
