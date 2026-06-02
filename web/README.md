# forge-web

The envisia-forge admin + browse UI: a **SPA** (TanStack Router, client-only)
built by Vite. The Rust `server` serves the built assets from `dist/` at a
**single origin**, so the browser calls the Rust HTTP API (`/admin/*`,
`/browse/*`, `/v3/*`) **directly** with relative URLs. There is no Node server
and no API proxy in production.

## Develop

```bash
npm install
# Run the Rust server (forge-server) on http://localhost:3000 in another shell.
FORGE_DEV_API_TARGET=http://localhost:3000 npm run dev   # Vite on :5173
```

The Vite dev server proxies `/admin`, `/browse`, `/v3`, `/auth` to
`FORGE_DEV_API_TARGET` so dev is single-origin too (relative URLs, no CORS).
This proxy is a dev-only static-routing convenience with no production
equivalent.

## Build

```bash
npm ci
npm run build      # tsc --noEmit + vite build -> dist/
```

The Rust server serves `dist/` when `web.enabled = true` (config) with
`web.assets_dir` pointing at it (default `web/dist`). See
`crates/server/src/web_ui.rs`.

## Test

```bash
npm test           # vitest (jsdom + React Testing Library)
```

## Layout

- `src/lib/` — cross-cutting, no JSX: `config.ts` (API base URL),
  `httpClient.ts` (fetch wrapper + auth injection + 401 handling),
  `auth.ts` (the single module a §12.2 cookie-session swap touches),
  `queryClient.ts`.
- `src/api/` — one typed module per resource (request fns + query-key
  factories + DTO types mirroring the Rust DTOs).
- `src/queries/` — TanStack Query hooks wrapping `src/api/`.
- `src/routes.ts` — virtual file routes (declared here, generated into
  `src/routeTree.gen.ts` by `@tanstack/router-plugin`; never hand-author route
  files or the generated tree).
- `src/routes/` — route components.
