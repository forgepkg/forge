import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'

/**
 * Vite config for the Forge SPA.
 *
 * Production: `vite build` emits a static SPA into `dist/` (`index.html` +
 * `assets/*`). The Rust `server` serves that directory directly (single
 * origin); the browser uses **relative** API URLs, so there is structurally no
 * Node proxy in production.
 *
 * Development: Vite serves assets + HMR. To keep dev single-origin (so the same
 * relative API URLs work and the CORS path is never exercised), the dev server
 * proxies the Rust API prefixes verbatim to a running `forge-server`. This is a
 * dev-only static-routing convenience, NOT an API proxy in the architectural
 * sense — it adds no logic and has no production equivalent. Point it at the
 * Rust origin with `FORGE_DEV_API_TARGET` (defaults to http://127.0.0.1:8421).
 */
const apiTarget = process.env.FORGE_DEV_API_TARGET ?? 'http://127.0.0.1:8421'

export default defineConfig({
  clearScreen: false,
  plugins: [
    // Virtual file routes declared in src/routes.ts -> src/routeTree.gen.ts.
    tanstackRouter({
      target: 'react',
      virtualRouteConfig: './src/routes.ts',
      autoCodeSplitting: true,
    }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '~': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 8420,
    proxy: {
      '/admin': { target: apiTarget, changeOrigin: false },
      '/browse': { target: apiTarget, changeOrigin: false },
      '/v3': { target: apiTarget, changeOrigin: false },
      '/v2': { target: apiTarget, changeOrigin: false },
      '/raw': { target: apiTarget, changeOrigin: false },
      '/npm': { target: apiTarget, changeOrigin: false },
      '/auth': { target: apiTarget, changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    // The Rust ServeDir serves /assets/* verbatim; keep the default layout.
    sourcemap: false,
  },
})
