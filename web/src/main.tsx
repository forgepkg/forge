import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { createRouter, RouterProvider } from '@tanstack/react-router'

import { makeQueryClient } from '~/lib/queryClient'
import { installChunkReloadHandler } from '~/lib/chunkReload'
import { initTheme } from '~/lib/theme'
import { RouteError } from '~/components/RouteError'
import { routeTree } from './routeTree.gen'
import '@fontsource-variable/ibm-plex-sans/wght.css'
import '@fontsource-variable/jetbrains-mono/wght.css'
import './styles.css'

// Re-apply the stored theme and follow OS changes while in "system" (the
// index.html bootstrap already painted the right theme).
initTheme()

// A lazy chunk from a previous deploy that no longer exists: reload once to
// pick up the new build (the router's error component is the second half).
installChunkReloadHandler()

const queryClient = makeQueryClient()

const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: 'intent',
  // Stale lazy chunk after a deploy -> reload once; other errors as before.
  defaultErrorComponent: RouteError,
  // SPA mode: there is no SSR; the router renders fully on the client.
  scrollRestoration: true,
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

const rootElement = document.getElementById('root')
if (!rootElement) throw new Error('root element #root missing from index.html')

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
)
