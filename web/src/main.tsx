import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { createRouter, RouterProvider } from '@tanstack/react-router'

import { makeQueryClient } from '~/lib/queryClient'
import { initTheme } from '~/lib/theme'
import { routeTree } from './routeTree.gen'
import './styles.css'

// Re-apply the stored light/dark preference and follow OS changes while in
// "system" (the index.html bootstrap already painted the right theme).
initTheme()

const queryClient = makeQueryClient()

const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: 'intent',
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
