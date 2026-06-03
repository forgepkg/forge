import { defineConfig, devices } from '@playwright/test'

import { BASE_URL } from './e2e/harness'

/**
 * Playwright config for the envisia-forge SPA e2e suite.
 *
 * The suite drives a **real `forge-server`** serving the **built** SPA against
 * the slice-1 infra (Postgres + versitygw), brought up in globalSetup. The
 * browser therefore exercises the production single-origin model: relative API
 * URLs, no Node proxy, no CORS.
 *
 * Requirements to run locally / in CI:
 *   - Docker (for Postgres + versitygw containers)
 *   - a built server (`cargo build -p forge-server`) — globalSetup builds it
 *   - Playwright browsers installed (`pnpm run e2e:install`)
 *
 * If browsers can't be downloaded in a sandbox, `tsc`/`playwright test --list`
 * still type-check and enumerate the specs (see DEVELOPMENT.md).
 */
export default defineConfig({
  testDir: './e2e/specs',
  // The whole suite shares one server; keep it serial for deterministic state.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  timeout: 30_000,
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
