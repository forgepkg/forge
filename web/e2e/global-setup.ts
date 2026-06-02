import { setup } from './harness'

/**
 * Playwright globalSetup: boot the infra + Rust server serving the built SPA.
 * Runs once before the whole suite; teardown is the symmetric globalTeardown.
 */
export default async function globalSetup() {
  await setup()
}
