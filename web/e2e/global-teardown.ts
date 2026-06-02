import { teardown } from './harness'

/** Playwright globalTeardown: stop the server + remove the e2e containers. */
export default async function globalTeardown() {
  await teardown()
}
