import { describe, expect, it } from 'vitest'

import { canonicalUsername, upnError } from './users'

/** The same cases as `crates/db/src/username.rs`, which stays authoritative. */
describe('upnError', () => {
  it('accepts UPNs with subdomains, Unicode domains and A-labels', () => {
    for (const name of [
      'alice@example.com',
      ' Alice@Example.COM ',
      'alice.smith@corp.example.com',
      'a@b.c',
      'first.last+ci@mail.example.org',
      "o'brien@example.ie",
      'x-1@a-b.example',
      'jürgen@müller.example',
      'Jürgen@Müller.Example',
      'user@例え.テスト',
      'user@उदाहरण.परीक्षा',
      'jürgen@xn--mller-kva.example',
      `alice@${'a'.repeat(63)}.example`,
      `alice@${'ü'.repeat(63)}.example`,
    ]) {
      expect(upnError(name), name).toBeNull()
    }
  })

  it('refuses names that are not UPNs', () => {
    for (const name of [
      'alice',
      'alice@corp@example.com',
      '@example.com',
      'alice@',
      'alice smith@example.com',
      'alice smith@example.com',
      'alice@localhost',
      'alice@example.com.',
      'alice@example..com',
      'alice@-corp.example',
      'alice@corp-.example',
      `alice@${'a'.repeat(64)}.example`,
      'alice@corp_1.example',
      'alice@127.0.0.1',
    ]) {
      expect(upnError(name), name).toBe(
        'The username must be a UPN such as alice@example.com.',
      )
    }
  })

  it('canonicalizes like the server', () => {
    expect(canonicalUsername('  Alice@Example.COM ')).toBe('alice@example.com')
    expect(canonicalUsername('José')).toBe('josé')
  })
})
