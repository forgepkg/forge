import { describe, expect, it } from 'vitest'

import { indexedPackages, parseParagraphs, words } from './AptIndex'

describe('apt indexes', () => {
  it('reads a Release file', () => {
    const [release] = parseParagraphs(
      'Origin: Forge\nSuite: bookworm\nArchitectures: all amd64 arm64\nComponents: contrib main\nSHA256:\n abc 12 main/binary-amd64/Packages\n',
    )
    expect(release.Suite).toBe('bookworm')
    expect(words(release.Architectures)).toEqual(['all', 'amd64', 'arm64'])
    expect(words(release.Components)).toEqual(['contrib', 'main'])
    expect(release.SHA256).toBe('\nabc 12 main/binary-amd64/Packages')
  })

  it('lists the packages of a Packages index by name', () => {
    expect(
      indexedPackages(
        'Package: zeta\nVersion: 1.0-1\nArchitecture: amd64\nDescription: last\n more\n\n' +
          'Package: alpha\r\nVersion: 2:3.0\r\nArchitecture: all\r\nSection: utils\r\n',
      ),
    ).toEqual([
      { name: 'alpha', version: '2:3.0', architecture: 'all', section: 'utils', summary: undefined },
      { name: 'zeta', version: '1.0-1', architecture: 'amd64', section: undefined, summary: 'last' },
    ])
    expect(indexedPackages('')).toEqual([])
  })
})
