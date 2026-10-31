import { describe, expect, it } from 'vitest'

import { aptAuth, aptSource, connectSnippets, npmrc, yarnrc } from './PackageConnect'

describe('connectSnippets', () => {
  it('gives a format without commands of its own its URL', () => {
    expect(
      connectSnippets('example', 'pkgs', 'https://forge.example.com/repository/pkgs', true),
    ).toEqual([
      {
        label: 'Repository URL',
        command: 'https://forge.example.com/repository/pkgs',
        copyLabel: 'Copy repository URL',
      },
    ])
  })

  it('leaves the push command out unless the repository takes pushes', () => {
    const labels = (canPush: boolean) =>
      connectSnippets('nuget', 'feed', 'https://f/repository/feed', canPush).map((s) => s.label)
    expect(labels(true)).toEqual(['Add the source', 'Push a package'])
    expect(labels(false)).toEqual(['Add the source'])
  })

  it('points npm at the registry URL with its trailing slash', () => {
    const snippets = connectSnippets('npm', 'npm-all', 'https://f.example/repository/npm-all', false)
    expect(snippets.map((s) => s.command)).toEqual([
      'npm config set registry https://f.example/repository/npm-all/',
      'npm config set @<scope>:registry https://f.example/repository/npm-all/',
      'npm login --registry https://f.example/repository/npm-all/',
    ])
    expect(
      connectSnippets('npm', 'npm-hosted', 'https://f.example/repository/npm-hosted', true).at(-1)
        ?.command,
    ).toBe('npm publish --registry https://f.example/repository/npm-hosted/')
  })
})

describe('npmrc', () => {
  it('scopes the token to the registry, without the scheme', () => {
    expect(npmrc('https://f.example/repository/npm-all')).toBe(
      'registry=https://f.example/repository/npm-all/\n//f.example/repository/npm-all/:_authToken=<token>',
    )
    expect(yarnrc('http://localhost:8080/repository/x')).toContain(
      'npmRegistryServer: "http://localhost:8080/repository/x/"',
    )
  })
})

describe('apt', () => {
  const url = 'https://forge.example.com/repository/apt-internal'

  it('trusts the repository key, adds the source and uploads like Nexus', () => {
    const snippets = connectSnippets('apt', 'apt-internal', url, true, {
      kind: 'hosted',
      options: { distribution: 'bookworm' },
    })
    expect(snippets.map((s) => s.command)).toEqual([
      `curl -fsSL ${url}/key.asc | sudo tee /etc/apt/keyrings/apt-internal.asc > /dev/null`,
      `echo "deb [signed-by=/etc/apt/keyrings/apt-internal.asc] ${url}/ bookworm main" | sudo tee /etc/apt/sources.list.d/apt-internal.list`,
      `curl -u <username>:<token> -H "Content-Type: multipart/form-data" --data-binary "@<package>.deb" ${url}/`,
    ])
    expect(
      connectSnippets('apt', 'apt-internal', url, false, {
        kind: 'hosted',
        options: { distribution: 'bookworm' },
      }),
    ).toHaveLength(2)
  })

  it("points a proxy's clients at the upstream's keyring", () => {
    const [source] = connectSnippets('apt', 'debian', url, false, {
      kind: 'proxy',
      options: { distribution: 'bookworm-security' },
    })
    expect(source.command).toContain('signed-by=/usr/share/keyrings/debian-archive-keyring.gpg')
    expect(source.command).toContain(`${url}/ bookworm-security main`)
  })

  it('writes the sources.list line and the auth.conf entry', () => {
    expect(aptSource('apt-internal', url, 'jammy')).toBe(
      `deb [signed-by=/etc/apt/keyrings/apt-internal.asc] ${url}/ jammy main`,
    )
    expect(aptAuth(url)).toBe(
      'machine forge.example.com/repository/apt-internal\nlogin <username>\npassword <token>',
    )
    // apt sends credentials over plain HTTP only to an http:// machine.
    expect(aptAuth('http://localhost:8421/repository/apt').split('\n')[0]).toBe(
      'machine http://localhost:8421/repository/apt',
    )
  })
})
