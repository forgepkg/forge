import { describe, expect, it } from 'vitest'

import { connectSnippets, npmrc, yarnrc } from './PackageConnect'

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
