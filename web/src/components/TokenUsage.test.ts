import { describe, expect, it } from 'vitest'

import type { BrowseRepo } from '~/api/packages'
import {
  nugetConfig,
  nugetCredentialsElement,
  shellWord,
  tokenUsageSnippets,
  usableRepositories,
  type UsageSnippet,
} from './TokenUsage'

const TOKEN = 'AbC-_123xyz'
const USER = 'alice@example.com'

function repo(over: Partial<BrowseRepo> & Pick<BrowseRepo, 'name' | 'format'>): BrowseRepo {
  return { id: 1, kind: 'hosted', online: true, ...over }
}

function text(snippets: UsageSnippet[]): string[] {
  return snippets.map((s) => (s.kind === 'command' ? s.command : `${s.title}\n${s.code}`))
}

describe('tokenUsageSnippets', () => {
  it('fills the token into the NuGet source, push and NuGet.config', () => {
    const url = 'https://forge.example.com/repository/nuget-internal'
    const snippets = text(
      tokenUsageSnippets(repo({ name: 'nuget-internal', format: 'nuget', url }), USER, TOKEN, true),
    )
    expect(snippets[0]).toBe(
      `dotnet nuget add source ${url}/index.json --name nuget-internal --username ${USER} --password ${TOKEN} --store-password-in-clear-text`,
    )
    expect(snippets[1]).toBe(
      `dotnet nuget push <package>.nupkg --source nuget-internal --api-key ${TOKEN}`,
    )
    expect(snippets[2]).toContain(`<add key="nuget-internal" value="${url}/index.json" />`)
    expect(snippets[2]).toContain(`<add key="ClearTextPassword" value="${TOKEN}" />`)
    expect(snippets[2]).toContain(`<add key="Username" value="${USER}" />`)
  })

  it('leaves the push out when the token may not push', () => {
    const r = repo({ name: 'nu', format: 'nuget', url: 'http://h/repository/nu' })
    expect(text(tokenUsageSnippets(r, USER, TOKEN, false)).some((s) => s.includes('push'))).toBe(
      false,
    )
  })

  it('writes the .npmrc auth line npm reads for the registry', () => {
    const url = 'https://forge.example.com/repository/npm-all'
    const snippets = text(tokenUsageSnippets(repo({ name: 'npm-all', format: 'npm', url }), USER, TOKEN, true))
    expect(snippets[0]).toBe(
      `npm config set //forge.example.com/repository/npm-all/:_authToken ${TOKEN}`,
    )
    expect(snippets[1]).toBe(
      `.npmrc (npm, pnpm, Bun, Yarn 1)\nregistry=${url}/\n//forge.example.com/repository/npm-all/:_authToken=${TOKEN}`,
    )
    expect(snippets[2]).toContain(`npmAuthToken: "${TOKEN}"`)
  })

  it('logs Docker and Helm in to the registry with the token on stdin', () => {
    const r = repo({
      name: 'images',
      format: 'docker',
      registry: 'forge.example.com',
      pull_prefix: 'forge.example.com/images',
    })
    const snippets = text(tokenUsageSnippets(r, USER, TOKEN, true))
    expect(snippets).toEqual([
      `echo ${TOKEN} | docker login forge.example.com --username ${USER} --password-stdin`,
      `echo ${TOKEN} | helm registry login forge.example.com --username ${USER} --password-stdin`,
      'docker pull forge.example.com/images/<image>:<tag>',
      'docker push forge.example.com/images/<image>:<tag>',
    ])
  })

  it('sends the token as the Basic password or a Bearer token with curl', () => {
    const url = 'https://forge.example.com/repository/binaries'
    const snippets = text(tokenUsageSnippets(repo({ name: 'binaries', format: 'raw', url }), USER, TOKEN, true))
    expect(snippets).toEqual([
      `curl -u ${USER}:${TOKEN} -O ${url}/<path>`,
      `curl -H 'Authorization: Bearer ${TOKEN}' -O ${url}/<path>`,
      `curl -u ${USER}:${TOKEN} --upload-file <file> ${url}/<path>`,
    ])
  })

  it('writes apt’s auth.conf.d entry with the token', () => {
    const url = 'https://forge.example.com/repository/debian'
    const [auth] = tokenUsageSnippets(repo({ name: 'debian', format: 'apt', url }), USER, TOKEN, false)
    expect(auth).toEqual({
      kind: 'file',
      title: '/etc/apt/auth.conf.d/debian.conf',
      code: `machine forge.example.com/repository/debian\nlogin ${USER}\npassword ${TOKEN}`,
      copyLabel: 'Copy auth.conf entry',
    })
  })
})

describe('usableRepositories', () => {
  const repos: BrowseRepo[] = [
    repo({ id: 1, name: 'nu', format: 'nuget', url: 'http://h/repository/nu' }),
    repo({ id: 2, name: 'img', format: 'docker', registry: 'h', pull_prefix: 'h/img' }),
    repo({ id: 3, name: 'other', format: 'conda', url: 'http://h/repository/other' }),
    repo({ id: 4, name: 'gone', format: 'npm' }),
  ]

  it('keeps the repositories of a format with snippets and an address', () => {
    expect(usableRepositories(repos, null).map((r) => r.name)).toEqual(['nu', 'img'])
  })

  it('keeps only those a scoped token reaches', () => {
    expect(usableRepositories(repos, { repositories: [2] }).map((r) => r.name)).toEqual(['img'])
  })
})

describe('shellWord', () => {
  it('quotes only what the shell would read', () => {
    expect(shellWord('alice@example.com')).toBe('alice@example.com')
    expect(shellWord('o’brien@example.com')).toBe(`'o’brien@example.com'`)
    expect(shellWord("o'brien@example.com")).toBe(`'o'\\''brien@example.com'`)
  })
})

describe('nugetCredentialsElement', () => {
  it('escapes what an XML name refuses, as NuGet decodes it', () => {
    expect(nugetCredentialsElement('nuget-internal')).toBe('nuget-internal')
    expect(nugetCredentialsElement('1st.feed')).toBe('_x0031_st.feed')
    expect(nugetCredentialsElement('a_x0041_b')).toBe('a_x005F_x0041_b')
  })

  it('keys the credentials of a repository named with a leading digit', () => {
    const config = nugetConfig('2024', 'http://h/repository/2024', USER, TOKEN)
    expect(config).toContain('<_x0032_024>')
    expect(config).toContain('</_x0032_024>')
    expect(config).toContain('<add key="2024" value="http://h/repository/2024/index.json" />')
  })
})
