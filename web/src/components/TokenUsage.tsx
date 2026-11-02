import { useState } from 'react'

import type { BrowseRepo } from '~/api/packages'
import type { TokenScope } from '~/api/tokens'
import {
  CodeBlock,
  CommandSnippet,
  Panel,
  SelectField,
  Tabs,
  formatLabel,
} from '~/components/ui'
import { aptAuth, npmAuthKey, npmrc, yarnrc } from '~/components/PackageConnect'

/** The formats the panel has snippets for, in tab order. */
export const USAGE_FORMATS = ['nuget', 'npm', 'docker', 'raw', 'apt'] as const
export type UsageFormat = (typeof USAGE_FORMATS)[number]

/** One copyable command, or the contents of a configuration file. */
export type UsageSnippet =
  | { kind: 'command'; label: string; command: string; copyLabel: string }
  | { kind: 'file'; title: string; code: string; copyLabel: string }

function isUsageFormat(format: string): format is UsageFormat {
  return (USAGE_FORMATS as readonly string[]).includes(format)
}

/**
 * The repositories a token's snippets can name: those of a format with
 * snippets and an address for it, within the token's repository scope.
 */
export function usableRepositories(
  repositories: ReadonlyArray<BrowseRepo>,
  scope: TokenScope | null | undefined,
): BrowseRepo[] {
  const only = scope?.repositories ?? null
  return repositories.filter(
    (repo) =>
      isUsageFormat(repo.format) &&
      (repo.format === 'docker' ? !!repo.registry && !!repo.pull_prefix : !!repo.url) &&
      (only === null || only.includes(repo.id)),
  )
}

/**
 * Whether the snippets offer pushing to `repo`: a hosted repository (or a
 * group, which takes a push through its writable member) and a token not
 * limited to reading. The owner's own rights still decide.
 */
function offersPush(repo: BrowseRepo, scope: TokenScope | null | undefined): boolean {
  if (scope?.level === 'read') return false
  return repo.kind === 'hosted' || (repo.format === 'docker' && repo.kind === 'group')
}

/**
 * A word for a POSIX shell: as it is when it holds no character the shell
 * reads, otherwise single-quoted. API tokens (URL-safe base64) and Forge's
 * usernames (UPNs) mostly need no quotes.
 */
export function shellWord(word: string): string {
  return /^[A-Za-z0-9@%+=:,./_-]+$/.test(word) ? word : `'${word.replace(/'/g, `'\\''`)}'`
}

/**
 * The XML element name NuGet keys a source's credentials by
 * (`packageSourceCredentials`): the source name with what XML refuses in a
 * name escaped as `_xHHHH_`, as NuGet's `XmlConvert.EncodeLocalName` does. A
 * repository name may start with a digit, which no XML name may.
 */
export function nugetCredentialsElement(source: string): string {
  const hex = (c: string) => `_x${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}_`
  return Array.from(source)
    .map((c, i) => {
      if (c === '_' && /^_x[0-9A-Fa-f]{4}_/.test(source.slice(i))) return hex(c)
      if (i === 0) return /[A-Za-z_]/.test(c) ? c : hex(c)
      return /[A-Za-z0-9._-]/.test(c) ? c : hex(c)
    })
    .join('')
}

/** The `NuGet.config` of the NuGet repository `repo` at `url`, with credentials. */
export function nugetConfig(repo: string, url: string, username: string, token: string): string {
  const element = nugetCredentialsElement(repo)
  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<configuration>',
    '  <packageSources>',
    `    <add key="${repo}" value="${url}/index.json" />`,
    '  </packageSources>',
    '  <packageSourceCredentials>',
    `    <${element}>`,
    `      <add key="Username" value="${xmlAttr(username)}" />`,
    `      <add key="ClearTextPassword" value="${xmlAttr(token)}" />`,
    `    </${element}>`,
    '  </packageSourceCredentials>',
    '</configuration>',
  ].join('\n')
}

function xmlAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/**
 * The commands and configuration files that use the API token `token` of
 * `username` with `repo`, the token filled in: `docker login`, `.npmrc`,
 * `NuGet.config`, `curl`, apt's `auth.conf.d`. Pushes are offered when
 * `canPush`.
 */
export function tokenUsageSnippets(
  repo: BrowseRepo,
  username: string,
  token: string,
  canPush: boolean,
): UsageSnippet[] {
  const user = shellWord(username)
  const secret = shellWord(token)
  const url = repo.url ?? ''
  switch (repo.format) {
    case 'nuget':
      return [
        {
          kind: 'command',
          label: 'Add the source',
          command: `dotnet nuget add source ${url}/index.json --name ${repo.name} --username ${user} --password ${secret} --store-password-in-clear-text`,
          copyLabel: 'Copy add-source command',
        },
        ...(canPush
          ? [
              {
                kind: 'command' as const,
                label: 'Push a package (the token is the API key)',
                command: `dotnet nuget push <package>.nupkg --source ${repo.name} --api-key ${secret}`,
                copyLabel: 'Copy push command',
              },
            ]
          : []),
        {
          kind: 'file',
          title: 'NuGet.config',
          code: nugetConfig(repo.name, url, username, token),
          copyLabel: 'Copy NuGet.config',
        },
      ]
    case 'npm':
      return [
        {
          kind: 'command',
          label: 'Store the token for the registry',
          command: `npm config set ${npmAuthKey(url)}:_authToken ${secret}`,
          copyLabel: 'Copy npm config command',
        },
        {
          kind: 'file',
          title: '.npmrc (npm, pnpm, Bun, Yarn 1)',
          code: npmrc(url, token),
          copyLabel: 'Copy .npmrc',
        },
        {
          kind: 'file',
          title: '.yarnrc.yml (Yarn 2 and later)',
          code: yarnrc(url, token),
          copyLabel: 'Copy .yarnrc.yml',
        },
      ]
    case 'docker': {
      const registry = repo.registry ?? ''
      const prefix = repo.pull_prefix ?? ''
      return [
        {
          kind: 'command',
          label: 'Log in (Docker; Podman and nerdctl take the same)',
          command: `echo ${secret} | docker login ${registry} --username ${user} --password-stdin`,
          copyLabel: 'Copy docker login command',
        },
        {
          kind: 'command',
          label: 'Log in with Helm (charts in this repository)',
          command: `echo ${secret} | helm registry login ${registry} --username ${user} --password-stdin`,
          copyLabel: 'Copy helm registry login command',
        },
        {
          kind: 'command',
          label: 'Pull an image',
          command: `docker pull ${prefix}/<image>:<tag>`,
          copyLabel: 'Copy pull command',
        },
        ...(canPush
          ? [
              {
                kind: 'command' as const,
                label: 'Push an image',
                command: `docker push ${prefix}/<image>:<tag>`,
                copyLabel: 'Copy push command',
              },
            ]
          : []),
      ]
    }
    case 'raw':
      return [
        {
          kind: 'command',
          label: 'Download a file (the token as the password)',
          command: `curl -u ${shellWord(`${username}:${token}`)} -O ${url}/<path>`,
          copyLabel: 'Copy download command',
        },
        {
          kind: 'command',
          label: 'Or as a Bearer token',
          command: `curl -H ${shellWord(`Authorization: Bearer ${token}`)} -O ${url}/<path>`,
          copyLabel: 'Copy Bearer download command',
        },
        ...(canPush
          ? [
              {
                kind: 'command' as const,
                label: 'Upload a file',
                command: `curl -u ${shellWord(`${username}:${token}`)} --upload-file <file> ${url}/<path>`,
                copyLabel: 'Copy upload command',
              },
            ]
          : []),
      ]
    case 'apt':
      return [
        {
          kind: 'file',
          title: `/etc/apt/auth.conf.d/${repo.name}.conf`,
          code: aptAuth(url, username, token),
          copyLabel: 'Copy auth.conf entry',
        },
        ...(canPush
          ? [
              {
                kind: 'command' as const,
                label: 'Upload a package',
                command: `curl -u ${shellWord(`${username}:${token}`)} -H "Content-Type: multipart/form-data" --data-binary "@<package>.deb" ${url}/`,
                copyLabel: 'Copy upload command',
              },
            ]
          : []),
      ]
    default:
      return []
  }
}

/**
 * "Use this token": shown under a token just created (on Your tokens and on
 * an account's page in the admin screens), the commands and configuration
 * files of each format with the token and its owner's username filled in, for
 * a repository the token reaches. A tab per format the reader can see a
 * repository of; the repository is picked from a list.
 *
 * `repositories` are the readable repositories (`/browse/repos`), which name
 * the client addresses. The token's own scope narrows them.
 */
export function TokenUsage({
  token,
  username,
  scope,
  repositories,
}: {
  token: string
  username: string
  scope: TokenScope | null | undefined
  repositories: ReadonlyArray<BrowseRepo>
}) {
  const usable = usableRepositories(repositories, scope)
  const formats = USAGE_FORMATS.filter((f) => usable.some((r) => r.format === f))
  const [format, setFormat] = useState<UsageFormat | null>(null)
  const [repoName, setRepoName] = useState<string | null>(null)

  if (formats.length === 0) return null
  const current = format && formats.includes(format) ? format : formats[0]!
  const ofFormat = usable.filter((r) => r.format === current)
  const repo = ofFormat.find((r) => r.name === repoName) ?? ofFormat[0]!
  const snippets = tokenUsageSnippets(repo, username, token, offersPush(repo, scope))

  return (
    <Panel
      title="Use this token"
      description={
        <>
          Paste one of these into the client: the token is filled in, as the password
          of <code>{username}</code>. Like the token, they are shown only now.
        </>
      }
    >
      <Tabs
        label="Client"
        idPrefix="token-usage"
        items={formats.map((f) => ({ id: f, label: formatLabel(f) || f }))}
        value={current}
        onChange={(f) => {
          setFormat(f)
          setRepoName(null)
        }}
      />
      <div
        role="tabpanel"
        id={`token-usage-${current}`}
        aria-labelledby={`token-usage-tab-${current}`}
        className="flex flex-col gap-4"
      >
        {ofFormat.length > 1 && (
          <SelectField
            label="Repository"
            value={repo.name}
            onChange={(e) => setRepoName(e.target.value)}
          >
            {ofFormat.map((r) => (
              <option key={r.id} value={r.name}>
                {r.name}
              </option>
            ))}
          </SelectField>
        )}
        {ofFormat.length === 1 && (
          <p className="fg-field-desc">
            Repository <code>{repo.name}</code>
          </p>
        )}
        {snippets.map((snippet) =>
          snippet.kind === 'command' ? (
            <CommandSnippet
              key={snippet.label}
              label={snippet.label}
              command={snippet.command}
              copyLabel={snippet.copyLabel}
            />
          ) : (
            <CodeBlock
              key={snippet.title}
              title={snippet.title}
              code={snippet.code}
              copyLabel={snippet.copyLabel}
              placeholders={['<package>', '<path>', '<file>', '<image>', '<tag>']}
            />
          ),
        )}
      </div>
    </Panel>
  )
}
