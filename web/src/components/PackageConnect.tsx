import { Link } from '@tanstack/react-router'

import { CodeBlock, CommandSnippet, CopyField, Panel } from '~/components/ui'

/** One copyable command of a format's connect panel. */
interface Snippet {
  label: string
  command: string
  copyLabel: string
}

/** What else the snippets of some formats need: apt's kind and distribution. */
export interface ConnectContext {
  kind?: string
  options?: Record<string, string>
}

/**
 * The client commands for a repository of `format` at `url` (its
 * `/browse/repos` address), named `repo` in the client's configuration.
 * Push commands are left out unless `canPush`. A format without commands of
 * its own gets the repository URL.
 */
export function connectSnippets(
  format: string,
  repo: string,
  url: string,
  canPush: boolean,
  context: ConnectContext = {},
): Snippet[] {
  switch (format) {
    case 'apt': {
      const distribution = context.options?.distribution ?? '<distribution>'
      if (context.kind === 'proxy') {
        return [
          {
            label: 'Add the source (the upstream signs its indexes: trust its keyring)',
            command: `echo "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] ${url}/ ${distribution} main" | sudo tee /etc/apt/sources.list.d/${repo}.list`,
            copyLabel: 'Copy add-source command',
          },
        ]
      }
      return [
        {
          label: 'Trust the repository’s signing keys',
          command: `curl -fsSL ${url}/key.asc | sudo tee /etc/apt/keyrings/${repo}.asc > /dev/null`,
          copyLabel: 'Copy key download command',
        },
        {
          label: 'Add the source',
          command: `echo "${aptSource(repo, url, distribution)}" | sudo tee /etc/apt/sources.list.d/${repo}.list`,
          copyLabel: 'Copy add-source command',
        },
        ...(canPush
          ? [
              {
                label: 'Upload a package',
                command: `curl -u <username>:<token> -H "Content-Type: multipart/form-data" --data-binary "@<package>.deb" ${url}/`,
                copyLabel: 'Copy upload command',
              },
            ]
          : []),
      ]
    }
    case 'nuget':
      return [
        {
          label: 'Add the source',
          command: `dotnet nuget add source ${url}/index.json --name ${repo} --username <username> --password <token> --store-password-in-clear-text`,
          copyLabel: 'Copy add-source command',
        },
        ...(canPush
          ? [
              {
                label: 'Push a package',
                command: `dotnet nuget push <package>.nupkg --source ${repo} --api-key <token>`,
                copyLabel: 'Copy push command',
              },
            ]
          : []),
      ]
    case 'npm':
      return [
        {
          label: 'Use the registry',
          command: `npm config set registry ${url}/`,
          copyLabel: 'Copy set-registry command',
        },
        {
          label: 'Or only for a scope',
          command: `npm config set @<scope>:registry ${url}/`,
          copyLabel: 'Copy scope-registry command',
        },
        {
          label: 'Sign in',
          command: `npm login --registry ${url}/`,
          copyLabel: 'Copy login command',
        },
        ...(canPush
          ? [
              {
                label: 'Publish a package',
                command: `npm publish --registry ${url}/`,
                copyLabel: 'Copy publish command',
              },
            ]
          : []),
      ]
    default:
      return [
        {
          label: 'Repository URL',
          command: url,
          copyLabel: 'Copy repository URL',
        },
      ]
  }
}

/**
 * The `.npmrc` lines that point npm, pnpm, Bun and Yarn 1 at the npm
 * registry at `url`, with an API token: `npm login` writes the same
 * `_authToken` line.
 */
export function npmrc(url: string): string {
  const path = url.replace(/^[a-z]+:/i, '')
  return `registry=${url}/\n${path}/:_authToken=<token>`
}

/** The `sources.list` line of a hosted apt repository, its keys at `/etc/apt/keyrings/<repo>.asc`. */
export function aptSource(repo: string, url: string, distribution: string): string {
  return `deb [signed-by=/etc/apt/keyrings/${repo}.asc] ${url}/ ${distribution} main`
}

/**
 * The `/etc/apt/auth.conf.d/` entry of the repository at `url`: apt sends
 * credentials over plain HTTP only to a machine written with `http://`.
 */
export function aptAuth(url: string): string {
  let machine = url
  try {
    const parsed = new URL(url)
    machine = `${parsed.protocol === 'http:' ? 'http://' : ''}${parsed.host}${parsed.pathname.replace(/\/$/, '')}`
  } catch {
    // Not a URL: shown as it is.
  }
  return `machine ${machine}\nlogin <username>\npassword <token>`
}

/** The `.yarnrc.yml` settings of Yarn 2 and later for the registry at `url`. */
export function yarnrc(url: string): string {
  return `npmRegistryServer: "${url}/"\nnpmAlwaysAuth: true\nnpmAuthToken: "<token>"`
}

/**
 * "Connect" panel of a package repository (NuGet, npm, or another format
 * plugin's): the address to copy, the client commands for it, and
 * where the password comes from — clients authenticate with an API token
 * (from the Your tokens screen, or for npm one `npm login` mints), not the
 * UI sign-in. Docker repositories have `DockerConnect`.
 */
export function PackageConnect({
  format,
  repo,
  url,
  kind,
  options,
  canPush = false,
}: {
  format: string
  repo: string
  url: string
  /** The repository's kind (apt's snippets differ for a proxy). */
  kind?: string
  /** The settings of its format's own (apt's distribution). */
  options?: Record<string, string>
  canPush?: boolean
}) {
  const snippets = connectSnippets(format, repo, url, canPush, { kind, options })
  const tokens = (
    <Link to="/tokens" className="fg-link">
      Your tokens
    </Link>
  )
  return (
    <Panel
      title="Connect"
      description={
        format === 'npm' ? (
          <>
            Sign in with <code>npm login</code>, or put an API token in{' '}
            <code>.npmrc</code>; create one under {tokens}.
          </>
        ) : (
          <>Use your username and an API token as the password; create one under {tokens}.</>
        )
      }
    >
      {format === 'nuget' && (
        <CopyField
          label="Service index"
          value={`${url}/index.json`}
          copyLabel="Copy service index"
        />
      )}
      {format === 'npm' && (
        <CopyField label="Registry URL" value={`${url}/`} copyLabel="Copy registry URL" />
      )}
      {format === 'apt' && (
        <CopyField
          label="Repository URL"
          value={`${url}/`}
          copyLabel="Copy repository URL"
          description={
            options?.distribution ? (
              <>
                Distribution <code>{options.distribution}</code>, components from the
                packages’ sections (<code>main</code> unless a section says otherwise).
              </>
            ) : undefined
          }
        />
      )}
      {snippets.map((snippet) => (
        <CommandSnippet key={snippet.label} {...snippet} prompt={snippet.command !== url} />
      ))}
      {format === 'apt' && (
        <>
          {kind !== 'proxy' && (
            <CodeBlock
              title={`/etc/apt/sources.list.d/${repo}.list`}
              copyLabel="Copy sources.list line"
              code={aptSource(repo, url, options?.distribution ?? '<distribution>')}
              placeholders={['<distribution>']}
            />
          )}
          <CodeBlock
            title={`/etc/apt/auth.conf.d/${repo}.conf`}
            copyLabel="Copy auth.conf entry"
            code={aptAuth(url)}
          />
          {kind !== 'proxy' && (
            <p className="fg-field-desc">
              Download the signing keys: <a href={`${url}/key.asc`} className="fg-link">key.asc</a>{' '}
              (armored) or <a href={`${url}/key.gpg`} className="fg-link">key.gpg</a> (binary keyring).
            </p>
          )}
        </>
      )}
      {format === 'npm' && (
        <>
          <CodeBlock
            title=".npmrc (npm, pnpm, Bun, Yarn 1)"
            copyLabel="Copy .npmrc"
            code={npmrc(url)}
            placeholders={['<token>']}
          />
          <CodeBlock
            title=".yarnrc.yml (Yarn 2 and later)"
            copyLabel="Copy .yarnrc.yml"
            code={yarnrc(url)}
            placeholders={['<token>']}
          />
        </>
      )}
    </Panel>
  )
}
