import { Link } from '@tanstack/react-router'

import { CommandSnippet, CopyField, Panel } from '~/components/ui'

/** One copyable command of a format's connect panel. */
interface Snippet {
  label: string
  command: string
  copyLabel: string
}

/**
 * The client commands for a repository of `format` at `url` (its
 * `/browse/repos` address), named `repo` in the client's configuration.
 * Push commands are left out unless `canPush`. A format without commands of
 * its own (a WebAssembly plugin's) gets the repository URL.
 */
export function connectSnippets(
  format: string,
  repo: string,
  url: string,
  canPush: boolean,
): Snippet[] {
  switch (format) {
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
 * "Connect" panel of a package repository (NuGet, or another format
 * plugin's): the address to copy, the client commands for it, and where the
 * password comes from — clients authenticate with an API token (from the
 * Your tokens screen), not the UI sign-in. Docker repositories have
 * `DockerConnect`.
 */
export function PackageConnect({
  format,
  repo,
  url,
  canPush = false,
}: {
  format: string
  repo: string
  url: string
  canPush?: boolean
}) {
  const snippets = connectSnippets(format, repo, url, canPush)
  return (
    <Panel
      title="Connect"
      description={
        <>
          Use your username and an API token as the password; create one
          under{' '}
          <Link to="/tokens" className="fg-link">
            Your tokens
          </Link>
          .
        </>
      }
    >
      {format === 'nuget' && (
        <CopyField
          label="Service index"
          value={`${url}/index.json`}
          copyLabel="Copy service index"
        />
      )}
      {snippets.map((snippet) => (
        <CommandSnippet key={snippet.label} {...snippet} prompt={snippet.command !== url} />
      ))}
    </Panel>
  )
}
