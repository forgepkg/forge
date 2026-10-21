import { Link } from '@tanstack/react-router'

import { Subheading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { CommandSnippet } from '~/components/CopyButton'

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
    case 'helm':
      return [
        {
          label: 'Add the repository',
          command: `helm repo add ${repo} ${url} --username <username> --password <token>`,
          copyLabel: 'Copy repo-add command',
        },
        {
          label: 'Install a chart',
          command: `helm install <release> ${repo}/<chart>`,
          copyLabel: 'Copy install command',
        },
        ...(canPush
          ? [
              {
                label: 'Push a chart',
                command: `curl -u <username>:<token> --data-binary @<chart>-<version>.tgz ${url}/api/charts`,
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
 * "Connect" panel of a package repository (NuGet, Helm, or another format
 * plugin's): copyable client commands for its address, and where the
 * password comes from — clients authenticate with an API token (from the
 * Tokens screen), not the UI sign-in. Docker repositories have
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
  return (
    <section
      aria-labelledby="package-connect"
      className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <div>
        <Subheading id="package-connect">Connect</Subheading>
        <Text className="mt-1">
          Use your username and an API token as the password — create one on
          the{' '}
          <Link
            to="/tokens"
            className="text-sky-600 hover:underline dark:text-sky-400"
          >
            Tokens
          </Link>{' '}
          page.
        </Text>
      </div>
      {connectSnippets(format, repo, url, canPush).map((snippet) => (
        <CommandSnippet key={snippet.label} {...snippet} />
      ))}
    </section>
  )
}
