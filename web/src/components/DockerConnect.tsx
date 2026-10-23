import { Link } from '@tanstack/react-router'

import { CommandSnippet, Panel } from '~/components/ui'

/**
 * "Connect" panel of a docker repository: copyable `docker login` / `docker
 * pull` (and, for a hosted repository, `docker push`) commands with generic
 * `<image>:<tag>` placeholders, plus where the password comes from — the
 * registry authenticates `docker login` with an API token (from the Tokens
 * screen) as the password, not the UI sign-in.
 *
 * `registry` is the `host[:port]` to log in to and `pullPrefix` what image
 * names start with (`<registry>/<repo>`, or the repository's own host).
 */
export function DockerConnect({
  registry,
  pullPrefix,
  canPush = false,
}: {
  registry: string
  pullPrefix: string
  canPush?: boolean
}) {
  return (
    <Panel
      title="Connect"
      description={
        <>
          Log in with your username and an API token as the password; create
          one under{' '}
          <Link to="/tokens" className="fg-link">
            Your tokens
          </Link>
          .
        </>
      }
    >
      <CommandSnippet
        label="Log in"
        command={`docker login ${registry}`}
        copyLabel="Copy login command"
      />
      <CommandSnippet
        label="Pull an image"
        command={`docker pull ${pullPrefix}/<image>:<tag>`}
        copyLabel="Copy pull command"
      />
      {canPush && (
        <CommandSnippet
          label="Push an image"
          command={`docker push ${pullPrefix}/<image>:<tag>`}
          copyLabel="Copy push command"
        />
      )}
    </Panel>
  )
}
