import { Link } from '@tanstack/react-router'

import { Subheading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { CommandSnippet } from '~/components/CopyButton'

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
    <section
      aria-labelledby="docker-connect"
      className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <div>
        <Subheading id="docker-connect">Connect</Subheading>
        <Text className="mt-1">
          Log in with your username and an API token as the password — create
          one on the{' '}
          <Link
            to="/tokens"
            className="text-sky-600 hover:underline dark:text-sky-400"
          >
            Tokens
          </Link>{' '}
          page.
        </Text>
      </div>
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
    </section>
  )
}
