# Trusted publishing with workload identity

Forge can authenticate a CI job with its short-lived OIDC identity token instead
of a stored API key. The token is validated against the configured
issuer's discovery document and JWKS, matched against explicit claim rules, and
mapped to an ordinary Forge RBAC role. A matching trusted publisher can add
package-scoped write or delete rights on one hosted repository. No user or
browser session is created.

A job uses its token in one of two ways:

- **Token exchange (recommended).** The job sends the token once to
  `POST /api/v2/token` and gets a short-lived workload API key back, exactly as
  nuget.org's trusted publishing works. It publishes with
  `dotnet nuget push --api-key <key>` and restores with the key as the Basic
  password of the username `oidc`. [npm](#npm) performs its own native
  exchange automatically, and [`docker login`](#docker--oci-images) takes
  the key as the password of `oidc`. Each token is redeemed once.
- **Direct token.** The job presents the token itself on every request, as the
  Basic password (username `oidc`), the `X-NuGet-ApiKey` or a Bearer token.

The implementation supports workload-only discovery documents containing just
`issuer` and `jwks_uri`, including GitHub Actions. Interactive OIDC login keeps
its stricter discovery requirements and remains a separate realm kind.

## Security model

A workload token is accepted only when all of these checks pass:

- RSA signature and an explicit, non-empty `kid`; a missing `kid` fails before
  metadata fetch. An unknown `kid` may claim one cooldown-gated JWKS refresh
  and then fails closed, so random-key traffic cannot force a refetch per
  request;
- exact configured issuer and at least one exact allowed audience (wildcards are
  rejected);
- required `exp`, `iat`, and `sub`, plus `nbf` when present;
- `iat` is not in the future, token age is within `max_token_age_seconds`, and
  the declared `exp - iat` lifetime is also within that bound;
- optional `azp` is in `allowed_authorized_parties` when that list is configured;
- the first matching rule has at least one explicit claim condition; catch-all
  rules are rejected. A rule must also contain a workload identity condition:
  issuer/audience/time/ref/environment conditions alone are rejected because
  they can match unrelated jobs. For GitHub Actions, every rule must include
  both `repository_id` and `repository_owner_id`; GitLab.com requires a numeric
  project ID (`job_project_id` or `project_id`) and namespace ID
  (`job_namespace_id` or `namespace_id`). Mutable paths and `sub` are optional
  extra boundaries, not identity anchors. Any other issuer (self-managed
  GitLab, GitHub Enterprise Server, other CI systems) must pin one of the
  built-in stable identity claims (`sub`, `repository_id`,
  `repository_owner_id`, `repository`, `repository_owner`,
  `job_workflow_ref`, `workflow_ref`, `project_id`, `job_project_id`,
  `namespace_id`, `job_namespace_id`, `project_path`, `namespace_path`) or a
  claim the realm declares in `identity_claims` (for a CI system with its own
  workload identifier); claims such as `actor` or `event_name` can be shared
  by unrelated jobs and never count as an identity. The one exception is an
  **issuer-wide** rule (`"issuer_wide": true`, **Every project of this
  issuer** in the web UI), the opt-in for a self-managed issuer whose
  workloads all may read. It matches every token of the realm's issuer
  without an identity condition; conditions on context such as
  `ref_protected` may narrow it, and none is required. Forge refuses it for
  GitHub Actions and GitLab.com, whose tokens anyone can mint, and a
  self-managed GitLab with open sign-up is just as public: every account that
  can create a project and run a pipeline, in a personal namespace or a fork
  too, gets the role. Rules are first-match, so an issuer-wide rule must come
  after every other rule. A workload it matched holds its role's grants
  capped at `read`, with the CI token, an exchanged key and the registry
  tokens minted from either: a `write` or `delete` grant the role holds, or
  is given later, never reaches every project. Writes stay pinned to a
  workload identity: a rule for the project ahead of the issuer-wide one
  picks a role of its own, and a trusted publisher still adds `write` for its
  own project on top of the issuer-wide read; and
- a realm rule must accept the token and map it to a role; a trusted publisher
  alone never authenticates a workload. The role continues to grant base access,
  commonly `read` on hosted and proxy repositories, while a trusted publisher
  adds write or delete rights only for its hosted repository and matching
  canonical package IDs.

Positive signature-verification results may be cached only when the token has a
`jti`. The cache key includes the complete token digest and validation-policy
digest, and its TTL is the smaller of `positive_cache_seconds` and the remaining
time to `exp`. Claim rules and role lookup still run for every request.

In the direct-token flow a valid token can be reused for the multiple HTTP
requests a native NuGet operation makes until `exp`; `jti` is not a one-time
consumption ledger there. Keep provider token lifetimes short and set
`max_token_age_seconds` accordingly.

Every successful workload publish — and every unlist, relist and delete a
workload performs — appends a `trusted_publish_audit` row (its `action` says
which) in the same PostgreSQL transaction as the package change, behind the
same realm and publisher fences described below. It snapshots repository,
realm, issuer, role, canonical package ID/version, validated token `iat`, and
SHA-256 digests of subject and `jti`; raw claims and bearer tokens are not
retained. When a trusted publisher authorized the write, the audit also records
its id and name snapshot; both are null when the role authorized it. Immediately
before commit, Forge locks the current realm and role and compares the complete
normalized realm-config digest with the config that authenticated the request.
It also rechecks matched publisher definition digests. A realm edit revokes that
realm's keys; editing or deleting a publisher withdraws only its rights from
already issued keys and registry tokens. Repository grants and selectors are
enforced before this hook; they are not re-evaluated by the audit insert itself.
The table has no cascading foreign keys and a database trigger rejects UPDATE
or DELETE, so ordinary application-level repository/realm/role removal preserves
the snapshotted names. This is an internal append-only application ledger, not a
tamper-evident or external transparency log: a database owner can still disable
the trigger or truncate the table, and the row does not capture every provider
claim, matched rule, source commit, or ref. Externally verifiable attestations
remain future work.

### Token exchange

`POST /api/v2/token` takes the job's token as `Authorization: Bearer`, with
nuget.org's request body (optional here):

```http
POST /api/v2/token
Authorization: Bearer <CI OIDC token>
Content-Type: application/json

{"username": "oidc", "tokenType": "ApiKey"}
```

Add a trusted publisher to the hosted `releases` repository. GitLab's protected
environment deploy access determines which jobs may use `nuget-release`; Forge
checks the signed claims and does not make that provider-side decision:

```json
{
  "name": "widgets-release",
  "description": "Protected GitLab release environment for Acme.Widgets",
  "realm": "gitlab-com",
  "packages": { "includes": ["Acme.Widgets.*"], "excludes": [] },
  "actions": ["write"],
  "conditions": [
    { "claim": "job_project_id", "any_of": ["1001"] },
    { "claim": "job_namespace_id", "any_of": ["2001"] },
    { "claim": "environment", "any_of": ["nuget-release"] },
    { "claim": "environment_protected", "any_of": ["true"] }
  ]
}
```

```json
{"apiKey": "forge_wif.…", "expires": "2026-10-21T15:04:05Z"}
```

- The token passes every check above (the realm's claim rules pick the role),
  and it must carry a `jti`: each `(issuer, jti)` is exchanged **once**, so a
  token captured from a job log cannot be redeemed again. A second exchange,
  a token without `jti`, an API key in place of a token and a token of an
  issuer no realm trusts all get 401.
- `username` is optional and, when given, must be `oidc`; `tokenType`, when
  given, must be `ApiKey` (400 otherwise). Identity comes only from the
  verified token, never from the body.
- The key lives for the realm's `api_key_ttl_seconds` (60 to 86400, default
  3600, nuget.org's lifetime), independent of the token's own `exp`. That
  matters for GitLab, whose token lives as long as the job's timeout.
- The key authorizes as the token's workload: same realm, role, matched trusted
  publishers and audit identity. A publish with it records the exchanged
  token's subject and `jti` digests and its `iat` in `trusted_publish_audit`.
- **Revocation:** a key is honoured only while its realm is enabled with the
  very configuration it was issued under. Editing anything in the realm
  (rules, audiences, lifetimes, its name) or disabling or deleting it revokes
  all of its outstanding keys on the next request, for good: enabling the
  realm again or reverting the edit does not bring them back. A key issued
  under the new configuration works on every instance at once, also on
  those that have not reloaded the realm yet. Deleting the role leaves the
  key without role rights. Editing or deleting a trusted publisher similarly
  revokes only that publisher's rights from existing keys and registry tokens;
  the realm's other keys keep working. A registry token `docker login -u oidc`
  got with a key stops working within 10 seconds of these changes, and expires no
  later than the key. Forge stores only SHA-256 digests of the key, subject
  and `jti` (table `workload_api_key`), and the auth reaper deletes a row
  once the key has expired and the token has been expired for 15 minutes
  (the most clock skew a realm accepts, plus a margin). Whether a token has
  expired is decided on the database's clock, so an instance whose clock
  runs behind it cannot redeem a token twice.
- A key starts with `forge_wif.`, which no user API token can (user tokens
  are URL-safe base64, without a dot). Secret scanners can match
  `forge_wif\.[A-Za-z0-9_-]{43}`.
- The key is accepted as `X-NuGet-ApiKey` (`--api-key`, or the `NUGET_API_KEY`
  environment variable from .NET SDK 10.0.300), as a Bearer token, or as the
  Basic password of the username `oidc`.

This implements the exchange profile of the OpenSSF Trusted Publishers
guidance: a short-lived, repository-controlled publish credential and
one-time `jti` redemption. The direct-token flow stays available for clients
that cannot run an exchange step.

### The `oidc` username

`oidc` is a reserved account name. HTTP Basic with the username `oidc` (in
any case) is only ever checked as a workload credential: the password must be
a token of an enabled `workload_identity` realm or a workload API key. Anything
else, including a user's API token, is refused with 401, and it never reaches
the password realms, so it is never forwarded to a credential-forwarding
upstream. No account can be created, bootstrapped or provisioned under the name
(it is no UPN either), and the browser login refuses it.

Other Basic usernames still work with a direct token, as before. Prefer `oidc`:
it is the one name that can never mean an account.

## GitHub Actions

Create a `workload_identity` realm under **Admin → Authentication**. Give its
reader role `read` access to this hosted repository and the feeds the project
restores from. Its realm rule accepts the project's jobs and maps them to that
role. Use stable numeric identity claims rather than repository/owner names,
which can be renamed.

Also pin **which workflow** may publish and **how it was triggered**:
`job_workflow_ref` (e.g.
`acme/widgets/.github/workflows/release.yml@refs/heads/main`) keeps any other
workflow in the repository — including one a contributor adds in a pull
request — from minting a usable token, and `event_name` (e.g. `push` or
`release`) excludes `pull_request_target`, `workflow_dispatch` and similar
triggers you did not intend.

```json
{
  "issuer": "https://token.actions.githubusercontent.com",
  "allowed_audiences": ["https://forge.example.com"],
  "clock_skew_seconds": 60,
  "max_token_age_seconds": 900,
  "positive_cache_seconds": 60,
  "rules": [
    {
      "role": "ci-reader",
      "conditions": [
        { "claim": "repository_id", "any_of": ["987654321"] },
        { "claim": "repository_owner_id", "any_of": ["1234567"] }
      ]
    }
  ]
}
```

Then add a trusted publisher on the hosted repository at
**Admin → Repositories → releases → Trusted publishers**. This pins publishing
to the release workflow while the realm rule above keeps all jobs in the
repository eligible for read access:

```json
{
  "name": "widgets-release",
  "description": "Protected GitHub release workflow for Acme.Widgets packages",
  "realm": "github-actions",
  "packages": { "includes": ["Acme.Widgets.*"], "excludes": [] },
  "actions": ["write"],
  "conditions": [
    { "claim": "repository_id", "any_of": ["987654321"] },
    { "claim": "repository_owner_id", "any_of": ["1234567"] },
    { "claim": "ref", "any_of": ["refs/heads/main"] },
    {
      "claim": "job_workflow_ref",
      "any_of": ["acme/widgets/.github/workflows/release.yml@refs/heads/main"]
    },
    { "claim": "event_name", "any_of": ["push"] }
  ]
}
```

The workflow needs only read access to the checkout plus permission to request
an OIDC token. The official `NuGet/login` action requests it with the audience
configured above and exchanges it at Forge's token endpoint. Push to the hosted
repository's publish URL with `--no-service-endpoint`: the client then sends a
single `PUT` carrying the key, without first fetching the private service
index, so no source credentials are needed for the push.

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-dotnet@v4

  - name: Exchange the OIDC token for a Forge API key
    uses: NuGet/login@v1
    id: forge
    with:
      user: oidc
      audience: https://forge.example.com
      token-service-url: https://forge.example.com/api/v2/token

  - name: Restore and build
    shell: bash
    env:
      # `forge` is the repository's nuget.config source (no credentials in it).
      NuGetPackageSourceCredentials_forge: Username=oidc;Password=${{ steps.forge.outputs.NUGET_API_KEY }}
    run: |
      dotnet restore
      dotnet pack -c Release -o artifacts --no-restore

  - name: Publish
    shell: bash
    run: >-
      dotnet nuget push "artifacts/*.nupkg"
      --source https://forge.example.com/repository/releases/package
      --no-service-endpoint
      --api-key "${{ steps.forge.outputs.NUGET_API_KEY }}"
```

`NuGetPackageSourceCredentials_<name>` applies to the source of that name in
`nuget.config`; the name must be a valid environment-variable name (no `-`),
and NuGet ignores a malformed value without a message.

#### Without the exchange

Pass the token itself as the NuGet API key and the source password:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-dotnet@v4

  - name: Request Forge identity token
    id: forge-token
    shell: bash
    run: |
      response="$(curl --fail --silent --show-error \
        -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=https%3A%2F%2Fforge.example.com")"
      token="$(jq -r '.value' <<<"${response}")"
      echo "::add-mask::${token}"
      echo "token=${token}" >> "${GITHUB_OUTPUT}"

  - name: Publish
    shell: bash
    env:
      FORGE_TOKEN: ${{ steps.forge-token.outputs.token }}
      NUGET_CONFIG: ${{ runner.temp }}/forge-nuget-${{ github.run_id }}-${{ github.run_attempt }}.config
    run: |
      umask 077
      printf '%s\n' '<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear /></packageSources></configuration>' > "${NUGET_CONFIG}"
      chmod 600 "${NUGET_CONFIG}"
      dotnet nuget add source \
        https://forge.example.com/repository/releases/index.json \
        --name forge-oidc \
        --username oidc \
        --password "${FORGE_TOKEN}" \
        --store-password-in-clear-text \
        --configfile "${NUGET_CONFIG}"
      dotnet nuget push artifacts/*.nupkg \
        --source forge-oidc \
        --api-key "${FORGE_TOKEN}" \
        --configfile "${NUGET_CONFIG}"

  - name: Remove temporary Forge credentials
    if: always()
    shell: bash
    env:
      NUGET_CONFIG: ${{ runner.temp }}/forge-nuget-${{ github.run_id }}-${{ github.run_attempt }}.config
    run: |
      if [[ -f "${NUGET_CONFIG}" ]]; then
        dotnet nuget remove source forge-oidc --configfile "${NUGET_CONFIG}" >/dev/null 2>&1 || true
        rm -f "${NUGET_CONFIG}"
      fi
```

See GitHub's [OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)
for the current claim set and subject customization options.

## npm

npm 11.5.1 and later can exchange a CI identity token automatically during
`npm publish`, without a stored `_authToken` or a curl step. npm 11.21 and
later also supports the exchange for `npm dist-tag`. Use a current npm release
with this support; pnpm, Yarn and Bun do not perform npm's exchange.

Configure a `workload_identity` realm under **Admin → Authentication**, using
the GitHub Actions or GitLab claim rules shown in this document, but set
`allowed_audiences` to `["npm:forge.example.com"]`. The audience is
`npm:<registry hostname>`, not the registry URL, port or repository path.
If the realm also serves NuGet, add this audience alongside its existing one.

Give the mapped role **write** on the hosted npm repository and, when
publishing through a group, **read** on the group and **write** on its
writable member. Package selectors on that role can restrict the package
namespace.

### GitHub Actions

Use the GitHub issuer and immutable repository/owner IDs from the
[GitHub Actions configuration](#github-actions) above, with the npm audience.
Do not configure `NODE_AUTH_TOKEN` or `_authToken`:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: '26'
  - run: npm ci
  - run: npm publish --provenance=false --registry https://forge.example.com/repository/npm-all/
```

npm requests the GitHub job's ID token with the `npm:forge.example.com`
audience, exchanges it at Forge and uses the resulting key for the command.
For private dependencies, `npm ci` still needs separate read credentials;
the automatic exchange is for publishing, not installing.

### GitLab CI, including self-hosted GitLab

Use the [GitLab realm configuration](#gitlab-ci) below with the npm audience.
GitLab supplies the token through `NPM_ID_TOKEN`:

```yaml
publish:
  image: mirror.gcr.io/library/node:26
  timeout: 10m
  id_tokens:
    NPM_ID_TOKEN:
      aud: npm:forge.example.com
  script:
    - npm ci
    - npm publish --registry https://forge.example.com/repository/npm-all/
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $CI_COMMIT_REF_PROTECTED == "true"'
```

Self-hosted GitLab works the same way: set the realm's `issuer` to the exact
`iss` in that instance's job tokens, for example `https://gitlab.example.com`,
instead of `https://gitlab.com`. Pin numeric project and namespace IDs in the
claim rules, plus protected-ref or environment restrictions. Older GitLab
versions without `job_project_id` / `job_namespace_id` can use `project_id` /
`namespace_id`. Forge must be able to reach that issuer's HTTPS discovery
document and JWKS and trust its TLS certificate, including for a private
instance. Do not enable `allow_http_issuer` for production. Set
`max_token_age_seconds` to cover the job timeout, as described below.

### Exchange and limitations

npm calls `POST /-/npm/v1/oidc/token/exchange/package/<escaped-name>` at the
**host root**, even when the registry is `/repository/npm-all/`. Reverse proxies must
forward this root path to Forge, not only `/repository/`. The answer is
`{"token":"forge_wif.…"}`; invalid requests or credentials receive a JSON
`error` and 400 or 401 (temporary authentication failures receive 503).

Both exchange endpoints share the same one-redemption-per-`(issuer, jti)`
ledger, realm checks and `api_key_ttl_seconds`. The named package does not
scope the issued key: the realm's role and matched trusted publishers authorize
its use. The exchange has no repository, so a key may be issued even when the
workload has no publisher for that package; its publish is refused with 403.

npm silently falls back to configured credentials when the exchange fails;
omit stored tokens in jobs intended to require trusted publishing. Forge
does not serve npm's package-visibility endpoint. npm 11.5.1 can enable
provenance automatically for public GitHub repositories without checking that
endpoint, so pass `--provenance=false` to `npm publish` for those clients.
Forge rejects provenance statements until attestations can be stored.

## GitLab CI

[GitLab CI with workload identity](gitlab-ci.md) walks through this setup step
by step, from the role to the `.gitlab-ci.yml`;
[CI with service accounts](ci-service-accounts.md) covers pipelines that
cannot use workload identity.

Give the realm's reader role `read` access to the hosted repository and the
feeds the project restores from. The realm rule accepts jobs from the project,
so every pipeline can restore; a separate trusted publisher limits writes to
the protected release environment and selected packages.

```json
{
  "issuer": "https://gitlab.com",
  "allowed_audiences": ["https://forge.example.com"],
  "clock_skew_seconds": 60,
  "max_token_age_seconds": 39600,
  "positive_cache_seconds": 60,
  "rules": [
    {
      "role": "ci-reader",
      "conditions": [
        { "claim": "job_project_id", "any_of": ["1001"] },
        { "claim": "job_namespace_id", "any_of": ["2001"] }
      ]
    }
  ]
}
```

GitLab gives an ID token the job's timeout as its lifetime, so
`max_token_age_seconds` must be at least the longest timeout of a job that
publishes. The default, 39600 (11 hours), covers jobs up to 11 hours; set a
lower value when your release jobs are shorter. The exchanged key lives for the
realm's `api_key_ttl_seconds` instead, whatever the job's timeout.

Ask GitLab to mint an ID token with that exact audience, exchange it, and push
to the publish URL with `--no-service-endpoint` (see GitHub Actions above):

```yaml
publish:
  environment:
    name: nuget-release
  id_tokens:
    FORGE_ID_TOKEN:
      aud: https://forge.example.com
  script:
    - >-
      export NUGET_API_KEY="$(curl --fail --silent --show-error
      -X POST https://forge.example.com/api/v2/token
      -H "Authorization: Bearer $FORGE_ID_TOKEN"
      -H 'Content-Type: application/json'
      -d '{"username":"oidc","tokenType":"ApiKey"}' | jq -r .apiKey)"
    - export NuGetPackageSourceCredentials_forge="Username=oidc;Password=$NUGET_API_KEY"
    - dotnet restore
    - dotnet pack -c Release -o artifacts --no-restore
    - >-
      dotnet nuget push "artifacts/*.nupkg"
      --source https://forge.example.com/repository/releases/package
      --no-service-endpoint
      --api-key "$NUGET_API_KEY"
```

#### Without the exchange

```yaml
publish:
  id_tokens:
    FORGE_ID_TOKEN:
      aud: https://forge.example.com
  script:
    - export NUGET_CONFIG="$CI_PROJECT_DIR/.forge-nuget-$CI_JOB_ID.config"
    - umask 077
    - printf '%s\n' '<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear /></packageSources></configuration>' > "$NUGET_CONFIG"
    - chmod 600 "$NUGET_CONFIG"
    - >-
      dotnet nuget add source
      https://forge.example.com/repository/releases/index.json
      --name forge-oidc
      --username oidc
      --password "$FORGE_ID_TOKEN"
      --store-password-in-clear-text
      --configfile "$NUGET_CONFIG"
    - >-
      dotnet nuget push artifacts/*.nupkg
      --source forge-oidc
      --api-key "$FORGE_ID_TOKEN"
      --configfile "$NUGET_CONFIG"
  after_script:
    - export NUGET_CONFIG="$CI_PROJECT_DIR/.forge-nuget-$CI_JOB_ID.config"
    - dotnet nuget remove source forge-oidc --configfile "$NUGET_CONFIG" >/dev/null 2>&1 || true
    - rm -f "$NUGET_CONFIG"
```

See GitLab's [ID-token authentication reference](https://docs.gitlab.com/ci/secrets/id_token_authentication/)
for provider claim semantics.

In the direct-token examples the temporary Basic source is intentional. The
.NET NuGet client resolves the service index before it sends the push API key,
and `--api-key` is not attached to that initial GET (pushing to the publish URL
with `--no-service-endpoint`, as the exchange examples do, skips that GET). Supplying the same short-lived OIDC token as the source
password authenticates both phases; the cleanup step removes it even after a
failed push. The examples use a job-unique, mode-0600 config rather than the
runner's default/global NuGet.Config, so concurrent jobs cannot reuse it and
ordinary failure cleanup removes the bearer. Cleanup is best-effort: hard runner
termination can leave the file until the token expires, so prefer ephemeral
runners. An `anonymous_read` repository can omit this temporary source and push
directly by URL, but that deliberately exposes the repository's read-side
metadata according to the configured anonymous policy.

## Docker / OCI images

The registry takes a workload the way the feeds do: the job logs in with the
username `oidc` and its workload key as the password. The key is the
workload's, not NuGet's: the [token exchange](#token-exchange) issues it, and
`NuGet/login` gets one for `docker login` as well. For each pull or push the
client presents the key to the registry's token service, which answers a
short-lived registry token for the images and actions the job asks for
([Logging in](docker.md#logging-in)). A registry token stops working within
10 seconds of the key's revocation, and expires no later than the key.

Keep the realm and its rule of [GitHub Actions](#github-actions) or
[GitLab CI](#gitlab-ci), and give the rule's role `read` on the docker
repositories the jobs pull from. Then add a trusted publisher to the hosted
docker repository the images go to. Its packages are **image names**, without
the repository's name: the image `forge.example.com/docker-hosted/acme/widgets`
of the repository `docker-hosted` is `acme/widgets`. A `*` also matches `/`,
so `acme/*` takes in `acme/widgets/api` as well.

```json
{
  "name": "widgets-images",
  "description": "Images of acme/widgets from the release workflow",
  "realm": "github-actions",
  "packages": { "includes": ["acme/widgets"], "excludes": [] },
  "actions": ["write"],
  "conditions": [
    { "claim": "repository_id", "any_of": ["987654321"] },
    { "claim": "repository_owner_id", "any_of": ["1234567"] },
    { "claim": "ref", "any_of": ["refs/heads/main"] },
    {
      "claim": "job_workflow_ref",
      "any_of": ["acme/widgets/.github/workflows/release.yml@refs/heads/main"]
    },
    { "claim": "event_name", "any_of": ["push"] }
  ]
}
```

A GitLab publisher takes the conditions of the
[one above](#token-exchange), with the environment of the job that pushes
the images. A job the publisher does not match pulls with the role's `read`,
and its push is refused. Every push of a workload is recorded in
`trusted_publish_audit`, and so is every delete.

### GitHub Actions

`NuGet/login` exchanges the job's token, and `docker login` takes the key
from standard input:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v4

  - name: Exchange the OIDC token for a Forge API key
    uses: NuGet/login@v1
    id: forge
    with:
      user: oidc
      audience: https://forge.example.com
      token-service-url: https://forge.example.com/api/v2/token

  - name: Log in to Forge's registry
    shell: bash
    env:
      FORGE_KEY: ${{ steps.forge.outputs.NUGET_API_KEY }}
    run: echo "$FORGE_KEY" | docker login forge.example.com -u oidc --password-stdin

  - name: Build and push the image
    shell: bash
    env:
      IMAGE: forge.example.com/docker-hosted/acme/widgets
    run: |
      docker build -t "$IMAGE:$GITHUB_SHA" .
      docker push "$IMAGE:$GITHUB_SHA"
```

`docker/login-action` logs in the same way, with `registry:
forge.example.com`, `username: oidc` and the key as `password`. The login
serves `docker buildx` and the other clients that read Docker's
`config.json`, and a `FROM` image in Forge is pulled with it and the role's
`read`. Helm keeps a login of its own: `helm registry login
forge.example.com -u oidc --password-stdin`.

The .NET SDK builds and pushes an image itself, with
[`dotnet publish`](#dotnet-publish):

```yaml
  - uses: actions/setup-dotnet@v4

  - name: Publish the image
    shell: bash
    env:
      DOTNET_CONTAINER_REGISTRY_UNAME: oidc
      DOTNET_CONTAINER_REGISTRY_PWORD: ${{ steps.forge.outputs.NUGET_API_KEY }}
    run: >-
      dotnet publish -c Release --os linux --arch x64 -t:PublishContainer
      -p:ContainerRegistry=forge.example.com
      -p:ContainerRepository=docker-hosted/acme/widgets
      -p:ContainerImageTag=$GITHUB_SHA
```

### GitLab CI

The job asks GitLab for an ID token with the realm's audience, exchanges it
and logs in. The `docker` image has busybox `wget` but no `curl` or `jq`, so
`wget` runs the exchange and `sed` picks the key out of the answer. The job
needs a runner set up for Docker-in-Docker (GitLab's
[Use Docker to build Docker images](https://docs.gitlab.com/ci/docker/using_docker_build/)):

```yaml
variables:
  FORGE_URL: https://forge.example.com
  FORGE_REGISTRY: forge.example.com
  IMAGE: forge.example.com/docker-hosted/acme/widgets

docker-image:
  stage: deploy
  image: mirror.gcr.io/library/docker:29-cli
  services:
    - name: mirror.gcr.io/library/docker:29-dind
      alias: docker
  id_tokens:
    FORGE_ID_TOKEN:
      aud: https://forge.example.com
  environment:
    name: image-release
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - |
      FORGE_KEY="$(wget -qO- --header "Authorization: Bearer $FORGE_ID_TOKEN" \
        --header 'Content-Type: application/json' \
        --post-data '{"username":"oidc","tokenType":"ApiKey"}' \
        "$FORGE_URL/api/v2/token" \
        | sed -n 's/.*"apiKey":"\([^"]*\)".*/\1/p')"
      test -n "$FORGE_KEY"
      echo "$FORGE_KEY" | docker login "$FORGE_REGISTRY" -u oidc --password-stdin
    - docker build -t "$IMAGE:$CI_COMMIT_TAG" .
    - docker push "$IMAGE:$CI_COMMIT_TAG"
```

`FORGE_KEY="$(…)"` stays a plain assignment, so that `test -n` fails the job
when the exchange fails. The `services` entry gives the daemon the host name
`docker`, where the `docker` image looks for it; GitLab would otherwise name
the service after its image's path.

With [`dotnet publish`](#dotnet-publish) the job needs no Docker daemon, and
the .NET SDK image has `curl`:

```yaml
dotnet-image:
  stage: deploy
  image: mcr.microsoft.com/dotnet/sdk:10.0
  id_tokens:
    FORGE_ID_TOKEN:
      aud: https://forge.example.com
  environment:
    name: image-release
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - |
      FORGE_KEY="$(curl --fail --silent --show-error -X POST "$FORGE_URL/api/v2/token" \
        -H "Authorization: Bearer $FORGE_ID_TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{"username":"oidc","tokenType":"ApiKey"}' \
        | sed -n 's/.*"apiKey":"\([^"]*\)".*/\1/p')"
      test -n "$FORGE_KEY"
      export DOTNET_CONTAINER_REGISTRY_UNAME=oidc
      export DOTNET_CONTAINER_REGISTRY_PWORD="$FORGE_KEY"
    - >-
      dotnet publish -c Release --os linux --arch x64 -t:PublishContainer
      -p:ContainerRegistry=$FORGE_REGISTRY
      -p:ContainerRepository=docker-hosted/acme/widgets
      -p:ContainerImageTag=$CI_COMMIT_TAG
```

### dotnet publish

`dotnet publish -t:PublishContainer` (built into the .NET SDK from 8.0.200)
builds the image and pushes it to `ContainerRegistry` itself, without a
Docker daemon.

- **Names.** `ContainerRegistry` is Forge's host, and `ContainerRepository`
  the repository's name followed by the image's:
  `docker-hosted/acme/widgets`. For a repository with a
  [host](docker.md#names) of its own, `ContainerRegistry` is that host and
  `ContainerRepository` the image alone.
- **Credentials.** The SDK takes them from `DOTNET_CONTAINER_REGISTRY_UNAME`
  and `DOTNET_CONTAINER_REGISTRY_PWORD`, and from Docker's `config.json`
  when they are not set: a job that ran `docker login -u oidc` needs no
  variables.
- **A base image in Forge** (`-p:ContainerBaseImage=forge.example.com/docker/dotnet/aspnet:10.0`,
  through a proxy of `https://mcr.microsoft.com`) is pulled with the same
  variables, or the same `config.json`. They never reach another registry:
  the default base image comes from MCR without credentials.
- **`DOTNET_CONTAINER_PUSH_REGISTRY_UNAME` / `_PWORD`** serve the push alone.
  With them, a base image in Forge needs `DOTNET_CONTAINER_PULL_REGISTRY_UNAME`
  / `_PWORD` as well, set to the same `oidc` and key; without them or a
  `config.json`, the publish fails with `CONTAINER1008`.
- **Identity tokens fail.** A `config.json` entry or credential helper that
  answers an identity token (the user name `<token>`) makes the SDK ask for
  the registry token with an OAuth2 `POST` alone. Forge's token service
  answers `GET` with Basic credentials and refuses the `POST`, so the
  publish fails with `CONTAINER1016`. `docker login -u oidc` and the
  variables give a user name and a password.

## Operational guidance

- Give each CI trust policy its own repository-scoped role. Forge rejects WIF
  rules that map to the built-in global `admin` role.
- Keep all rules for one issuer in one enabled realm. Forge rejects duplicate
  enabled WIF issuers so routing cannot depend on realm order.
- Grant a selector-scoped `write` level (which includes `read`) on the
  intended hosted repository, using an include/exclude package selector such
  as `Acme.Widgets.*`. The `read` it includes serves a private feed's
  service-index GET; it does not widen access beyond that selector on
  package-addressed routes.
- Prefer numeric provider IDs and add a protected ref/environment condition.
  A ref or environment is an additional boundary, not a workload identity by
  itself. Forge does not require one: a rule that pins only the repository or
  project lets **any** branch and any workflow of it publish (bypassing branch
  protection), including `pull_request_target` runs and, on GitLab, a
  pipeline for a fork's merge request run in the parent project. On GitHub
  add `job_workflow_ref` plus a protected ref or an `environment` to every
  publishing rule; GitLab tokens have no `job_workflow_ref`, so there add
  `ref_protected = true` or an `environment`, and prefer the `job_*` ids:
  `project_id` and `namespace_id` name a merge request's *source* project.
- Use a dedicated, exact audience for Forge; never reuse a broad cloud audience.
- Set `positive_cache_seconds = 0` to disable the per-token positive verdict
  cache. Discovery and JWKS have their own caches (JWKS defaults to one hour),
  so this does not force signing-key revocation to be fetched on every request.
  The positive verdict cache itself never extends past its configured TTL or
  token expiry.
- When the issuer's discovery document or JWKS cannot be fetched (a timeout,
  a refused connection, a 5xx) and is not cached yet, a workload token
  cannot be checked: the exchange, the feeds and `/v2/token` answer 503 with
  `Retry-After` rather than 401, so clients that retry do. This happens on a
  cold cache only: after a restart, on a new replica, or when the JWKS cache
  expires (hourly by default) during the issuer's outage.
- Treat a token as a bearer credential until `exp`, and a workload key until
  its `expires`: mask both in CI logs and do not persist them as an artifact,
  cache entry, or repository secret. Exchange right before restoring or
  publishing; a key outlives the job only up to `api_key_ttl_seconds`, so
  lower it when your jobs are short.
- To revoke every outstanding workload key of a realm at once, edit or disable
  the realm; the keys stay revoked when you enable it again.
