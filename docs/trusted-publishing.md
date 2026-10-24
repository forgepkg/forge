# Trusted publishing with workload identity

Forge can authenticate a CI job with its short-lived OIDC identity token instead
of a stored API key. The token is validated against the configured
issuer's discovery document and JWKS, matched against explicit claim rules, and
mapped to an ordinary Forge RBAC role. No user or browser session is created.

A job uses its token in one of two ways:

- **Token exchange (recommended).** The job sends the token once to
  `POST /api/v2/token` and gets a short-lived workload API key back, exactly as
  nuget.org's trusted publishing works. It publishes with
  `dotnet nuget push --api-key <key>` and restores with the key as the Basic
  password of the username `oidc`. [npm](#npm) performs its own native
  exchange automatically. Each token is redeemed once.
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
  by unrelated jobs and never count as an identity; and
- the mapped role authorizes both the target repository and canonical package
  ID. Use package selectors on publisher roles to bind a CI identity to the
  package namespace it owns.

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
same realm fence described below. It snapshots repository, realm,
issuer, role, canonical package ID/version, validated token `iat`, and SHA-256
digests of subject and `jti`; raw claims and bearer tokens are not retained.
Immediately before commit, Forge locks the current realm and role and compares
the complete normalized realm-config digest with the config that authenticated
the request. A stale peer realm snapshot is therefore denied after an audience,
claim-rule, token-lifetime, or other realm-config edit. Repository grants and
selectors are enforced before this hook; they are not re-evaluated by the audit
insert itself.
The table has no cascading foreign keys and a database trigger rejects UPDATE
or DELETE, so ordinary application-level repository/realm/role removal preserves
the snapshotted names. This is an internal append-only application ledger, not a
tamper-evident or external transparency log: a database owner can still disable
the trigger or truncate the table, and the row does not capture every provider
claim, matched rule, source commit, or ref. An admin API/UI and externally
verifiable attestations are follow-up work.

### Token exchange

`POST /api/v2/token` takes the job's token as `Authorization: Bearer`, with
nuget.org's request body (optional here):

```http
POST /api/v2/token
Authorization: Bearer <CI OIDC token>
Content-Type: application/json

{"username": "oidc", "tokenType": "ApiKey"}
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
- The key authorizes as the token's workload: same realm, role and audit
  identity. A publish with it records the exchanged token's subject and `jti`
  digests and its `iat` in `trusted_publish_audit`.
- **Revocation:** a key is honoured only while its realm is enabled with the
  very configuration it was issued under. Editing anything in the realm
  (rules, audiences, lifetimes, its name) or disabling or deleting it revokes
  all of its outstanding keys on the next request, for good: enabling the
  realm again or reverting the edit does not bring them back. A key issued
  under the new configuration works on every instance at once, also on
  those that have not reloaded the realm yet. Deleting the role leaves the
  key without rights. A registry token `docker login -u oidc` got with a
  key stops working within 10 seconds of the same changes, and expires no
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

1.0.0 reserved no names: an account named `oidc` from 1.0.0 needs renaming,
as the 1.1.0 upgrade notes in `CHANGELOG.md` describe.

Other Basic usernames still work with a direct token, as before. Prefer `oidc`:
it is the one name that can never mean an account.

## GitHub Actions

Create a `workload_identity` realm under **Admin → Authentication**. Use stable
numeric identity claims rather than repository/owner names, which can be
renamed. A protected environment or exact ref is a useful additional boundary.

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
      "role": "github-widgets-publisher",
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
scope the issued key: the realm's role and package selectors authorize its
use. The exchange has no repository, so a role without write permission can
receive a key but its publish is refused with 403. Per-package trusted
publishers are not implemented yet.

npm silently falls back to configured credentials when the exchange fails;
omit stored tokens in jobs intended to require trusted publishing. Forge
does not serve npm's package-visibility endpoint. npm 11.5.1 can enable
provenance automatically for public GitHub repositories without checking that
endpoint, so pass `--provenance=false` to `npm publish` for those clients.
Forge rejects provenance statements until attestations can be stored.

## GitLab CI

Use GitLab's immutable numeric project/namespace claims and require protected
refs or a protected environment for release jobs:

```json
{
  "issuer": "https://gitlab.com",
  "allowed_audiences": ["https://forge.example.com"],
  "clock_skew_seconds": 60,
  "max_token_age_seconds": 39600,
  "positive_cache_seconds": 60,
  "rules": [
    {
      "role": "gitlab-widgets-publisher",
      "conditions": [
        { "claim": "job_project_id", "any_of": ["1001"] },
        { "claim": "job_namespace_id", "any_of": ["2001"] },
        { "claim": "ref_protected", "any_of": ["true"] }
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
