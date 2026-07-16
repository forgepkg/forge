# Trusted publishing with workload identity

Forge can authenticate a CI job with its short-lived OIDC identity token instead
of a stored NuGet API key. The token is validated against the configured
issuer's discovery document and JWKS, matched against explicit claim rules, and
mapped to an ordinary Forge RBAC role. No user or browser session is created.

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
  extra boundaries, not identity anchors; and
- the mapped role authorizes both the target repository and canonical package
  ID. Use package selectors on publisher roles to bind a CI identity to the
  package namespace it owns.

Positive signature-verification results may be cached only when the token has a
`jti`. The cache key includes the complete token digest and validation-policy
digest, and its TTL is the smaller of `positive_cache_seconds` and the remaining
time to `exp`. Claim rules and role lookup still run for every request.

This is a direct-token flow. A valid token can be reused for the multiple HTTP
requests a native NuGet operation makes until `exp`; `jti` is not a one-time
consumption ledger. Keep provider token lifetimes short and set
`max_token_age_seconds` accordingly.

Relative to the OpenSSF Trusted Publishers guidance, Forge supports the direct
OIDC-token authentication variant. It does **not** yet implement the recommended
exchange for a repository-controlled short-lived publish token or consumed-`jti`
replay prevention. Treat this as compatible direct-token support, not full
alignment with the recommended token-exchange profile.

Every successful workload publish appends a `trusted_publish_audit` row in the
same PostgreSQL transaction as the package. It snapshots repository, realm,
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

## GitHub Actions

Create a `workload_identity` realm under **Admin → Authentication**. Use stable
numeric identity claims rather than repository/owner names, which can be
renamed. A protected environment or exact ref is a useful additional boundary.

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
        { "claim": "ref", "any_of": ["refs/heads/main"] }
      ]
    }
  ]
}
```

The workflow needs only read access to the checkout plus permission to request
an OIDC token. Request the exact audience configured above and pass the returned
token as the NuGet API key:

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
        https://forge.example.com/v3/releases/index.json \
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

## GitLab CI

Use GitLab's immutable numeric project/namespace claims and require protected
refs or a protected environment for release jobs:

```json
{
  "issuer": "https://gitlab.com",
  "allowed_audiences": ["https://forge.example.com"],
  "clock_skew_seconds": 60,
  "max_token_age_seconds": 3600,
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

Ask GitLab to mint an ID token with that exact audience:

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
      https://forge.example.com/v3/releases/index.json
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

The temporary Basic source is intentional. The .NET NuGet client resolves the
service index before it sends the push API key, and `--api-key` is not attached
to that initial GET. Supplying the same short-lived OIDC token as the source
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
- Grant selector-scoped `read` **and** `write` on the intended hosted repository,
  using the same include/exclude package selector such as `Acme.Widgets.*`.
  `read` is required for a private feed's service-index GET; it does not widen
  access beyond that selector on package-addressed routes.
- Prefer numeric provider IDs and add a protected ref/environment condition.
  A ref or environment is an additional boundary, not a workload identity by
  itself.
- Use a dedicated, exact audience for Forge; never reuse a broad cloud audience.
- Set `positive_cache_seconds = 0` to disable the per-token positive verdict
  cache. Discovery and JWKS have their own caches (JWKS defaults to one hour),
  so this does not force signing-key revocation to be fetched on every request.
  The positive verdict cache itself never extends past its configured TTL or
  token expiry.
- Treat a token as a bearer credential until `exp`: mask it in CI logs and do
  not persist it as an artifact, cache entry, or repository secret.
