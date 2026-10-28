# CI with service accounts

Some pipelines cannot use [workload identity](gitlab-ci.md): a GitLab older
than 15.7, a GitLab whose discovery document and JWKS Forge cannot reach, a
CI system without OIDC tokens. They authenticate with an API token of a
[service account](deployment.md#service-accounts) instead: an account for a
machine that nobody signs in to.

Prefer workload identity wherever it works. A token stored in GitLab is a
long-lived secret: any job that sees it can use it, until it expires or is
revoked, from anywhere. This guide keeps the same split as the workload
identity guide, so that a leaked token reveals as little as possible:

| Token | Account | Stored in GitLab | Can |
| --- | --- | --- | --- |
| Read token | `gitlab-ci@example.com` | masked variable, every pipeline | restore from the feeds the account reads |
| Release token | `gitlab-release@example.com` | masked and protected variable, protected refs only | push the named packages to one hosted repository |

The examples use the names of the [workload identity guide](gitlab-ci.md):
Forge at `https://forge.example.com`, the hosted repository `releases`, the
proxy `nuget-org`, the group `nuget`, and the packages `Acme.Widgets` and
`Acme.Widgets.*`.

## 1. The roles

**Reading.** The read-only role of the workload identity guide serves here
too: `gitlab-ci-read`, with `read` on `releases`, `nuget-org` and `nuget`
(see [step 1](gitlab-ci.md#1-the-read-only-role) there). One role for both
methods keeps what CI may read in one place; give each method its own role
when they should differ.

**Publishing.** Pin the packages with a content selector, then grant `write`
through it:

1. Under **Admin → Content selectors**, create `acme-widgets` with the
   includes `Acme.Widgets` and `Acme.Widgets.*`.
2. Under **Admin → Roles**, create `widgets-publish`, and on its page add the
   grant: repository `releases`, level **write**, content selector
   `acme-widgets`.

Without the selector, the grant reaches every package of `releases`.

## 2. The service accounts

Under **Admin → Service accounts**, create two accounts:

| Name | Description | Access | Roles (on its page) |
| --- | --- | --- | --- |
| `gitlab-ci@example.com` | restores for the GitLab project `acme/widgets`; who owns it | Reader | `gitlab-ci-read` |
| `gitlab-release@example.com` | releases `Acme.Widgets` from `acme/widgets`; who owns it | Reader | `widgets-publish` |

**Reader** gives an account no built-in role: it may do what its roles allow.
**Writer** would let it publish anything to every repository; leave it for
accounts that really need it. A service account never holds the `admin` role.

Two accounts rather than one keep the release rights out of the read token,
and the logs tell restores and releases apart.

## 3. The tokens

On each account's page, under **Tokens**, create a token:

| | Read token | Release token |
| --- | --- | --- |
| Token name | `gitlab acme/widgets` | `gitlab acme/widgets release` |
| Token expiry | 90 days, or 1 year | 90 days, or 1 year |
| Level | at most **read** | at most **write** |
| Repositories | every repository the owner can reach | only `releases` |

The secret is shown once: put it into GitLab straight away. A token's scope
only narrows its account's roles. Here it keeps the tokens to their purpose
even when someone later gives the account a wider role.

## 4. The GitLab variables

In the project, under **Settings → CI/CD → Variables**, add:

| Key | Value | Settings |
| --- | --- | --- |
| `FORGE_READ_TOKEN` | the read token | **Masked**, not protected |
| `FORGE_RELEASE_TOKEN` | the release token | **Masked** and **Protected** |

A protected variable reaches only pipelines of protected branches and tags.
Protect the release tags (**Settings → Repository → Protected tags**, for
example `v*`, created by Maintainers only), so the release token reaches the
pipeline of such a tag and nothing else. The read token is in every pipeline,
including those of branches anybody with the Developer role can push: anyone
who can change `.gitlab-ci.yml` can print it. It carries `read` alone for
that reason.

## 5. The pipeline

`nuget.config` is the one of the workload identity guide, naming the source
`forge` without credentials. The jobs pass the read token as the source's
password and the release token as the push's API key:

```yaml
variables:
  FORGE_URL: https://forge.example.com

.forge:
  image: mcr.microsoft.com/dotnet/sdk:10.0
  before_script:
    - export NuGetPackageSourceCredentials_forge="Username=gitlab-ci@example.com;Password=$FORGE_READ_TOKEN"

build:
  extends: .forge
  script:
    - dotnet restore
    - dotnet build -c Release --no-restore
    - dotnet test -c Release --no-build

publish:
  extends: .forge
  stage: deploy
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - dotnet restore
    - dotnet pack -c Release -o artifacts --no-restore
    - >-
      dotnet nuget push "artifacts/*.nupkg"
      --source "$FORGE_URL/repository/releases/package"
      --no-service-endpoint
      --api-key "$FORGE_RELEASE_TOKEN"
```

- **The username** in the source credentials is the account's name. Forge
  identifies the account by the token, but the name `oidc` is reserved for
  workload identity and refuses every API token.
- **The push** goes to the hosted repository's publish URL with
  `--no-service-endpoint`: NuGet then sends a single `PUT` with the API key,
  without reading the service index first.

## What each token can do

- **Its account's roles, narrowed by its scope.** The read token restores
  from `releases`, `nuget-org` and `nuget`, and pushes nothing (403). The
  release token pushes `Acme.Widgets*` to `releases`, and nothing else.
- **Never more than an API token.** Nobody signs in to a service account, it
  has no password, and its tokens reach no admin API.
- **Until it ends.** A token works until its expiry, until it is revoked on
  the account's page, or while the account is deactivated
  (**Deactivate…** on its page stops all its tokens at once). The list of
  service accounts shows when each was last used.

**Rotating a token:** create a new one on the account's page, replace the
variable's value in GitLab, run a pipeline, then revoke the old token. With
an expiry on every token, a forgotten one ends by itself.

## Using both

Workload identity and service accounts work side by side, without any
setting: Forge tells the credentials apart.

- HTTP Basic with the username `oidc` is only ever a workload credential.
- A JWT whose issuer has a workload identity realm goes to that realm, and a
  failure there is final: it never falls through to the password checks.
- Anything else, such as a service account's token, is checked as an API
  token.

So each project can use whichever method it can, and switch when it can. To
move a project from a service account to workload identity:

1. Add its project and namespace IDs to the realm rule, and a trusted
   publisher for its packages ([GitLab CI with workload identity](gitlab-ci.md),
   steps 2 to 4).
2. Change its pipeline to the token exchange (step 5 there), and run it.
3. Revoke the tokens, delete the GitLab variables, and deactivate the service
   accounts once no project uses them.

| | Workload identity | Service account |
| --- | --- | --- |
| Secret stored in GitLab | none | the tokens, in CI/CD variables |
| Identity | each job, from claims GitLab signs | whoever holds the token |
| Rights | one role, plus trusted publishers | the account's roles, narrowed by the token's scope |
| Limited to protected refs or environments | by the token's claims, which Forge checks | by GitLab's protected variables |
| Credential lifetime | the exchanged key's, one hour by default | until expiry or revocation |
| Audit | the publish audit, with the job's subject and `jti` digests | the account and token in the logs |
| Needs | Forge reaches GitLab's discovery document and JWKS | nothing |
