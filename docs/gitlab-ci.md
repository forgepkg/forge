# GitLab CI with workload identity

This guide connects a GitLab project's NuGet builds to Forge without storing a
secret in GitLab. Every job of the project can restore from Forge's feeds, and
only the release job can push, and only the packages you name:

| Job | Identity | Can |
| --- | --- | --- |
| Every job (build, test, merge requests) | the realm rule's read-only role | restore from the feeds the role reads |
| The release job | the same role, plus a trusted publisher | restore, and push the named packages to one hosted repository |

Both identities come from the same GitLab ID token and the same Forge realm. A
job holds exactly **one** role, the one the realm's first matching rule names,
and an issuer has exactly one enabled realm. The write identity is therefore
no second realm or role: it is a **trusted publisher** on the hosted
repository, which adds `write` there for the jobs its conditions match. A job
that matches no publisher keeps the read-only role.

[Trusted publishing](trusted-publishing.md) is the reference behind this guide:
the security model, the token exchange and every setting. For pipelines that
cannot use workload identity, see [CI with service accounts](ci-service-accounts.md).

The examples use these names; substitute your own:

| Name | Example |
| --- | --- |
| Forge | `https://forge.example.com` |
| GitLab, the token issuer | `https://gitlab.example.com` (or `https://gitlab.com`) |
| Hosted repository the packages go to | `releases` |
| Proxy of nuget.org | `nuget-org` |
| Group the builds restore from (`releases` + `nuget-org`) | `nuget` |
| GitLab project ID / namespace ID | `1001` / `42` |
| Packages the project publishes | `Acme.Widgets`, `Acme.Widgets.*` |

## Before you start

- **GitLab issues ID tokens** (the `id_tokens` keyword, GitLab 15.7 and
  later). Forge must reach the issuer's
  `/.well-known/openid-configuration` and its JWKS over HTTPS and trust the
  certificate, also for a GitLab on a private network. Plain HTTP is for test
  instances only.
- **You know the issuer and the IDs.** The issuer is the exact `iss` of the
  instance's tokens, normally the instance URL (`$CI_SERVER_URL` in a job).
  The project ID is on the project's overview page (**⋮ → Copy project ID**)
  and is `$CI_PROJECT_ID` in a job. The namespace ID is the ID of the group
  the project sits in directly, `$CI_PROJECT_NAMESPACE_ID` in a job.
- **Which claims your GitLab puts in its tokens.** Current GitLab versions
  carry `job_project_id` and `job_namespace_id`; older self-managed versions
  have only `project_id` and `namespace_id`. If in doubt, run this job once
  and read its log. It prints the token's claims without its signature, which
  is no credential; delete the job afterwards, since the claims name the user
  who ran it.

  ```yaml
  show-forge-claims:
    image: mcr.microsoft.com/dotnet/sdk:10.0
    when: manual
    id_tokens:
      FORGE_ID_TOKEN:
        aud: https://forge.example.com
    script:
      - |
        payload="$(printf '%s' "$FORGE_ID_TOKEN" | cut -d. -f2 | tr '_-' '/+')"
        while [ $(( ${#payload} % 4 )) -ne 0 ]; do payload="$payload="; done
        printf '%s' "$payload" | base64 -d
        echo
  ```

- **The repositories exist in Forge** (**Admin → Repositories**): the hosted
  NuGet repository the packages go to, and the feeds the builds restore from.

## 1. The read-only role

Under **Admin → Roles**, create a role, for example `gitlab-ci-read`. On its
page, under **Grants**, add one grant per repository the builds restore from,
each with the level **read**:

- `releases`, so builds can use the project's own packages;
- `nuget-org`;
- `nuget`, the group.

A group serves a caller only the members that caller may read, so grant
`read` on the group **and** on each member it should serve from. Leave
**All repositories** alone unless every job of the project may read every
repository: a role's grants reach every format, npm, Docker and raw
repositories as well as NuGet.

The role needs no `write`: the trusted publisher in step 4 adds it for the
release job only.

## 2. The workload identity realm

Under **Admin → Authentication**, create a realm of the kind **Workload
identity**:

| Field | Value |
| --- | --- |
| Name | `gitlab` (the trusted publisher names the realm) |
| Issuer URL | `https://gitlab.example.com`, exactly the tokens' `iss` |
| Allowed audiences | `https://forge.example.com`, an audience used for Forge alone |
| Maximum token age (seconds) | at least the longest timeout of a job that uses Forge; the default, 39600 (11 hours), covers most |
| Exchanged API key lifetime (seconds) | how long a job may use its key; the default is 3600 (1 hour) |

Under **Rules**, add one rule with the role `gitlab-ci-read` and two
conditions:

| Claim | Any of |
| --- | --- |
| `job_project_id` | `1001` |
| `job_namespace_id` | `42` |

Every job of project 1001 now matches the rule and gets `gitlab-ci-read`; a
job of any other project gets 401. The realm's configuration, as the admin
API takes it (`POST /admin/realms`):

```json
{
  "kind": "workload_identity",
  "name": "gitlab",
  "config": {
    "issuer": "https://gitlab.example.com",
    "allowed_audiences": ["https://forge.example.com"],
    "max_token_age_seconds": 39600,
    "api_key_ttl_seconds": 3600,
    "rules": [
      {
        "role": "gitlab-ci-read",
        "conditions": [
          { "claim": "job_project_id", "any_of": ["1001"] },
          { "claim": "job_namespace_id", "any_of": ["42"] }
        ]
      }
    ]
  }
}
```

- **Numeric IDs, not paths.** A project or group can be renamed, and another
  can take its old path. On `https://gitlab.com` every rule must contain a
  project ID and a namespace ID; a self-managed GitLab accepts any
  [stable identity claim](trusted-publishing.md#security-model), but pin both
  IDs there too.
- **`job_*` claims where your GitLab has them.** In a merge request pipeline
  run in the parent project, `project_id` and `namespace_id` name the merge
  request's source project, `job_project_id` and `job_namespace_id` the
  project the job runs in. Use `project_id` and `namespace_id` only on a
  GitLab without the `job_*` claims.
- **More projects** go into the same realm: add their IDs to the rule's
  lists, or add a rule per team with a role of its own. Rules are ordered,
  and the first rule whose conditions all match picks the role.
- **Saving the realm revokes its keys.** Any change to the realm revokes
  every key it has issued, so jobs running at that moment fail and must be
  retried.

## 3. Who may release, in GitLab

The write identity trusts what GitLab signs into the token, so GitLab decides
who may run the release job. Protect the ref the release runs on, and with
GitLab Premium or Ultimate also the environment it deploys to:

- **Protected tags** (**Settings → Repository → Protected tags**): protect
  `v*` and choose who may create such tags, for example Maintainers. A job
  of a pipeline for a protected tag gets `ref_protected: true` in its token.
- **Protected environment** (**Settings → CI/CD → Protected environments**):
  protect `nuget-release` and choose who may deploy to it. A job that deploys
  to it gets `environment: nuget-release` and `environment_protected: true`.
  The environment must exist first: the first job that names it creates it,
  or create it under **Operate → Environments**.

## 4. The trusted publisher

Open the hosted repository under **Admin → Repositories → releases**, and in
its **Trusted publishers** panel choose **Add trusted publisher**:

| Field | Value |
| --- | --- |
| Publisher name | `widgets-release` |
| Realm | `gitlab` |
| Description | who owns it and what it releases |
| Package includes | `Acme.Widgets` and `Acme.Widgets.*`, one glob per line |
| Package excludes | empty |
| Claim conditions | the JSON below |
| Allow unlist and delete | off |

```json
[
  { "claim": "job_project_id", "any_of": ["1001"] },
  { "claim": "job_namespace_id", "any_of": ["42"] },
  { "claim": "ref_type", "any_of": ["tag"] },
  { "claim": "ref_protected", "any_of": ["true"] },
  { "claim": "environment", "any_of": ["nuget-release"] },
  { "claim": "environment_protected", "any_of": ["true"] }
]
```

On GitLab Free, which has no protected environments, leave out the two
`environment` conditions; the protected tag then decides alone.

- **Pin the packages.** An empty include list means every package. Patterns
  match the package ID without regard to case.
- **The publisher only adds.** It never authenticates a job by itself: a job
  must match the realm rule first, and then holds `gitlab-ci-read` plus
  `write` on `releases` for the included packages.
- **`ref_protected` belongs next to the environment.** It keeps a merge
  request pipeline from a fork, which a maintainer may run in the parent
  project, from publishing even when it deploys to the environment: a merge
  request's ref is never protected.
- **Unlist and delete** add the `delete` level for the same packages. Leave
  them off unless the pipeline removes versions.
- **Editing or deleting the publisher** withdraws its rights from the keys
  already issued; the realm's other keys keep working.

The admin API takes the same publisher at
`POST /admin/repositories/releases/trusted-publishers`:

```json
{
  "name": "widgets-release",
  "description": "Tag releases of Acme.Widgets from the protected nuget-release environment",
  "realm": "gitlab",
  "packages": { "includes": ["Acme.Widgets", "Acme.Widgets.*"], "excludes": [] },
  "actions": ["write"],
  "conditions": [
    { "claim": "job_project_id", "any_of": ["1001"] },
    { "claim": "job_namespace_id", "any_of": ["42"] },
    { "claim": "ref_type", "any_of": ["tag"] },
    { "claim": "ref_protected", "any_of": ["true"] },
    { "claim": "environment", "any_of": ["nuget-release"] },
    { "claim": "environment_protected", "any_of": ["true"] }
  ]
}
```

## 5. The project

The project's `nuget.config` names Forge's group feed and holds no
credentials:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="forge" value="https://forge.example.com/repository/nuget/index.json" />
  </packageSources>
</configuration>
```

In `.gitlab-ci.yml`, a hidden job requests the ID token and exchanges it for a
key in `before_script`; every job that uses Forge extends it:

```yaml
variables:
  FORGE_URL: https://forge.example.com

.forge:
  image: mcr.microsoft.com/dotnet/sdk:10.0
  id_tokens:
    FORGE_ID_TOKEN:
      aud: https://forge.example.com
  before_script:
    - |
      FORGE_KEY="$(curl --fail --silent --show-error -X POST "$FORGE_URL/api/v2/token" \
        -H "Authorization: Bearer $FORGE_ID_TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{"username":"oidc","tokenType":"ApiKey"}' \
        | sed -n 's/.*"apiKey":"\([^"]*\)".*/\1/p')"
      test -n "$FORGE_KEY"
      export FORGE_KEY
      export NuGetPackageSourceCredentials_forge="Username=oidc;Password=$FORGE_KEY"

build:
  extends: .forge
  script:
    - dotnet restore
    - dotnet build -c Release --no-restore
    - dotnet test -c Release --no-build

publish:
  extends: .forge
  stage: deploy
  environment:
    name: nuget-release
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - dotnet restore
    - dotnet pack -c Release -o artifacts --no-restore
    - >-
      dotnet nuget push "artifacts/*.nupkg"
      --source "$FORGE_URL/repository/releases/package"
      --no-service-endpoint
      --api-key "$FORGE_KEY"
```

- **The audience** under `id_tokens` must be one of the realm's allowed
  audiences, exactly.
- **The exchange** runs once per job. A token can be exchanged only once, and
  the job's later commands share the key. `FORGE_KEY="$(…)"` stays a plain
  assignment so that a failed exchange fails the job: `export
  FORGE_KEY="$(…)"` would succeed whatever `curl` returned, and the job would
  go on without a key. The .NET SDK image has `curl` but no `jq`, so `sed`
  picks the key out of the answer, `{"apiKey":"forge_wif.…","expires":"…"}`.
- **A job with a `before_script` of its own** replaces the hidden job's, and
  then has no key. List the hidden job's first:

  ```yaml
  test:
    extends: .forge
    before_script:
      - !reference [.forge, before_script]
      - dotnet tool restore
    script:
      - dotnet test
  ```
- **`NuGetPackageSourceCredentials_forge`** gives the `forge` source of
  `nuget.config` the key as its password; the part after the `_` must be the
  source's key. NuGet ignores a malformed value without a message.
- **The push** goes to the hosted repository's publish URL with
  `--no-service-endpoint`, so NuGet sends a single `PUT` with the key instead
  of first reading the service index.
- **The publish job** restores with the read-only role, which every job of
  the project holds, and pushes with the write the trusted publisher adds.

## Every project on a runner

The hidden job above lives in each project. An organization that runs its own
GitLab Runner for its .NET builds can run the exchange on the runner instead,
once for every job it builds. Each job then restores with the realm rule's
read-only role, and only a job that a trusted publisher matches can push. The
runner's `pre_build_script` runs in the job's shell right before the job's
`before_script` and `script`, so the key it exports reaches the job.

The runner cannot ask for the token itself: GitLab issues an ID token only to
a job that declares `id_tokens`. Each project keeps that part.

### The realm rule

The rule of [step 2](#2-the-workload-identity-realm) names every project the
runner builds. On a self-managed GitLab a rule may pin namespaces alone: every
project directly in one of the groups matches, and so does a project created
there later.

```json
{
  "role": "gitlab-ci-read",
  "conditions": [
    { "claim": "job_namespace_id", "any_of": ["42", "43", "57"] }
  ]
}
```

- **A subgroup is a namespace of its own.** `job_namespace_id` is the group a
  project sits in directly, so a group's ID does not cover its subgroups:
  list each of them.
- **On `https://gitlab.com`** every rule needs project IDs as well: list the
  projects there.
- **Keep the role read-only.** Every job of those groups holds it, merge
  request pipelines included.
- **Rules are ordered.** A project that needs a role of its own goes into a
  rule before this one.

### The runner

In the runner's `config.toml`, in its `[[runners]]` entry:

```toml
[[runners]]
  # name, url, token, executor, …
  environment = ["FORGE_URL=https://forge.example.com"]
  pre_build_script = '''
if [ -n "${FORGE_ID_TOKEN:-}" ] &&
  [ -n "$(find "$CI_PROJECT_DIR" -maxdepth 3 -iname nuget.config -exec grep -liF "$FORGE_URL" {} + 2>/dev/null)" ]; then
  FORGE_KEY="$(curl --fail --silent --show-error -X POST "$FORGE_URL/api/v2/token" \
    -H "Authorization: Bearer $FORGE_ID_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"username":"oidc","tokenType":"ApiKey"}' \
    | sed -n 's/.*"apiKey":"\([^"]*\)".*/\1/p')"
  test -n "$FORGE_KEY"
  export FORGE_KEY
  export NuGetPackageSourceCredentials_forge="Username=oidc;Password=$FORGE_KEY"
fi
'''
```

- **Only jobs with a token.** `FORGE_ID_TOKEN` exists only in a job that asks
  for it, so the runner leaves every other job alone.
- **Only projects that use Forge.** The exchange runs only when a
  `nuget.config` up to three directories deep names `$FORGE_URL`, whatever
  the case of the file's name. The `find` lists nothing both when there is no
  such file and when none of them names Forge.
- **A failed exchange fails the job**, as in the hidden job: `test -n` stops
  it before `dotnet restore` gets 401.
- **The image** of such a job needs `curl`, `sed`, `find` and a POSIX shell;
  the .NET SDK image has them. A Windows runner needs a PowerShell version.
- **The source key is `forge`** in every project's `nuget.config`:
  `NuGetPackageSourceCredentials_forge` reaches that source alone.
- **Your own runners only.** GitLab.com's instance runners take no
  configuration of yours: register a project, group or instance runner of
  your own.

### The projects

Each project asks for the token in every job, and runs no exchange of its
own:

```yaml
default:
  image: mcr.microsoft.com/dotnet/sdk:10.0
  id_tokens:
    FORGE_ID_TOKEN:
      aud: https://forge.example.com

build:
  script:
    - dotnet restore
    - dotnet build -c Release --no-restore
    - dotnet test -c Release --no-build
```

- **No `extends: .forge`.** A token is exchanged once, so the hidden job's
  exchange would get 401 after the runner's.
- **The release job** of [step 5](#5-the-project) stays as it is, without
  `extends: .forge`: it pushes with the `$FORGE_KEY` the runner exported,
  which the trusted publisher of step 4 gives `write`.
- **The jobs run on that runner**: give them its tags, or let it pick up
  untagged jobs.

### Without workload identity

A runner can also hand every job a [service account](ci-service-accounts.md)'s
read token, with no change to the projects:

```toml
[[runners]]
  environment = ["NuGetPackageSourceCredentials_forge=Username=gitlab-ci@example.com;Password=<read token>"]
```

The token is then a long-lived secret in the runner's configuration, and every
job the runner runs can print it, whatever project the job belongs to. Give it
the **read** level alone, an expiry, and only the repositories the builds
restore from ([step 3](ci-service-accounts.md#3-the-tokens) there).

## What each identity can do

| | Every job | The release job |
| --- | --- | --- |
| Restore from `releases`, `nuget-org` and `nuget` | yes | yes |
| Push `Acme.Widgets*` to `releases` | no, 403 | yes |
| Push another package, or to another repository | no | no |
| Unlist or delete | no | only with **Allow unlist and delete** |
| The admin API, the web UI, API tokens | never | never |

- **No account.** A job is a workload, not a user: it signs in nowhere, and
  `/auth/tokens` needs a browser session, so it cannot mint an API token.
  Forge refuses a realm rule that maps to the built-in `admin` role, so no
  token reaches the admin API.
- **Public reads.** Like every caller, a job may also read what anonymous
  access allows.
- **Lifetimes.** The key lives for the realm's exchanged API key lifetime,
  whatever the job's timeout. The ID token itself lives until the job's
  timeout but can be exchanged only once.
- **Revoking.** Disabling or editing the realm revokes all its keys for good;
  enabling it again does not bring them back. Removing a grant from
  `gitlab-ci-read` takes effect on the next request.
- **Audit.** Every publish by a job is recorded in `trusted_publish_audit`
  with the realm, the role, the publisher and digests of the token's subject
  and `jti`.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| The exchange answers 401 | No rule matched: check the issuer (the tokens' exact `iss`), the audience, and the IDs; on an older GitLab use `project_id` / `namespace_id`. Or the token is older than the maximum token age, or was exchanged already (a retried `curl`, a second exchange in the job, the project's exchange after the [runner's](#every-project-on-a-runner)). |
| The exchange answers 503 | Forge cannot fetch GitLab's discovery document or JWKS: the network between them, a proxy, or a certificate Forge does not trust. |
| `dotnet restore` gets 401 | `NuGetPackageSourceCredentials_<key>` does not name the `nuget.config` source, or the key expired during a long job: raise the exchanged API key lifetime. |
| A package from a group member is missing | The role reads the group but not that member. |
| The push gets 403 | The job did not match the publisher (not a protected tag, not the protected environment), or the package ID is outside its includes. |
| The push gets 405 | It went to a proxy, or to a group that names no writable member: push to `/repository/releases/package`. |
| The push gets 401 | The key was revoked by an edit of the realm, or expired. |

## Without the exchange

A client that cannot run the exchange can present the ID token itself on
every request, as the Basic password of the username `oidc` and as the API
key. [Trusted publishing](trusted-publishing.md#without-the-exchange-1) shows
the GitLab job; the exchange is preferred, since the token then cannot be
replayed from a job log.
