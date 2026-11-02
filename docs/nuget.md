# NuGet feeds

Forge serves NuGet packages to `dotnet`, `nuget.exe`, MSBuild and Visual
Studio over the NuGet **V3** protocol: restore, search, push, unlist and
relist. Repositories of `format: "nuget"` are served at
`https://<host>/repository/<repository>/`, with the service index at
`https://<host>/repository/<repository>/index.json`, in the usual three kinds:

- **hosted**: push and restore your own packages;
- **proxy**: a cache of another V3 feed, `https://api.nuget.org/v3/index.json`
  or a private one (Azure Artifacts, GitHub Packages, Artifactory, a Nexus);
- **group**: one feed over several members, which keeps your package ids
  internal (`prefer_hosted`, `reserved_prefixes`).

[DEVELOPMENT.md](../DEVELOPMENT.md#repository-types) shows how to create each
kind. Nexus serves its NuGet feeds at the same path, so a client that pointed
at a Nexus keeps its configuration once the Nexus host name points at Forge
([aliases](deployment.md#further-host-names-aliases)).

## Contents

- [Connecting a client](#connecting-a-client)
- [Logging in](#logging-in)
- [Pushing](#pushing)
- [Unlisting and deleting](#unlisting-and-deleting)

## Connecting a client

A repository's page in the web UI shows its service index and these
commands, ready to copy. When you create a token under **Your tokens**, the
page shows them again with the token and your username filled in, and the
`NuGet.config` below.

```bash
dotnet nuget add source https://forge.example.com/repository/nuget-all/index.json \
  --name forge --username <username> --password <token> --store-password-in-clear-text
dotnet restore
```

Or in the project's `NuGet.config` (or `~/.nuget/NuGet/NuGet.Config`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="forge" value="https://forge.example.com/repository/nuget-all/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <forge>
      <add key="Username" value="<username>" />
      <add key="ClearTextPassword" value="<token>" />
    </forge>
  </packageSourceCredentials>
</configuration>
```

The element under `packageSourceCredentials` is named after the source's
`key`. A key XML refuses as a name, such as one starting with a digit, is
escaped the way NuGet reads it: `_x0031_` for a leading `1`. To keep the
token out of the file, leave `packageSourceCredentials` out and set
`NuGetPackageSourceCredentials_forge="Username=<username>;Password=<token>"`
in the environment instead.

A repository that allows anonymous reads (with the anonymous mode on, under
**Admin → Settings**) restores without credentials.

## Logging in

NuGet sends its credentials as HTTP Basic, after the feed answers `401`.

- **API tokens** are the password to use. Create one under **Your tokens**
  in the web UI, or with `POST /admin/me/tokens`. Its scope applies (a level,
  some repositories), and it is listed and revocable there.
- **Passwords** work for the users of a realm that accepts passwords from
  clients ([Admin → Authentication](deployment.md#passwords-from-clients)).
  A credential-forwarding realm accepts them by default, so users of an
  existing Nexus or LDAP restore with their upstream password, as before.
  The local realm accepts them once an administrator turns that on. A
  password restores packages but never pushes, unlists or deletes them: those
  take an API token or a workload.
- **Browser sign-in** (OIDC or Entra included): NuGet signs in through a
  credential provider. Forge's, `nuget-plugin-forge`, is still to come: it
  will use the [device login](deployment.md#device-login). Until then, sign
  in to the web UI and create an API token.
- **CI workloads** with a workload-identity realm send their OIDC token, or
  the API key it was exchanged for, as the password or the API key
  ([Trusted publishing](trusted-publishing.md)). The [GitLab CI
  guide](gitlab-ci.md) and [CI with service accounts](ci-service-accounts.md)
  set up a pipeline step by step.

Every failed password counts toward the sign-in lockout (**Admin →
Settings**), the same lockout as the web UI's login.

## Pushing

`dotnet nuget push` sends the API key as `X-NuGet-ApiKey`, as for
nuget.org and Nexus. Any API token of yours with the **write** level on the
repository is a key:

```bash
dotnet nuget push MyLib.1.2.3.nupkg --source forge --api-key <token>
```

A push goes to a hosted repository. The repository's upload limit (512 MiB
unless set) applies, and a version it already holds is refused with `409
Conflict` unless the repository allows redeploys.

## Unlisting and deleting

`dotnet nuget delete` unlists a version (the **delete** level), as on
nuget.org: it stays restorable, but search and floating version ranges no
longer find it. A `POST` to the same URL lists it again:

```bash
dotnet nuget delete MyLib 1.2.3 --source forge --api-key <token> --non-interactive
curl -X POST -H 'X-NuGet-ApiKey: <token>' \
  https://forge.example.com/repository/nuget-hosted/package/MyLib/1.2.3
```

Retention rules delete versions for good ([Retention](retention.md)), and so
does **Delete version** on a package's page in the web UI.
