# Production deployment

This is the operator guide for running the Forge image in
production. For local development see [DEVELOPMENT.md](../DEVELOPMENT.md); for
CI publishing without stored API keys see
[trusted publishing](trusted-publishing.md).

## What you need

| Dependency | Notes |
| --- | --- |
| PostgreSQL 15+ (17 tested) | The authority for all metadata, sessions, RBAC and coordination. Migrations run automatically at startup. From PostgreSQL 15 on, `public` no longer grants CREATE to every role, so the role in `FORGE_DATABASE__URL` must own the database (`CREATE DATABASE forge OWNER forge`) or hold CREATE on its schema. |
| S3-compatible object store | Package blobs (content-addressed). AWS S3, MinIO, Ceph RGW, versitygw, … A missing bucket is created in the configured region; see [S3 permissions](#s3-permissions). Static keys or [short-lived credentials](#short-lived-s3-credentials) (IRSA, EKS Pod Identity, STS web identity). |
| TLS termination | A reverse proxy or load balancer in front of Forge (nginx, Traefik, an ingress, an ALB). Forge itself speaks plain HTTP. |
| Valkey or Redis 6+ (optional) | Shared L2 cache and cross-instance invalidation. Recommended as soon as you run more than one instance. TLS via `rediss://`. The Helm chart (`valkey.enabled`) and the kustomize component `valkey` can run a Valkey in the cluster. |

Forge is a single stateless process. The API, the NuGet feed and the web UI
share one port (`8421`), so one upstream on the reverse proxy is enough.

On Kubernetes, install the Helm chart
(`oci://ghcr.io/<owner>/charts/forge`, see
[`deploy/helm/forge`](../deploy/helm/forge/README.md)) or start from the
kustomize manifests in [`deploy/kubernetes`](../deploy/kubernetes/README.md).
Both set the probes, the shutdown timing and the security context described
below, and pin the image to the release they belong to.

### S3 permissions

Forge's S3 credentials need these actions on its bucket (an AWS IAM policy
for the bucket `forge`; MinIO and Ceph RGW use the same action names):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::forge"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
      "Resource": "arn:aws:s3:::forge/*"
    }
  ]
}
```

- `s3:ListBucket` is what the bucket check (HeadBucket, at startup and in
  `/readyz`) needs, and without it S3 answers a lookup of a missing key with
  403 instead of 404.
- `s3:PutObject` covers multipart uploads too (large pushes and proxied
  downloads); `s3:AbortMultipartUpload` discards an interrupted one.
- `s3:DeleteObject` is not optional. When a package is deleted or retention
  evicts a version, garbage collection deletes the blob through the outbox.
  With append-only credentials that delete fails, the blob's reservation
  stays fenced, and every later ingest of the same bytes retries the delete
  itself and fails: a package deleted and pushed again with identical bytes,
  or a proxied version evicted by retention, can then never be stored again.
- `s3:CreateBucket` (on the bucket, next to `s3:ListBucket`) only if Forge
  should create the bucket. Forge creates a
  missing bucket in `FORGE_S3__REGION` (outside `us-east-1` it sends the
  region as the location constraint), and refuses to start when the name
  belongs to another account (`BucketAlreadyExists`). On AWS, create the
  bucket beforehand (with the [lifecycle rule](#s3-bucket-lifecycle) below);
  then Forge needs no `s3:CreateBucket`.

These are the S3 calls behind the policy: `HeadBucket`, `CreateBucket` (only
when the bucket is missing), `HeadObject`, `GetObject`, `PutObject`,
`DeleteObject`, `CreateMultipartUpload`, `UploadPart`,
`CompleteMultipartUpload` and `AbortMultipartUpload`. The policy is the same
for static keys and for the role behind short-lived credentials.

### Short-lived S3 credentials

Instead of a long-lived access key in a Secret, Forge can get temporary S3
credentials from the platform's workload identity and refresh them itself.
Then there is no S3 secret to store, rotate or leak. `s3.credentials`
(`FORGE_S3__CREDENTIALS`) chooses the source:

| `s3.credentials` | Credentials from |
| --- | --- |
| `static` (default) | `FORGE_S3__ACCESS_KEY` / `FORGE_S3__SECRET_KEY`. |
| `default_chain` | The AWS SDK default credentials chain, in this order: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`, the shared profile (`AWS_PROFILE`), web identity (`AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`, which IRSA injects), the container credentials endpoint (EKS Pod Identity, ECS task roles), and EC2 instance metadata (instance profiles). |
| `web_identity` | A token file exchanged for temporary keys with STS `AssumeRoleWithWebIdentity`, against AWS STS or the STS of MinIO or Ceph RGW (`[s3.web_identity]`, below). |

With `default_chain` and `web_identity`, leave `FORGE_S3__ACCESS_KEY` and
`FORGE_S3__SECRET_KEY` unset. Forge refuses to start with keys it would not
use, so a long-lived key does not stay behind in a Secret after the switch.
The insecure-default check (`minioadmin`) applies only to `static`. Endpoint,
region, path-style and checksum settings work the same with every source.

| Variable | `[s3.web_identity]` key | Value |
| --- | --- | --- |
| `FORGE_S3__WEB_IDENTITY__TOKEN_FILE` | `token_file` | Required. The token, e.g. a projected service-account token. |
| `FORGE_S3__WEB_IDENTITY__ROLE_ARN` | `role_arn` | The role to assume. AWS and MinIO's role policies need one; MinIO's claim-based policies take none. |
| `FORGE_S3__WEB_IDENTITY__STS_ENDPOINT` | `sts_endpoint` | Unset: AWS STS in `s3.region`. For MinIO and Ceph RGW, their URL (usually the S3 endpoint). |
| `FORGE_S3__WEB_IDENTITY__SESSION_NAME` | `session_name` | `RoleSessionName`, recorded by CloudTrail. Default `forge`. |
| `FORGE_S3__WEB_IDENTITY__DURATION_SECONDS` | `duration_seconds` | 900 to 43200. Unset leaves it to STS (one hour on AWS). |

How Forge handles them:

- **Refresh.** The S3 client caches the credentials and fetches new ones 30
  to 60 seconds before they expire, so no request is signed with expired
  keys. Each fetch reads `token_file` again, which picks up a token the
  kubelet rotated. Every request is signed with the credentials current when
  it is sent, so a multipart upload that outlives one set of credentials
  completes.
- **Failures.** A failed fetch fails the S3 call that needed it with an error
  that names the source, the role, the token file and the STS endpoint, and
  the STS error code (`InvalidIdentityToken`, `AccessDenied`, …). It is also
  logged as a warning. Neither ever contains the token or the derived keys,
  and neither does the configuration's debug output. Like an S3 failure, it
  makes the startup bucket check abort and `/readyz` answer 503. With the
  [local blob cache](#local-blob-cache), an STS that cannot be reached counts
  as S3 being down (start degraded, serve the cache), while a refused token
  still fails startup.
- **Network.** Forge must reach the STS (`sts.<region>.amazonaws.com`, or
  the store's endpoint), and for EKS Pod Identity the node's agent at
  `169.254.170.23:80`. Allow them in a restrictive egress policy.

**IRSA (EKS).** Create an IAM role with the [policy above](#s3-permissions)
and a trust policy for the cluster's OIDC provider and Forge's service
account (`system:serviceaccount:<namespace>:<service account>`). Annotate the
service account with `eks.amazonaws.com/role-arn: <role ARN>` and set
`FORGE_S3__CREDENTIALS=default_chain`. The EKS webhook injects
`AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` and the token volume.

**EKS Pod Identity.** Create a Pod Identity association between the role
(with the policy above, trusted by `pods.eks.amazonaws.com`) and Forge's
service account, and set `FORGE_S3__CREDENTIALS=default_chain`. The webhook
injects `AWS_CONTAINER_CREDENTIALS_FULL_URI` and
`AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`.

Both work with `automountServiceAccountToken: false`, which the Helm chart
and the kustomize base set. The webhook (amazon-eks-pod-identity-webhook)
selects pods by the service account's role annotation or the Pod Identity
association. It does not read `automountServiceAccountToken`, and it adds
its own projected token volume, separate from the Kubernetes API token that
setting controls.

**ECS, EC2.** `default_chain` picks up the task role or the instance profile.

**MinIO.** Its STS accepts tokens from an OpenID Connect issuer. To trust
the Kubernetes service-account issuer, set
`MINIO_IDENTITY_OPENID_CONFIG_URL` to the cluster's discovery document
(`<issuer>/.well-known/openid-configuration`), and
`MINIO_IDENTITY_OPENID_CLIENT_ID` to the audience Forge's token carries
(e.g. `forge-s3`). A projected service-account token cannot carry a policy
claim, so give the issuer a role policy (`MINIO_IDENTITY_OPENID_ROLE_POLICY=forge`)
and set `role_arn` to the role ARN MinIO logs at startup
(`IAM Roles: arn:minio:iam:::role/…`). Any pod in the
cluster can request a token for that audience, so restrict the policy to
Forge's service account with a `jwt:sub` condition (namespace `forge`,
service account `forge`, bucket `forge`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::forge"],
      "Condition": { "StringEquals": { "jwt:sub": "system:serviceaccount:forge:forge" } }
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
      "Resource": ["arn:aws:s3:::forge/*"],
      "Condition": { "StringEquals": { "jwt:sub": "system:serviceaccount:forge:forge" } }
    }
  ]
}
```

With an issuer whose tokens name the policy in a claim
(`MINIO_IDENTITY_OPENID_CLAIM_NAME`, MinIO's claim-based policies), leave
`role_arn` unset.

Point Forge at it:

```bash
FORGE_S3__CREDENTIALS=web_identity
FORGE_S3__WEB_IDENTITY__TOKEN_FILE=/var/run/secrets/forge/s3/token
FORGE_S3__WEB_IDENTITY__STS_ENDPOINT=https://minio.example.com:9000
FORGE_S3__WEB_IDENTITY__ROLE_ARN=arn:minio:iam:::role/<id from the MinIO log>
```

Forge then needs no `s3:CreateBucket`: create the bucket with MinIO's root
user (`mc mb`).

On Kubernetes, the token is a projected service-account token with that
audience. The Helm chart mounts it with `s3.credentials: web_identity`, and
the kustomize component `s3-workload-identity` does the same. Ceph RGW works
the same way with its OpenID Connect provider and `role_arn`.

**Not covered.** GCS's S3 interoperability API accepts only HMAC keys, and
Azure Blob Storage has no S3 API, so neither works with short-lived
credentials here.

## Image

```bash
docker pull ghcr.io/<owner>/<repo>:1.0.0
```

The image is published for `linux/amd64` and `linux/arm64` (from 2.0.0 on;
earlier releases are amd64 only) as one multi-platform image: its tags and
digest name an index of both platforms' images, from which `docker pull` and
Kubernetes take the image of the node's platform. The Helm chart and the
manifests therefore deploy to amd64 and arm64 nodes, mixed ones included,
without a change. Each platform's image is built natively, not under
emulation.

Release images are signed with keyless cosign and carry an SBOM and a
provenance attestation for each platform (`docker buildx imagetools inspect
ghcr.io/<owner>/<repo>:1.0.0` lists them). The release signs the index and
each platform's image, and its notes list their digests. The exact `cosign
verify` command is in each GitHub release's notes, next to the commit the
release was built from; it passes for each of those digests. It pins the
signer to this repository's release workflow at that release's tag, run by
the push of the tag, on that commit:

```bash
cosign verify ghcr.io/<owner>/<repo>@<digest> \
  --certificate-identity https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v1.0.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha <commit> \
  --certificate-github-workflow-trigger push
```

The identity alone names only the tag; pinning the commit as well rejects a
signature from a release run for a tag that was later moved or re-created on
another commit.

Each release also publishes the Helm chart of the same version,
`oci://ghcr.io/<owner>/charts/forge`, which pulls the image by the digest the
release signed, the index's, so each node pulls its platform's image. It is
signed the same way; its `cosign verify` command is in the release notes too.

`:latest` always names the newest stable release and `:<major>.<minor>` the
newest release of that line; prereleases and patches to older lines never move
them. Pin deployments to a version or digest. `GET /version` on a running
instance reports its version and source revision.

## Required configuration

The image ships a secret-free base config (`/app/forge.toml`, from
[`docker/forge.docker.toml`](../docker/forge.docker.toml), loaded through
`FORGE_CONFIG`). Everything is overridden with `FORGE_*` environment variables
(`__` separates nesting levels). If you point `FORGE_CONFIG` at your own file,
that file must exist: a missing file fails startup instead of being ignored.

Secret values (`FORGE_DATABASE__URL`, `FORGE_REDIS__URL`, the S3 keys, the
bootstrap password, `FORGE_OIDC__CLIENT_SECRET`, the credential-forwarding
pepper) are read verbatim as strings, so a numeric or bracketed password needs
no quoting, and configuration errors never print their values.

| Variable | Value |
| --- | --- |
| `FORGE_SERVER__PUBLIC_BASE_URL` | The **https** URL clients use, e.g. `https://nuget.example.com`. It is used for every absolute URL in NuGet responses, and it decides whether session cookies are `Secure`. |
| `FORGE_DATABASE__URL` | `postgres://forge:<password>@db:5432/forge` |
| `FORGE_S3__ENDPOINT` | e.g. `https://s3.eu-central-1.amazonaws.com` or `http://minio:9000` |
| `FORGE_S3__REGION` | e.g. `eu-central-1` |
| `FORGE_S3__BUCKET` | e.g. `forge` |
| `FORGE_S3__ACCESS_KEY` / `FORGE_S3__SECRET_KEY` | Object-store credentials, or instead `FORGE_S3__CREDENTIALS` for [short-lived credentials](#short-lived-s3-credentials). |
| `FORGE_S3__FORCE_PATH_STYLE` | `true` for MinIO and most self-hosted stores, `false` for AWS. |
| `FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME` / `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` | First start only: the initial admin, named by a [UPN](#usernames) (default `admin@example.com`), and its password. Without the password no bootstrap admin is created. |
| `FORGE_CRYPTO__ROOT__PROVIDER` + root key | **Required**: the root key of the [secret encryption](#secret-encryption-at-rest), e.g. `FORGE_CRYPTO__ROOT__PROVIDER=env` with `FORGE_ROOT_KEY=<openssl rand -base64 32>`. |
| `FORGE_AUTH__TRUSTED_PROXY_CIDRS` | The CIDRs of your reverse proxies, e.g. `[10.0.0.0/8]`. Without it, every request appears to come from the proxy's IP, so the login lockout sees one client, and the headers of a [trusted-header realm](#trusted-header-realms) are ignored. Every address in these ranges chooses the client IP Forge sees: a whole pod network trusts every pod in the cluster, which can then get around the login lockout. Keep the ranges as narrow as the proxies allow, and let only the proxies reach Forge (see [Reverse proxy](#reverse-proxy): on Kubernetes the Helm chart's `networkPolicy.from`, the kustomize `network-policy` component). |

Startup refuses the known placeholder credentials (a `changeme` bootstrap
password, `minioadmin` S3 keys, and a secret still holding a `<…>` placeholder
of the example env files, such as `<initial admin password>`) and a
configuration without a root key. It logs a warning when `public_base_url`
is not https or points at localhost. Treat those warnings as deployment
errors.

Never set `FORGE_SERVER__ALLOW_INSECURE_DEFAULTS=true` in production. It is
meant only for the local compose stack.

### The bootstrap admin

The image bakes no bootstrap admin; it comes only from the environment, and
only while a password is set. Set `FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD` for
the first start, and `FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME` to a
[UPN](#usernames) of your organization if `admin@example.com` will not do: the
account is created **once**. Startup refuses a name that is no UPN. Sign in
to the web UI, invite personal admin accounts ([below](#inviting-users)) or
connect OIDC, then delete the bootstrap account. It is not re-created on later
restarts. Then remove the password from the environment: with no bootstrap
password configured, Forge simply starts without a bootstrap admin.

Forge never lets the last active administrator go: deleting or deactivating
that account, or removing its `admin` role, is refused with `409 Conflict`.
So the replacement admin has to exist first; an OIDC or credential-forwarding
admin counts once they have signed in.

### Access levels

What a user may do follows from the roles they hold (**Admin → Roles**,
`/admin/roles`). A role's grants each give one of three ordered levels on a
repository, or on every repository, and each level includes the ones below
it:

| Level | Covers (in Nexus's terms) | In Forge |
| --- | --- | --- |
| `read` | browse, read | Download, list and search packages, images and files. |
| `write` | browse, read, add, edit | `read`, plus push and relist: a NuGet push, an npm publish, a container image or Helm chart push, a raw file upload; and npm's dist-tags and deprecations. |
| `delete` | browse, read, add, edit, delete | `write`, plus unlist and delete versions (`npm unpublish` too), delete image tags, delete or replace raw files, and redeploy a version. |

A check passes when a grant covering the repository has the level it needs or
a higher one. A role holds one grant per repository (or every repository) and
content selector: giving it another level there replaces the level
(`PUT /admin/roles/{id}/grants` with `{"repository": "<name>", "level":
"write"}`, or **Add grant** on the role's page). A content selector narrows a
grant to the packages it matches, for every level the grant includes: a
`write` grant scoped to `acme.*` reads and publishes `acme.*` only.

Administration is no level: it is membership in the built-in `admin` role.

An API token carries its owner's levels, never `admin`, unless its scope says
otherwise. `"scope": {"level": "read"}` caps every grant at that level (a
`delete` grant reads only), `"repositories": [<id>, ...]` limits the
repositories, and `"admin": true` keeps the owner's `admin` role, for
automation, when the scope does not limit repositories. A scope can only
narrow what its owner may do.

### Built-in roles

Every install has three built-in roles, which cannot be deleted or renamed:

| Role | Grants | For |
| --- | --- | --- |
| `admin` | Everything: every repository at every level, and administering the instance (repositories, users, roles, authentication, settings). It holds no grant; membership is the administration. | Administrators. |
| `writer` | `write` on every repository, ones created later included. No `delete`, no administration. | People and CI that publish packages: a NuGet push, an npm publish, a container image push, a Helm chart upload, a raw file upload, of a package or image the repository does not have yet too. |
| `anonymous` | What unauthenticated callers may read (`anonymous_read` repositories add to it). Its grants reach signed-in users too, as `read`, under the anonymous mode `all`. | Anonymous access. |

A user who holds neither `admin` nor `writer` is a **reader**: they read what
their other roles and anonymous access allow. **Admin → Users** shows each
user's level (admin, writer or reader), and the user's page switches it.

A writer cannot unlist or delete package versions, delete image tags, or
delete or replace raw files: deleting stays with administrators and custom
roles that grant `delete`, so a leaked CI token cannot remove published
versions. Nor can a writer reach the
admin API (`/admin/*` answers 403; only `/admin/me` answers, and reports the
`repo.write` capability). A writer mints their own API tokens on the
**Tokens** page; a token never carries more than its owner's rights.

### Inviting users

An administrator never sets another person's password. **Admin → Users →
New user** (`/manage/users/new`) takes the [username](#usernames), the email
address the invitation goes to (the username unless entered: a UPN is not
always a mailbox) and the access level (reader, writer or admin). Forge
creates the account without a password and emails its user a link,
`<server.public_base_url>/invite#<token>`, with which they choose their own
password, at least 12 characters, and then sign in.

- **The link** works once, until the lifetime set on the
  [email](#email) settings page (72 hours unless changed). The token is in the
  URL fragment, which reaches no server or proxy log and no `Referer`; Forge
  stores only its SHA-256 and never logs it. An unknown, used, expired,
  replaced or revoked link gets one answer, which names no account. Failed
  attempts are throttled per client network with the login lockout's budget
  (`login_max_failures` per `login_failure_window_seconds`, among the
  [access and sign-in settings](#access-and-sign-in-settings)).
- **Until the user has chosen the password**, the account signs in by no
  path: the login and HTTP Basic refuse every password, nothing is forwarded
  to a credential-forwarding realm, and an OIDC login does not link to it by
  name. **Admin → Users** shows it as *invited*, or *invitation expired* once
  its link no longer works.
- **The user's page** offers **Resend invitation** (a new email, to another
  address if needed), **Copy invitation link** (a new link shown once, for an
  install without email or a mailbox that does not receive it) and **Revoke
  invitation**. A new link replaces the previous one, which stops working.
  Deactivating or deleting the account revokes its invitation.
- **Without an email service**, or when the send fails, the account is still
  created and the link is shown once on the page to pass on yourself.
- Accounts of a credential-forwarding realm (see [Usernames](#usernames)) and
  OIDC accounts are not invited: they sign in through their realm. The
  bootstrap admin keeps its configured password.

The admin API is `POST /admin/users` with `{"username", "email", "role"}`
(`role` is `reader`, `writer` or `admin`), or `"realm"` for a
credential-forwarding account. It takes no password: the answer carries
`invitation` (`email_sent`, `error`, `expires_at`, and the `link` when no
email went out). `POST /admin/users/{id}/invitation` (`{"send_email": true |
false, "email": "…"}`) makes a new invitation and `DELETE` revokes it. The
invited user's page calls `POST /auth/invitations/lookup` and
`POST /auth/invitations/accept` (`{"token", "password"}`).

### Deactivating users

To cut a user off without deleting the account, deactivate it on the user's
page (**Admin → Users → <user> → Deactivate**, or `PATCH /admin/users/{id}`
with `{"active": false}`):

- every sign-in is refused: the password, the browser, OIDC, credential
  forwarding, the headers of a trusted-header realm and API tokens, and no
  realm provisions the name back to life;
- the user's browser sessions end, their cached upstream verdicts are
  dropped, and a pending invitation is revoked;
- their tokens are refused but **not** revoked: reactivating
  (`{"active": true}`) lets the unrevoked ones work again, so revoke those
  that should not before reactivating.

Deactivate, rather than delete, an account to suspend during an incident or
to keep after its user left: deleting cannot be undone and takes the
account's tokens, roles and identity links along, and an OIDC realm that
provisions accounts re-creates a deleted one at its next login.

**Sign out everywhere** (`POST /admin/users/{id}/reauth`) ends the user's
browser sessions without deactivating the account. For a
credential-forwarding account the next password is checked against the
upstream again, and the tokens the user minted from a forwarded sign-in are
revoked; tokens an administrator issued keep working.

### Service accounts

A CI pipeline, a build agent or a network the load balancer admits is no
person, and should not have a person's account that someone could sign in
to, invite or convert. Give it a **service account** (**Admin → Service
accounts**, `/manage/service-accounts`): an account for a machine or a
network that nobody signs in to.

- **It has** a [username](#usernames) (a UPN, in the name space every
  account shares, so a name always means one account), a description of
  what it is for and who owns it, roles and grants like a user's, and an
  access level of reader or writer.
- **It never has** a password, an invitation or an email address, and
  nobody signs in to it: the login screen, a password over HTTP Basic,
  credential forwarding (its name is never forwarded upstream) and OIDC
  (no identity is linked to it by name) all refuse it. **Sign out
  everywhere**, invitations and the switch to a local account do not apply.
- **It never holds the built-in `admin` role.** For admin automation, issue
  an administrator a token with the `admin` scope instead.
- **It authenticates** with the API tokens an administrator issues on its
  page (each secret shown once; expiry, scope and revocation as for a
  user's), and through the [trusted-header realm](#trusted-header-realms) it
  belongs to, if any. A service account belongs to at most one such realm,
  and only that realm may name it: another trusted-header realm, even one
  that provisions accounts, gets a 401 for its name. No realm creates
  service accounts.
- **Deactivating it** (**Deactivate…** on its page) stops its tokens and its
  realm from authenticating it; reactivating lets both work again. The list
  shows when each service account was last used: its tokens' latest use, or
  its realm's last request naming it.

A CI pipeline that publishes packages: create `ci@example.com` as a writer
(or with a role that grants `write` on its repositories), then issue it a
token on its page, scoped to those repositories if you like, and store the
token in the pipeline's secrets:

```bash
dotnet nuget push -s https://forge.example.com/repository/nuget/index.json \
  -k "$FORGE_TOKEN" MyLib.1.2.3.nupkg
```

A network the load balancer admits, reading without credentials: create
`office-lan@example.com` with the trusted-header realm of the load balancer
as its realm, give it the grants the network should have, and let the load
balancer name it for the network's clients (see the examples under
[Trusted-header realms](#trusted-header-realms)).

The admin API is the users API: `POST /admin/users` with `"kind":
"service"`, the `username`, an optional `description` and `role` (`reader`
or `writer`), and the optional `realm` (the name of a trusted-header realm).
`GET /admin/users?kind=service` lists the service accounts; every user view
carries `kind`, `description`, `realm` and `last_used_at`. `PATCH
/admin/users/{id}` sets a service account's `description` and `realm`
(`null` clears either) besides `active`. Tokens are
`POST /admin/users/{id}/tokens`, roles `PUT /admin/users/{id}/roles`.

### Usernames

Every account is named by a UPN, `local-part@domain` (`alice@example.com`):
the name says which organization the account belongs to, two
organizations' `alice` cannot collide, and it is the name Entra and Active
Directory sign the person in with. After canonicalization (trimmed, Unicode
NFC, lowercased) a username must have exactly one `@`, a non-empty local part
without whitespace, and a domain of at least two DNS labels without a
trailing dot. Each label is 1 to 63 letters, digits or `-`, and does not start
or end with `-`; the last one is not all digits. A Unicode domain is accepted
as written (`jürgen@müller.example`), and so is its `xn--` form; the two are
different names.

The rule applies wherever an account is created:

- **Admin → Users** and `POST /admin/users` answer 400 ("username must be a
  UPN such as alice@example.com").
- **The bootstrap admin** (see above).
- **`oidc` realms.** The realm's claim chain (the username claim, else the
  email claim when `email_verified`, else `sub`) must yield a UPN for a new
  account, or the login is refused and the login page names the claim. With
  Entra, `preferred_username` is the UPN. Elsewhere, map a claim that holds
  one, such as `email`. A name that is taken gets `-2`, `-3`, … on its local
  part. Whether a realm creates the account at all is set for each realm:
  **Auto-provision users on first login** on its page under **Admin →
  Authentication** (`auto_provision` in its config). The `[oidc]` block does
  not set it; the realm it seeds starts with it on.
- **Credential-forwarding realms create no accounts.** Create each one under
  **Admin → Users** with the realm as its sign-in (`POST /admin/users` with
  `"realm": "<name>"` and no password), named by a UPN whose local part is the
  upstream's username: Forge forwards the local part, so
  `alice@example.com` signs in as the upstream's `alice`. A login the
  upstream accepts but that names no account of the realm is refused. A
  realm config that sets `auto_provision: true` is refused by the admin API.
- **Trusted-header realms** ([below](#trusted-header-realms)) name an account
  by the UPN in their username header. With **Create a user's account on its
  first request** (`auto_provision`) the realm creates a missing one;
  otherwise create each account under **Admin → Users** with the realm as its
  sign-in. A name that is no UPN is refused.
- **[Service accounts](#service-accounts)**, under **Admin → Service
  accounts**.

### Access and sign-in settings

Who may read without signing in, and how people sign in, is not deployment
configuration: an administrator sets it in the web UI (**Admin → Settings**,
`/manage/settings`) or through `GET`/`PUT /admin/settings/auth`. The values
are kept in the database, so every instance applies the same ones: the
instance that takes a change at once, the others within
`auth.realm_cache_ttl_seconds` (10 s), without a restart. A `PUT` changes the
fields its body names; a value out of range is refused with `400` and what is
wrong.

| Setting | Default | Meaning |
| --- | --- | --- |
| `anonymous_mode` | `off` | `off` or `all`: who is served without credentials. A repository is read anonymously only when it also allows it (**Allow anonymous read**, or a grant of the `anonymous` role). Under `all`, signed-in users also read what anonymous callers may. To let a network read without credentials, have the load balancer name a service account through a [trusted-header realm](#trusted-header-realms). |
| `login_mode` | `identifier_first` | The login screen: the username first (then a password prompt or the identity provider whose login domains match), or `combined` (username and password, plus the OIDC button). |
| `allow_password_basic` | `false` | Accept a user's password over HTTP Basic on the feeds (see below). |
| `session_idle_ttl_seconds` | `28800` (8 h) | A browser session ends this long after its last use. |
| `session_absolute_ttl_seconds` | `604800` (7 d) | A browser session ends this long after sign-in. New lifetimes apply to sessions signed in afterwards; an open session's idle window moves to the new idle timeout on its next use. |
| `login_max_failures` | `10` | Failed passwords per client network and username before the lockout; `0` turns it off. Each instance counts its own. |
| `login_failure_window_seconds` | `300` | The failure window, and how long a lockout lasts (at most a day). |

A configuration that still sets one of these (`auth.anonymous_mode`,
`FORGE_AUTH__ALLOW_PASSWORD_BASIC`, …, or the `oidc.session_*` lifetimes)
is refused at startup, with a message naming the keys to remove.

#### Password Basic auth

`allow_password_basic` is off by default: the web UI signs in through its
login form (not affected by this setting), and NuGet clients and scripts
authenticate with API tokens (a token in the Basic password field is always
accepted). An enabled credential-forwarding realm turns the Basic password
path on by itself, because its users have no tokens until they first sign in
— and that path runs the whole password chain, so **local** users' passwords
are then accepted over Basic too, whatever this setting says. Turn it on only
if a client must send a local user's password over Basic without such a
realm.

A password sent over Basic is a **feed** credential only: the admin API
(`/admin/*`) and token minting refuse it with 403, even for an administrator,
because NuGet clients store that password and replay it on every request.
Administer through a browser session (the web UI, or `POST /auth/login` plus
the returned CSRF token), or mint an admin-scoped token
(`{"scope": {"admin": true}}`) for automation.

## Email

Forge sends email for invitations and notifications through one email
service, set up under **Admin → Email** (`/manage/settings/email`). The
settings are stored in the database only: there is no `forge.toml` section
and no `FORGE_*` variable for them, so they can change while Forge runs and
hold the same value on every instance (another instance picks a change up
within `auth.realm_cache_ttl_seconds`). Until they are saved, Forge sends no
email.

- **Sender.** The `From` address, an optional display name and `Reply-To`,
  and how long an invitation link stays valid (default 72 hours, at most
  720).
- **SMTP server.** Host, port and encryption: STARTTLS (port 587, refused
  when the server does not offer it) or TLS from the first byte (SMTPS,
  port 465). The server's certificate is always verified against the
  system's trusted roots; a private CA is not supported. Without TLS Forge
  connects only to a loopback host, a relay on the same machine (port 25).
  A username and password sign in with AUTH PLAIN or LOGIN, whichever the
  server offers; without a username Forge sends without signing in. IMAP is
  not used: a mail server whose IMAP takes an app password (Stalwart, for
  example) takes it on SMTP submission too.
- **Microsoft 365 (Graph).** Forge signs in as an Entra app registration and
  sends with Microsoft Graph, as the sender mailbox; see
  [Microsoft 365](#microsoft-365) below.
- **SMTP server with OAuth.** SMTP submission with an OAuth access token
  from the mail server's own authorization server instead of a password,
  Stalwart's for one; see [SMTP with OAuth](#smtp-with-oauth) below.
- **Secrets** (the SMTP password, the Graph client secret, the OAuth client
  secret and refresh token) are write-only: the page and
  `GET /admin/settings/email` say only whether one is set. Saving without it
  keeps the stored one, unless the SMTP host or username, the Graph tenant
  or app, or the OAuth issuer or mailbox changed. They are sealed at rest
  ([secret encryption](#secret-encryption-at-rest)).
- **Send test email** sends a message with the stored settings, to the
  address you enter or to your own (your UPN), even while sending is turned
  off, and shows the server's error when it fails. The page also shows the
  last send that failed.
- **Turning it off** (uncheck *Send email*) keeps the settings; **Remove**
  deletes them.

Each send is logged with its purpose, the recipient's domain and the
outcome; message bodies, links and secrets never are. The admin API is
`GET`, `PUT` and `DELETE /admin/settings/email` and
`POST /admin/settings/email/test` (`{"to": "..."}`, optional).

### Microsoft 365

For Exchange Online, send through Microsoft Graph rather than SMTP: SMTP
AUTH is off under security defaults, Microsoft recommends turning it off
tenant-wide, and its Basic authentication is being retired. Forge signs in
with the OAuth client credentials grant as an app registration and calls
`sendMail` for the sender mailbox, without saving the message to its Sent
Items; no mailbox password is involved.

1. **Register the app.** In the Entra admin center, **App registrations →
   New registration**, single tenant. Note the **Application (client) ID**
   and the **Directory (tenant) ID**.
2. **Let it send as the sender mailbox only**, with **RBAC for
   Applications** in Exchange Online:

   ```powershell
   Connect-ExchangeOnline
   New-ServicePrincipal -AppId <client id> -ObjectId <enterprise app object id> -DisplayName "Forge"
   New-ManagementScope -Name "Forge sender" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'forge@contoso.com'"
   New-ManagementRoleAssignment -App <client id> -Role "Application Mail.Send" -CustomResourceScope "Forge sender"
   Test-ServicePrincipalAuthorization -Identity <client id> -Resource forge@contoso.com
   ```

   The object id is the enterprise application's (**Enterprise
   applications → Forge → Object ID**), not the app registration's.
3. **Do not consent `Mail.Send` in Entra.** The Microsoft Graph `Mail.Send`
   application permission with admin consent works too, but lets the app
   send as every mailbox in the tenant, and Exchange adds it to the scoped
   role: with both, the scope narrows nothing. (Application Access Policies,
   `New-ApplicationAccessPolicy`, are the legacy way to narrow an Entra
   consent.)
4. **Give Forge a credential**, one of:
   - **A federated credential** (no secret to store or rotate). Choose
     *A federated credential* on the page and save: Forge then shows the
     issuer (its `server.public_base_url`), the subject and the audience.
     On the app, **Certificates & secrets → Federated credentials → Add
     credential → Other issuer**, and enter them. Forge signs its client
     assertions with the issuer keys a federated OIDC realm uses, published
     at `/.well-known/openid-configuration` and rotated automatically;
     Entra must reach that URL over https. The subject is the one a
     federated OIDC realm of the same app and tenant presents, so one
     credential covers both.
   - **A client secret**: **Certificates & secrets → New client secret**,
     and enter its value on the page. Renew it before it expires.
5. **Enter the tenant, the client id and the sender** (its UPN or object
   id; blank sends as the `From` address) on **Admin → Email**, and **Send
   test email**.

A failed send shows Entra's or Graph's error: `invalid_client` with an
`AADSTS…` description names a wrong secret or credential;
`ErrorAccessDenied` means the sender mailbox is outside the app's
`Application Mail.Send` scope (`Test-ServicePrincipalAuthorization` shows
it); a 401 from Graph usually means the sender has no
Exchange Online mailbox or licence. Each instance caches its access token
until shortly before it expires. National clouds and certificate
credentials are not supported yet.

### SMTP with OAuth

A mail server with its own OAuth authorization server, Stalwart for one,
takes an access token on SMTP submission (SASL `OAUTHBEARER`, RFC 7628, or
`XOAUTH2`) where it would take a password. Forge then stores no mailbox
password: it registers itself as an OAuth client, the mailbox authorizes it
once, and Forge refreshes its access token from then on.

1. **Enter the server** on **Admin → Email** with *SMTP server with OAuth*:
   the SMTP host, port and encryption as for SMTP, the **mailbox** Forge
   sends as (the account that authorizes it), and the **authorization
   server**, its issuer URL (`https`). Forge reads its metadata from
   `/.well-known/oauth-authorization-server` (RFC 8414), or
   `/.well-known/openid-configuration`, and the document must name that
   issuer. A **scope** is optional. Save.
2. **Give Forge a client**, one of:
   - **Register Forge** (RFC 7591). Forge registers a confidential client
     named *Forge (`server.public_base_url`)* with the redirect URI the page
     shows, for the authorization code, refresh and (when offered) device
     and client credentials grants. A server that does not take
     registrations from anyone wants them authenticated: with an **initial
     access token**, or as **an account** of the mail server (HTTP Basic).
     Either is used for that request only and never stored.
   - **Enter a client** registered on the server by hand: its client id
     and secret, with the redirect URI the page shows
     (`https://<forge>/admin/settings/email/oauth/callback`).
3. **Authorize Forge**, one of:
   - **In this browser**: Forge sends you to the authorization server (the
     code flow with PKCE, the mailbox as `login_hint`); sign in as the
     mailbox and allow Forge, and the server sends you back to the page.
     The flow is bound to your Forge sign-in and this browser, and expires
     after 10 minutes.
   - **On another device** (the device authorization grant, RFC 8628): the
     page shows a code and where to enter it, and waits until the mailbox
     has allowed Forge.
   - **With the client credentials grant**, when the server issues tokens
     to a client itself: no mailbox authorizes Forge.
4. **Send test email.**

Forge keeps the refresh token sealed with the settings and stores a new one
whenever the server rotates it; instances take turns refreshing, so two
never spend the same refresh token. When the server refuses a refresh
(`invalid_grant`: the authorization was revoked or expired), sending stops
and the page asks for a new authorization. A token the mail server refuses
is dropped and the next send gets a new one. Saving the settings keeps the
client while the issuer stays the same, and the authorization while the
SMTP host and the mailbox stay the same too: another host gets no token
before the transport is authorized again. Forge deletes a client it registered (RFC 7592) when the settings stop
using it, or names it so that it can be removed on the server when the
server offers no way to.

**Stalwart.** Stalwart 0.16 has all of this built in: its issuer is its
public https URL. Registration wants an account allowed to register OAuth
clients (the administrator account is), so choose *An account of the mail
server* and enter it. Stalwart offers no RFC 7592 management: remove a client
Forge no longer uses under its OAuth clients. Authorize in the browser on
Stalwart's sign-in page, or on another device at Stalwart's `/device` page.
Stalwart issues no tokens by the client credentials grant. The mailbox's
account needs the permission to send email; a refused token is answered
`535 5.7.8`, which the test send shows.

The admin API is `POST /admin/settings/email/oauth/register` (body
`{"initial_access_token": "…"}`, `{"username": "…", "password": "…"}` or
`{}`), `DELETE /admin/settings/email/oauth/client`,
`POST /admin/settings/email/oauth/authorize` (`{"method":
"authorization_code" | "device" | "client_credentials"}`),
`GET /admin/settings/email/oauth/callback` and
`POST /admin/settings/email/oauth/device/{id}` (one poll of a device
authorization).

## Secret encryption at rest

Upstream proxy passwords, authentication-realm secrets (OIDC client
secrets, credential-forwarding peppers), the email service's password or
client secret ([Email](#email)), the generated registry-token key
(without `docker.token_secret`) and the keys Forge signs its OIDC client
assertions with (a realm with a federated credential) are stored with
double-envelope encryption:
DEK → KEK → a root key that never enters the database. Encryption is
**required**: the `[crypto]` section names exactly one root provider, and
Forge refuses to start without a usable root key, naming what to set:

```bash
openssl rand -base64 32          # generate the root key once; store it in your secret manager
FORGE_CRYPTO__ROOT__PROVIDER=env
FORGE_ROOT_KEY=<base64 32 bytes>
# or, for a mounted secret file:
# FORGE_CRYPTO__ROOT__PROVIDER=file
# FORGE_CRYPTO__ROOT__ROOT_KEY_PATH=/run/secrets/forge_root_key
```

The Helm chart uses the `env` provider and refuses to render without
`FORGE_ROOT_KEY` (in `secretEnv`, `existingSecret` or `env`); the kustomize
base sets the provider, and `forge.env` holds the key.

The root key is part of your backup. Without it, stored secrets cannot be
recovered: they have to be entered again (proxy passwords, realm secrets,
the email credentials), and Forge generates a new registry-token key and new
issuer keys. Packages and metadata are unaffected. AWS KMS is not supported
yet.

There is no plaintext mode: every instance needs the same root key, and a
secret is never written unencrypted.

Each encrypted secret is bound to its row and to where it is sent: a proxy
password to the origin (scheme, host and port) of the repository's
`remote_url`, an OIDC client secret to the realm's `issuer` and `client_id`,
the email password to the SMTP host and username, the Graph client secret to
the tenant and app, the OAuth mailbox's secrets to the issuer, client,
mailbox and SMTP host.
Changing those through the admin API asks for the secret again. Changing
them directly in the database makes the secret undecryptable (the proxy
then fails instead of sending the password to the new host), and it has to
be entered again through the API. For a realm, that is an edit
(`PATCH /admin/realms/{id}` or the realm form) that includes the secret:
until then the realm is skipped at login, and an edit without the secret
answers 400 naming it.
`GET /admin/crypto/keys` reports the keys' metadata and the current
`root_key_version`. Key rotations (`POST /admin/crypto/rotate/{dek,kek,root}`
and the worker's age-based rotation) are serialized across all instances; a
rotation requested while another one runs is answered with `409 Conflict` and
can simply be retried.

### Rotating the root key on a running cluster

Every instance must be able to unwrap the KEKs with whichever root they were
last wrapped under, so rotate the root in **two phases**, with a complete
rolling restart after each:

1. **Add the new key as the previous key everywhere.** Keep the current key
   in `FORGE_ROOT_KEY` and add the *new* key as the previous one:
   `FORGE_CRYPTO__ROOT__ROOT_KEY_ENV_PREVIOUS=FORGE_ROOT_KEY_PREVIOUS` plus
   `FORGE_ROOT_KEY_PREVIOUS=<new key>` (with the file provider,
   `FORGE_CRYPTO__ROOT__ROOT_KEY_PATH_PREVIOUS`). Roll this out to every
   instance. Nothing is re-wrapped yet, but every instance can now read keys
   wrapped under either root.
2. **Swap.** Put the new key in `FORGE_ROOT_KEY` and the old one in
   `FORGE_ROOT_KEY_PREVIOUS`, and roll this out. Each instance re-wraps the
   KEKs under the new root at startup; `POST /admin/crypto/rotate/root` does
   the same on demand. During the roll-out old and new instances both reach
   both roots, so neither fails to unwrap (an instance that has not restarted
   yet may wrap a KEK back under the old root; that is harmless and converges
   once every instance runs phase 2).
3. Once `GET /admin/crypto/keys` shows every **non-revoked** KEK on the new
   `root_key_version` (revoked KEKs keep the old one and are never used
   again), remove the previous key and roll out once more. Keep the old root
   key with your backups for as long as you keep a database backup taken
   before the rotation: restoring such a backup needs it.

Swapping in one step makes the instances that still run with only the old
key fail to unwrap KEKs that a new instance has already re-wrapped.

## Reverse proxy

- Terminate TLS and forward to `http://forge:8421`, preserving `Host`.
  Forward `X-Forwarded-For`, and list the proxy in
  `FORGE_AUTH__TRUSTED_PROXY_CIDRS`.
- Let only the proxy reach Forge. Forge believes the `X-Forwarded-For` of
  every peer in `trusted_proxy_cidrs`, and the headers of a
  [trusted-header realm](#trusted-header-realms), so anything else that can
  connect from those ranges can pick the client address the login lockout
  sees. On Kubernetes the range is usually the whole pod network: admit only
  the ingress controller or gateway with a NetworkPolicy (the Helm chart's
  `networkPolicy.from`, the kustomize `network-policy` component; the CNI
  must enforce it).
- Allow large request bodies for `PUT /repository/{repo}/package` (package pushes),
  for image pushes under `/v2`, where docker sends a whole layer in one
  request, and for file uploads under `/repository` (and the web UI's
  `/browse/raw`). In nginx that is `client_max_body_size`. Match it to the
  largest upload limit a repository has (set per repository in the web UI;
  512 MiB for package and raw repositories and 1 GiB per blob for docker by
  default).
- Serve `/v2` at the root of the host: Docker clients always talk to
  `https://<host>/v2/`, whatever path `public_base_url` has. A docker
  repository with a `host` ([docs/docker.md](docker.md#names)) needs that
  name routed to Forge with `Host` preserved, and covered by the
  certificate.
- Disable response buffering or give it enough room. Package downloads are
  streamed.
- Do not rewrite the `Origin` or `Sec-Fetch-Site` headers. Forge refuses
  state-changing browser requests that are cross-site, so a proxy that strips
  or fakes these headers breaks that protection.
- With an `https://` `public_base_url` Forge sends
  `Strict-Transport-Security: max-age=31536000`; serve it over https only.
  API responses and every feed and registry response to a request with
  credentials are `Cache-Control: private, no-store`; feed responses carry
  `Vary: Authorization, Cookie, X-NuGet-ApiKey` and registry responses
  `Vary: Authorization, Cookie, Accept`: keep a caching proxy from
  overriding either.
- Forge bounds slow clients itself (`server.header_read_timeout_seconds`,
  `body_idle_timeout_seconds`, `request_timeout_seconds`); keep the proxy's
  own timeouts at least as long for package pushes. A proxy repository's
  first download of a package or layer may take up to
  `proxy.download_timeout_seconds` (30 min) before Forge answers, plus
  `request_timeout_seconds` to store it: allow that long a wait for the
  response on the feed and registry paths too, or the client is cut off
  first.
- Forge speaks HTTP/1.1 to the proxy (no h2c). `header_read_timeout_seconds`
  (default 150) also closes keep-alive connections that stay idle that long.
  If the proxy keeps upstream connections open longer than that (Envoy and
  Istio default to 1 hour), lower the proxy's upstream idle timeout or raise
  this setting; otherwise the proxy can reuse a connection Forge is closing
  and answer 502, which it does not retry for a push. AWS ALB and
  ingress-nginx (60 s), Traefik (90 s) and Caddy (120 s) are below the
  default.

Minimal nginx example:

```nginx
server {
    listen 443 ssl http2;
    server_name nuget.example.com;
    # ssl_certificate …; ssl_certificate_key …;

    client_max_body_size 1g;   # the largest repository upload limit (docker: 1 GiB by default)
    proxy_request_buffering off;
    proxy_buffering off;

    location / {
        proxy_pass http://forge:8421;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

### Trusted-header realms

A `trusted_header` realm (**Admin → Authentication → New realm → Trusted
header**) authenticates a request as the account a header of the load
balancer or reverse proxy in front of Forge names, in the style of
`REMOTE_USER`. The proxy decides who gets which name:

- an **SSO proxy** (oauth2-proxy, Authelia, …) names the person it signed in;
- a **load balancer** names a [service account](#service-accounts) for a
  network or machines it admits (`ci-runners@example.com`,
  `office-lan@example.com`), by source network, mTLS or VPN. This is how a
  network reads without credentials: the load balancer filters by network
  next to the rest of the network policy, and Forge only checks the headers.
  Create the service account under **Admin → Service accounts** with the
  realm as its trusted-header realm, and give it the grants the network
  should have. Only that realm may name it.

| Config key | Meaning |
| --- | --- |
| `username_header` | The header naming the account, e.g. `X-Forwarded-User`. Its value is a UPN. |
| `secret_header` | The header the proxy proves itself with, e.g. `X-Forge-Proxy-Secret`. |
| `secret` | Its value, 16 to 1024 printable characters without spaces (`openssl rand -hex 32`, or **Generate a secret** in the form). Write-only and sealed at rest like the other realms' secrets; compared in constant time. |
| `auto_provision` | Create a user's account on its first request when the realm has none of the name (off by default). It never creates a service account, nor takes over the name of one. |

What Forge believes, and when:

- The headers count only when the **socket peer** is in
  `auth.trusted_proxy_cidrs` and the request's `Host` is one of Forge's own
  names (the host of `public_base_url`, or one in `server.allowed_hosts`: a
  DNS-rebinding page reaches the proxy under its own name). From any other
  request they are ignored.
- They name the caller only when the request has **no credential of its
  own**: an API token, a password or a signed-in session is that
  credential's, whatever the headers say, and one that is refused is a 401,
  never the account the headers name. That includes an API token sent as
  `Authorization: Bearer` to a feed, as npm sends its `_authToken`: an SSO
  proxy must not forward a Bearer token of its own to `/repository`
  (oauth2-proxy's `--pass-authorization-header` stays off).
- The headers present but no realm's secret among them, the right secret
  with no, an empty, a repeated or an invalid name, a name of no account of
  the realm (without `auto_provision`), of a deactivated account, or of an
  account of another kind (local, OIDC, credential forwarding) or another
  realm, a service account of another realm or of none included: the
  headers **name nobody**. The request goes on as one without credentials,
  never anonymous whatever the anonymous mode: what needs a principal
  answers 401, while a credential of its own still counts (an API token sent
  as `Authorization: Bearer`, a registry token) and its sender can sign in.
  Deactivating the service account a load balancer names for a network so
  cuts the network's access, not the access of the people on it. The
  refusal is logged (`trusted-header credentials refused`).
  A realm never maps a name onto another source's account, and never
  creates or names the built-in `anonymous` principal.
- The headers are an **ambient** credential: the proxy adds them to every
  request of a client it admits, the ones a browser sends for a foreign page
  included. So a request they authenticate holds the account's grants but
  **never the `admin` role**: the admin API and minting tokens refuse it
  (403), and publishing packages or images takes an API token, which an
  administrator issues on the account's page (**Admin → Users → <user> →
  Tokens**, or **Admin → Service accounts → <account>**). State-changing
  requests a browser marks as cross-site are refused (403) before
  authentication. An account of the realm never holds the `admin` role
  either (creating or making it an admin is a 400): it would count as an
  administrator nobody can act as, and the last real one could go.
- A feed request the named account may not make is challenged like an
  anonymous one (401 with `WWW-Authenticate: Basic`), so a client with
  credentials of its own, such as NuGet, sends them.
- When the realm last named each account is kept, written at most once a
  minute: **Admin → Service accounts** shows it as the account's last use.
- Forge answers every feed and registry request the headers authenticated
  with `Cache-Control: private, no-store`: no cache varies on the headers.
  Keep caches from overriding it, and do not let one between the proxy and
  Forge store `/repository` responses regardless of their caching headers.
- In the web UI a user the SSO proxy signed in is signed in without a
  session; they sign out at the proxy.

The proxy must remove both headers from every request a client sends, and
set them only for the clients it admits, the secret only together with a
name. Most proxies replace a header they set; make sure they also drop the
client's when they set none.

nginx, admitting a network as a service account (`proxy_set_header`
replaces the client's header, and sends none for an empty value):

```nginx
# The networks admitted as a service account, and the secret only with a name.
geo $forge_account {
    default         "";
    10.20.0.0/16    "ci-runners@example.com";
}
map $forge_account $forge_proxy_secret {
    ""       "";
    default  "<the realm's secret>";
}

server {
    # … as above …
    location / {
        proxy_pass http://forge:8421;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-User $forge_account;
        proxy_set_header X-Forge-Proxy-Secret $forge_proxy_secret;
    }
}
```

nginx behind oauth2-proxy (`--set-xauthrequest`), naming the person it
signed in; every request it lets through has a name:

```nginx
location /oauth2/ {
    proxy_pass http://oauth2-proxy:4180;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
location = /oauth2/auth {
    internal;
    proxy_pass http://oauth2-proxy:4180;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}
location / {
    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in;
    auth_request_set $forge_user $upstream_http_x_auth_request_email;

    proxy_pass http://forge:8421;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-User $forge_user;
    proxy_set_header X-Forge-Proxy-Secret "<the realm's secret>";
}
```

NuGet, npm and docker clients cannot sign in to an SSO proxy: serve the
feeds and `/v2` to them past it (another host name, or the proxy's own rule
for requests with an `Authorization` or `X-NuGet-ApiKey` header), with
their API tokens.

ingress-nginx runs the same directives in a `configuration-snippet`
annotation where the controller allows snippets. Without snippets, use
`nginx.ingress.kubernetes.io/auth-url` and
`nginx.ingress.kubernetes.io/auth-response-headers`: the controller copies
the listed headers of the auth service's answer onto the request, in place
of the client's, so let the auth service answer both the name and the
secret.

Traefik (v3), admitting a network: a router for the network's clients sets
both headers, the other router removes them (an empty value removes a
header):

```yaml
http:
  routers:
    forge-ci:
      rule: "Host(`forge.example.com`) && ClientIP(`10.20.0.0/16`)"
      priority: 100
      service: forge
      middlewares: [forge-ci-account]
    forge:
      rule: "Host(`forge.example.com`)"
      service: forge
      middlewares: [forge-no-account]
  middlewares:
    forge-ci-account:
      headers:
        customRequestHeaders:
          X-Forwarded-User: "ci-runners@example.com"
          X-Forge-Proxy-Secret: "<the realm's secret>"
    forge-no-account:
      headers:
        customRequestHeaders:
          X-Forwarded-User: ""
          X-Forge-Proxy-Secret: ""
```

Behind an SSO proxy, Traefik's `forwardAuth` with
`authResponseHeaders: [X-Auth-Request-Email]` replaces the client's header
with the auth service's answer; add the secret with a `headers` middleware
after it, and set `username_header` to `X-Auth-Request-Email`.

HAProxy, admitting a network:

```haproxy
frontend fe_forge
    bind :443 ssl crt /etc/haproxy/forge.pem
    option forwardfor
    http-request del-header X-Forwarded-User
    http-request del-header X-Forge-Proxy-Secret
    acl ci_network src 10.20.0.0/16
    http-request set-header X-Forwarded-User ci-runners@example.com if ci_network
    http-request set-header X-Forge-Proxy-Secret <the realm's secret> if ci_network
    default_backend be_forge
```

## Health probes

| Endpoint | Use |
| --- | --- |
| `GET /healthz` | Liveness. Never touches a dependency. |
| `GET /readyz` | Readiness. PostgreSQL and S3 are each checked with a 3 s deadline; the endpoint returns 503 with the failing check names. With the [local blob cache](#local-blob-cache), an unreachable S3 is not a failure: 200 with `"status": "degraded"` and `"object_store": "degraded"`. |
| `GET /version` | The running version and revision. |

The image has no shell tools such as `curl`. Use your orchestrator's HTTP
probes rather than a Docker `HEALTHCHECK`.

Forge starts listening only **after** startup work is done: database
migrations, the bucket check, the bootstrap admin, the secret-encryption
bootstrap. On the first start of a new version (migrations) or
against a slow database this can take a while, and `/healthz` does not answer
until then. Give the container a **startup probe** on `/healthz` with a
generous budget, so the liveness probe does not restart it mid-migration.
(With the [local blob cache](#local-blob-cache), an unreachable S3 does not
hold up the start: the bucket check is retried in the background.)

```yaml
startupProbe:
  httpGet: { path: /healthz, port: 8421 }
  periodSeconds: 5
  failureThreshold: 60      # up to 5 minutes for migrations
livenessProbe:
  httpGet: { path: /healthz, port: 8421 }
  periodSeconds: 10
readinessProbe:
  httpGet: { path: /readyz, port: 8421 }
  periodSeconds: 10
```

The image runs as the numeric user `10001:10001`, so
`securityContext.runAsNonRoot: true` works without further settings.

On SIGTERM, Forge stops accepting connections and lets in-flight requests
finish before exiting. Give it a termination grace period long enough for your
largest package download.

## Telemetry

Forge exports **OpenTelemetry** metrics, traces and logs over OTLP/HTTP,
with the official OpenTelemetry SDK. Each signal is off until `[telemetry]`
turns it on:

```toml
[telemetry]
metrics = true        # FORGE_TELEMETRY__METRICS=true
traces = true         # FORGE_TELEMETRY__TRACES=true
logs = true           # FORGE_TELEMETRY__LOGS=true
# per_repository = true          # the repository's name on the metrics
# inventory_interval_seconds = 300
```

Where the signals go, and how, is set by the standard OpenTelemetry
variables, read by the SDK:

| Variable | Meaning |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | The OTLP/HTTP endpoint, usually an [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) beside Forge; default `http://localhost:4318`. Forge appends `/v1/metrics`, `/v1/traces` and `/v1/logs`; the `OTEL_EXPORTER_OTLP_{METRICS,TRACES,LOGS}_ENDPOINT` variables set one signal's full URL. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Headers sent with every export (`api-key=...` for a vendor's backend). Keep it in a secret. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf`, the only protocol Forge speaks: Forge refuses to start with `grpc`. |
| `OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_TIMEOUT` | `gzip`; the export timeout in milliseconds (default 10 000). |
| `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | The resource. Forge sets `service.name=forge`, `service.version`, `vcs.ref.head.revision`, `host.name` and a random `service.instance.id`; what these variables say wins. |
| `OTEL_METRIC_EXPORT_INTERVAL` | Milliseconds between two metric exports (default 60 000). |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Which traces are kept (default `parentbased_always_on`: all, and a caller's decision); e.g. `parentbased_traceidratio` and `0.1`. |
| `OTEL_SDK_DISABLED` | `true` turns every signal off, whatever `[telemetry]` says. |

An export that fails is logged and never fails a request: metrics are
cumulative, so the next export carries what a failed one held, while a
failed batch of spans or log records is dropped. Each instance exports its
own telemetry.

**Metrics.** The names follow the OpenTelemetry semantic conventions where
one exists (`http.server.request.duration`, `db.client.connection.count`),
and are `forge.*` otherwise. Durations are histograms in seconds, sizes in
bytes (`By`). **Attributes stay bounded**: none carries a package id, a
version, an image or tag, a username, a token or a path. A request is
counted under the *surface* of the route it matched (`forge.surface`:
`nuget`, `oci`, `plugin_npm`, `plugin_raw`, `plugin_other`, `admin`,
`browse`, `auth`, `health`, `ui`; `repository` for a `/repository/…` request
that named no repository), never its URL. The repository's name
(`forge.repository`) is the one attribute an administrator chooses; with
very many repositories turn `telemetry.per_repository` off and the
repositories add up.

| Area | Instruments (attributes) |
| --- | --- |
| HTTP | `http.server.request.duration` (`forge.surface`, `http.request.method`, `http.response.status_code`), to the response headers; `http.server.active_requests` (`http.request.method`); `http.server.response.body.size` |
| Proxies | `forge.proxy.lookups` (`forge.repository`, `forge.proxy.kind`: `metadata`, `package`, `manifest`, `blob`, `file`; `forge.proxy.outcome`: `hit`, `fetched`, `stale_served`, `negative_cached`, `delay_gated`, `not_found`, `offline`, `upstream_error`, `error`); `http.client.request.duration` of the requests to the upstreams (`forge.repository`, `http.request.method`, `http.response.status_code`, or `error.type` when none came); `forge.proxy.upstream.fetched` (bytes) |
| Storage | `forge.s3.operation.duration` (`forge.s3.operation`, `forge.s3.outcome`: `ok`, `not_found`, `precondition_failed`, `unreachable`, `breaker_open`, `error`); `forge.s3.circuit_breaker.open` (with the local blob cache); the counters of `GET /admin/blob-cache` as `forge.blob_cache.*` (`hits`, `served`, `hits_while_store_down`, `misses`, `fills`, `fill_failures`, `corrupt`, `evictions`, `evicted`, `bypassed`, `verifications`, and `entries`, `usage`, `reserved`, `limit`); `forge.staging.usage` against `forge.staging.limit` (`server.max_staging_bytes`); `forge.outbox.pending`, `forge.outbox.due`, `forge.outbox.oldest_due.age`; `forge.gc.deleted` (`forge.gc.source`) |
| Cache | `forge.cache.lookups` (`forge.cache.tier`: `l1` in process, `l2` Redis; `forge.cache.result`); `forge.cache.backplane.connected` (with Redis); `forge.cache.invalidations` (`forge.cache.direction`: `sent`, `received`) |
| Database | `db.client.connection.count` (`db.client.connection.state`: `idle`, `used`), `db.client.connection.max`, `db.client.connection.wait_time`, `db.client.connection.timeouts` |
| Workers | `forge.worker.runs` (`forge.worker`, `forge.worker.outcome`), `forge.worker.run.duration`, `forge.worker.last_success.time` (Unix seconds), `forge.worker.interval`, `forge.worker.restarts`, for the `outbox`, `reconciler`, `proxy-refresh`, `retention`, `auth-reaper`, `cred-reaper`, `registry-sweeper`, `crypto-rotation`, `blob-cache` and `metrics-inventory` workers (restarts for every worker) |
| Retention | `forge.retention.runs` (`forge.repository`, `forge.retention.outcome`), `forge.retention.versions` (`forge.retention.action`: `unlisted`, `deleted`), `forge.retention.freed` (the repository's size before a run less its size after) |
| Auth | `forge.auth.sign_ins` (`forge.auth.realm_type`, `forge.auth.outcome`): a password through the realms, on the login form or over HTTP Basic, and OIDC logins; `forge.auth.throttled` (`forge.auth.throttle.reason`), `forge.auth.token_exchanges` (`forge.auth.exchange.outcome`), `forge.auth.jwks.refresh_failures`, `forge.auth.forwarding.errors` |
| Inventory | `forge.repositories` (`forge.repository.format`, `forge.repository.kind`), `forge.repository.versions` (package versions, image tags, files) and `forge.repository.size` (`forge.repository`), counted by a worker every `telemetry.inventory_interval_seconds`, never per export |

The inventory and the outbox backlog are database-wide: every instance
reports the same numbers, so aggregate them with `max`, not `sum`. The pool's
wait times come from sqlx's pool events, which `forge-server` reads whatever
`RUST_LOG` says.

In Prometheus (the Collector's `prometheus` or `prometheusremotewrite`
exporter, or Prometheus' own OTLP receiver), the names become
`http_server_request_duration_seconds`, `forge_proxy_lookups_total`,
`forge_repository_size_bytes` and so on, the attributes `forge_surface`,
`forge_repository`, …, and `job` and `instance` come from `service.name` and
`service.instance.id`. [deploy/monitoring](../deploy/monitoring/README.md)
has an example Collector configuration, a Grafana dashboard and alerting
rules written against those names: a worker without a successful pass for
three of its intervals, the S3 circuit breaker open, a high 5xx rate, a
growing outbox backlog, upstream errors and rate limits per proxy, an
exhausted connection pool, a lost Redis backplane and nearly full staging
space.

**Traces.** Each request is a server span (`GET /repository/{repo}/{*rest}`:
the route, never the URL, names it), a child of the caller's trace when the
request carries a W3C `traceparent`. Beneath it are the spans of a proxy's
lookup (`proxy package`, with its outcome), its requests to the upstream
(client spans, which send the trace on in their own `traceparent`, so a
Forge proxying another Forge continues the trace), and the S3 operations
(`S3.GetObject`, …). Each pass of a background worker is a trace of its own
(`outbox pass`, …). Health probes make no spans. A span's URL never holds a
query string or credentials, and the secret in the path of an npm web login
(the URL the client polls for its token, the page that approves the login
and the API behind it) is recorded as `{secret}`.

**Logs.** With `logs` on, what Forge logs (filtered by `RUST_LOG`, as the
console log is) is exported too, each record with the trace and span it was
written in, so a backend links a request's log lines to its trace. The
console log stays as it is.

## Running more than one instance

Instances coordinate through PostgreSQL (row locks and leases), so any number
can run behind the load balancer. Configure `FORGE_REDIS__URL` so that caches
and invalidations converge immediately, not only after a TTL expires. The
[access and sign-in settings](#access-and-sign-in-settings) are read from the
database: the other instances follow a change within
`auth.realm_cache_ttl_seconds`. The password-failure lockout is kept in memory
on each instance; the networks a username signed in from, which that
username's backoff exempts, are shared through the database.

Redis is optional at runtime: an instance starts while Redis is unreachable
(after waiting a few seconds for it) and works from its own memory until
Redis is back. A Redis that stops answering slows only the requests that
talk to it, and an instance whose invalidation subscription goes silent
notices within about 15 s, drops its in-memory cache and resubscribes.

- **Connections.** Every instance opens up to `database.max_connections`
  (default 20); keep instances × that below PostgreSQL's `max_connections`.
  Through PgBouncer, use **session** pooling: migrations and key rotation
  take session-level advisory locks, which transaction pooling breaks.
- **Upgrades.** Migrations run at startup, serialized by an advisory lock.
  Once a newer version has migrated, an instance of the older version
  refuses to start, so roll forward and do not restart old instances in the
  middle of a rollout.
- **Rolling deploys.** On SIGTERM Forge stops accepting connections at once
  and drains in-flight requests. Give the load balancer time to stop routing
  to the instance first (for Kubernetes a `preStop` sleep of 5 to 10 s),
  otherwise requests routed in that gap are refused, and a refused push is
  not retried.
- **Temp space.** Pushes and first-time proxy downloads are staged in
  `server.staging_dir` (default `forge-staging` in the system temp
  directory). All staged files of an instance share `server.max_staging_bytes`
  (default four times the largest item: a push under the default upload
  limits, `proxy.max_package_bytes` or `docker.max_blob_bytes`, so 4 GiB;
  `0` removes the limit); past it, pushes and downloads are answered `503`
  with `Retry-After` until space frees up. A repository's upload limit may
  not exceed the budget (less `nuget.max_nuspec_bytes`), so raise the
  budget before giving a repository a larger limit. An explicit budget below
  the 1 GiB docker defaults lowers them to what it holds: docker
  repositories without a limit of their own accept layers up to the budget
  (less `nuget.max_nuspec_bytes`), and so do docker proxy downloads unless
  `docker.max_blob_bytes` is set (startup warns). Size the volume above that budget. Each process stages in a
  locked subdirectory of its own, and the files a killed process left are
  removed at the next start however recent they are, so they do not add to
  the space a restarted instance needs. Give each instance a volume of its
  own (the Helm chart and the Kubernetes base do). Instances on different
  hosts may share one only if its file locks work across those hosts (NFSv4,
  or NFSv3 with `lockd`; not a mount with `nolock` or `local_lock`):
  otherwise one instance's startup can remove another's files mid-request.
  Where locks do not work at all, a killed process's files are removed once
  idle for an hour instead. The staging directory must belong to Forge's
  user and must not be writable by group or others (unless it is sticky,
  like `/tmp`); Forge refuses to start otherwise, and creates a missing one,
  and each process's subdirectory, with mode `0700`. A staged file is read
  back through the handle it was written with, never by its name. On a host
  shared with other users, point `server.staging_dir` at a directory of
  Forge's own: another user could create the default one under the system
  temp directory first, and Forge then refuses to start. (The container
  image and the Kubernetes manifests are not affected.)
- **Audit log.** Package mutations and admin changes are logged at INFO
  under the `forge::audit` target, with the user/token or workload that
  made them; keep those lines.
- **Outbound proxy.** Proxy repositories send upstream traffic through
  `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` unless `NO_PROXY` exempts the
  host. Forge never sends an upstream request, or follows a redirect, to a
  link-local or cloud-metadata address (`169.254.0.0/16`, `fe80::/10`,
  `metadata.google.internal`, …). Through an outbound proxy the proxy
  resolves the host name, so Forge resolves it first and refuses it when any
  of its addresses is such a target. A name that resolves differently for
  the proxy than for Forge, or that only the proxy can resolve, still gets
  through: block those addresses on the proxy too. A proxy's format chooses
  which upstream URLs to request, but Forge sends them only to the origin of
  the repository's `remote_url` and to origins the upstream's own documents
  name ([format-plugins.md](./format-plugins.md#security-model)); to keep
  internal services out of reach even of an upstream that names them, block
  them on the outbound proxy or with network policy.

### Redis is a trust boundary

Anything that can write to Redis can write Forge's shared cache. Forge
therefore keeps every value a security decision or a client rests on **out of
Redis**: authorization sets, credential-forwarding verdicts, OIDC discovery
documents and signing keys, workload-identity token verdicts, and a proxy's
upstream service index, manifests and registrations are cached in each
instance's memory only. Redis carries only their invalidations, so the worst
a Redis writer can do to them is evict them early. Publishing invalidations
for ever new names cannot grow an instance's memory without bound either: the
per-name bookkeeping is capped (100,000 names), and an instance that reaches
the cap clears it together with its in-memory cache, which costs a round of
cache misses, not correctness. The only values still
shared through Redis are two proxy markers ("listing refreshed", "version
rejected"); forging them can hide a proxied package until its TTL expires,
not change what is served.

Still treat Redis like the database: a dedicated instance (or ACL user) for
Forge, `requirepass`/ACL credentials in the URL, not reachable from outside
the deployment, and TLS when it crosses a network you do not control
(`FORGE_REDIS__URL=rediss://user:password@redis.internal:6380`; the server
verifies the certificate against the system trust store).

## Local blob cache

Optionally, Forge keeps a copy of the blobs it serves on a local disk. Hot
downloads are then served without S3 (no request, no egress), and packages in
the cache **keep resolving while S3 is unreachable**. S3 stays the source of
truth: the cache only ever holds copies of objects S3 has, and since blobs are
content-addressed and immutable, a copy needs no invalidation. The disk can be
anything from an `emptyDir` to a dedicated or persistent volume.

| Setting | Meaning |
| --- | --- |
| `FORGE_BLOB_CACHE__PATH` | The cache directory, e.g. `/var/cache/forge/blobs`. Unset (the default) = no cache. Each instance needs a directory of its own. It must belong to Forge's user, and neither group nor others may write to it: startup refuses it otherwise, since a file placed there is served as the blob it is named after. Forge creates it (mode `0700`) when it is missing, so point it at a subdirectory of a mounted volume, whose root belongs to root. Entries are readable by Forge's user alone (`0600`). On Kubernetes, give the pod `fsGroupChangePolicy: OnRootMismatch` next to its `fsGroup` (the shipped manifests and chart do): otherwise the kubelet makes the directory group-writable at each pod start. Forge then restores it to `0700` and its entries to `0600`, logging a warning, and checks each entry against its hash on its first hit. |
| `FORGE_BLOB_CACHE__MAX_BYTES` | `auto` (default): the size of the filesystem holding the path, minus `min_free_bytes`, minus `server.max_staging_bytes` when staging is on the same filesystem; re-read every minute, so a resized volume is picked up without a restart. Or a fixed number of bytes. |
| `FORGE_BLOB_CACHE__MIN_FREE_BYTES` | Free space the cache always leaves on its filesystem, evicting instead of filling it, even when something else uses the disk too. Default: 5 % of the filesystem. On a shared disk with less free space than that, nothing is cached (logged as a warning at startup). |

**How it fills.** A download looks in the cache first; a hit never contacts
S3. A miss streams the blob from S3 to the client and into the cache at the
same time; concurrent misses of one blob share that single S3 read. The copy
is checked against the blob's SHA-256 and size before it joins the cache. A
push or a first-time proxy download writes its staged file through to the
cache once S3 has it (a hard link when staging shares the cache's
filesystem, a copy otherwise), so freshly published packages are cached too.
Package manifests (`.nuspec`) go through the cache as well. With the cache
on, package downloads also answer `Range` requests.

**Eviction** is first in, first out: over the limit, the blobs filled longest
ago go first, however often they are read (a read changes nothing on disk).
A file's modification time is its fill time, so the order survives a restart
on a persistent volume. A blob that garbage collection deletes from S3 is
dropped from the cache of the instance that deletes it at once, also when a
download was filling it at the time. Every other instance checks its cached
blobs against the database at startup and every 10 minutes, and drops those
garbage collection deleted (one query per 1,000 cached blobs).

**While S3 is down:**

- Cached blobs are served as usual. Package metadata comes from PostgreSQL,
  which is still required.
- Uncached downloads, pushes and first-time proxy downloads answer `503` with
  `Retry-After`. A circuit breaker makes them fail at once once S3 is known to
  be down, instead of each waiting for the S3 timeout. Nothing is ever
  acknowledged that exists only on one instance's disk.
- `/readyz` answers 200 with `"object_store": "degraded"`, so instances stay
  in the load balancer and serve what they have (a database failure is still
  503).
- An instance (re)started while S3 is unreachable starts anyway, serves its
  cache, and retries the bucket check in the background.
- When S3 is back, misses fill again and `/readyz` reports `ok`, without a
  restart.

**Robustness.** Any cache I/O error (a full disk, a read error, a file of the
wrong size) is logged, the entry is dropped and the request continues from S3
(or answers 503 while S3 is down): the cache never turns a servable request
into an error. Blobs found at startup are checked against their hash on their
first hit, so a file damaged while Forge was down is fetched again; partial
fills a killed process left are removed at startup.

**Statistics.** `GET /admin/blob-cache` (admin) reports the size against the
effective limit (and whether it is `auto`), the hit ratio, bytes served from
the cache, fills, fill failures, evictions and hits served while S3 was down.
The same numbers are logged every ten minutes (`local blob cache`).
Each instance has a cache of its own, so the numbers are those of the
instance that answered the request: `instance` names it by its host name
(`HOSTNAME`, the pod's name on Kubernetes) and start time. Behind a load
balancer, consecutive requests may be answered by different replicas; to see
one replica's numbers, ask it directly (its pod IP, or `kubectl
port-forward pod/<name>`), or read its log.

**On Kubernetes** (see [deploy/kubernetes](../deploy/kubernetes/README.md#local-blob-cache)):

- **`emptyDir`** with a `sizeLimit` and a fixed `max_bytes` below it — the
  simplest option, and it works with any number of replicas. `statvfs` on an
  `emptyDir` reports the node's filesystem, not the volume's `sizeLimit`, so
  with `auto` the cache could outgrow the limit and get the pod evicted. The
  cache goes with the pod: it bridges an S3 outage only while the pod keeps
  running.
- **A generic ephemeral volume** (`ephemeral.volumeClaimTemplate`) on a fast
  StorageClass gives each pod a disk of its own where `auto` works; it is
  deleted with the pod, too.
- **A PersistentVolume** lets the cache survive pod restarts during an S3
  outage. A ReadWriteOnce volume needs a single replica replaced with
  `strategy: Recreate` (the `local-cache-persistent` component), or Forge as
  a StatefulSet with a `volumeClaimTemplate` per pod. Keep
  `fsGroupChangePolicy: OnRootMismatch` in the pod's security context (the
  default of the manifests and the chart): with the kubelet's default,
  `Always`, every pod start walks the whole cache to change its group.

With the Helm chart, set `config.blob_cache` and mount the volume with
`extraVolumes`/`extraVolumeMounts`:

```yaml
config:
  blob_cache:
    path: /var/cache/forge/blobs   # Forge creates it in the volume
    max_bytes: 8589934592   # below the emptyDir sizeLimit
extraVolumes:
  - name: blob-cache
    emptyDir: { sizeLimit: 10Gi }
extraVolumeMounts:
  - name: blob-cache
    mountPath: /var/cache/forge
```

## Backup and restore

PostgreSQL and the object store are **one** backup unit. Metadata references
blobs by content hash, so the restored bucket must still contain every object
the restored database references.

The safe order is: take the database snapshot **first**, and make sure no
object that existed at that moment can be missing from the bucket copy.
Garbage collection deletes objects after packages are deleted or retained
away, so a bucket copied *later* could already lack them. Either:

- enable **bucket versioning** (or an equivalent point-in-time feature) and
  restore the bucket to a point **at the database snapshot's time, and no
  later than the snapshot time plus `outbox.grace_seconds`** (default 3600 s;
  garbage collection deletes an object only after that grace period, so a
  later bucket state can already lack objects the restored database still
  references). Keep noncurrent versions longer than your backup retention; or
- stop **every** Forge instance while both copies are taken (garbage
  collection runs on every instance and has no separate switch;
  switching retention runs off in Admin → Retention does not stop it).

Objects written after the database snapshot are harmless: nothing in the
restored database references them. They only use storage.

Keep the secret-encryption root key with the backup set, stored separately
from it.

### S3 bucket lifecycle

Large pushes and proxied downloads are uploaded with S3 multipart uploads. An
upload that is interrupted (client disconnect, process restart) leaves its
parts in the bucket, invisible but billed. Add a lifecycle rule that aborts
incomplete multipart uploads, for example after one day:

```json
{
  "Rules": [{
    "ID": "abort-incomplete-multipart-uploads",
    "Status": "Enabled",
    "Filter": {},
    "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 1 }
  }]
}
```

(`aws s3api put-bucket-lifecycle-configuration --bucket forge
--lifecycle-configuration file://lifecycle.json`; MinIO and Ceph RGW accept
the same rule.) Do not add expiration rules for current objects: Forge's own
garbage collection decides when a blob may go.

To restore: stop every Forge instance, restore PostgreSQL, restore the bucket
as described above, then start Forge. Practise this before you need it.

## Locked out of every realm (break-glass)

The admin API and the web UI refuse (`409 Conflict`) to disable or delete a
realm when no enabled realm people can sign in with interactively (`local` or
OIDC) would remain. They cannot tell whether that realm works, though: with an
enabled OIDC realm whose IdP is down or misconfigured, `local` can still be
disabled, and then nobody can sign in. API tokens keep working, so restores
and pushes continue. To turn the `local` realm back on:

- **With an admin-scoped API token**, minted beforehand with
  `{"scope": {"admin": true}}` (keep one for this): look up the
  realm's id, then enable it. The token can also go in the Basic password.

  ```bash
  curl -H "X-NuGet-ApiKey: $TOKEN" https://nuget.example.com/admin/realms
  curl -H "X-NuGet-ApiKey: $TOKEN" -X PATCH https://nuget.example.com/admin/realms/<id> \
    -H 'content-type: application/json' -d '{"enabled": true}'
  ```

- **With SQL**, when there is no such token:

  ```sql
  UPDATE auth_realm SET enabled = true WHERE kind = 'local';
  ```

  Every instance picks the change up within `auth.realm_cache_ttl_seconds`
  (default 10 s); no restart is needed.

Then sign in as a local administrator and fix or disable the broken realm.

## Upgrades

- 2.0.0 does not upgrade a 1.x install: it is installed fresh, with an empty
  database, as the 2.0.0 upgrade notes say. Upgrades are from 2.0.0 on.
- Read the [changelog](../CHANGELOG.md) for each version you skip over. A
  release that needs something other than a rolling restart says so there.
- Migrations run automatically on the first start of a new version and only
  move forward. Rolling back to an older binary after a newer one has migrated
  the database requires restoring the backup taken before the upgrade.
- Back up (see above) before every upgrade.

## Known limitations

See the "Known limitations" section of the [changelog](../CHANGELOG.md#known-limitations).
