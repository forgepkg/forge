# Package delay

A proxy repository can hold new upstream releases back for a while before
it serves them: a dependency cooldown. A release that turns out to be
compromised is usually found and pulled within hours or days, so a build
that only takes versions older than that does not install it. The delay is
a proxy's setting, for NuGet and npm proxies; docker, raw and apt proxies
have none.

- [The delay](#the-delay)
- [Overrides: other delays for some packages](#overrides-other-delays-for-some-packages)
- [Releasing one version early](#releasing-one-version-early)
- [Groups](#groups)

## The delay

`package_delay_seconds` on the proxy (Repositories → the proxy → **Package
delay**) is how long a new version is held back: up to a year, `0` for none.
It counts from when the upstream published the version, where the upstream
says so (NuGet's registration, npm's packument), otherwise from when Forge
first saw it. A version published long ago is therefore served at its first
request; only new releases wait.

While a version is held back, the proxy behaves as if it did not exist yet:
it is left out of the version listings, the registration and search, and a
download answers 404. Nothing is fetched from the upstream for it, and the
404 is not remembered as a "not found" answer. In the web UI, the package's
page lists it with a **delayed** badge and when it becomes available.

```bash
curl -u admin@example.com:<admin-token> -X POST -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories -d '{
    "name": "nuget-org", "kind": "proxy",
    "remote_url": "https://api.nuget.org/v3/index.json",
    "package_delay_seconds": 172800
  }'
```

## Overrides: other delays for some packages

Some packages should not wait, or should wait longer: your own packages on a
private upstream, vendors you trust (`Microsoft.*`, `System.*`), or a package
you watch more closely. `package_delay_overrides` is an ordered list of
other delays on the proxy. The first entry that matches a package decides
its delay; a package no entry matches keeps `package_delay_seconds`.

```json
"package_delay_overrides": [
  { "selector": "trusted-vendors", "delay_seconds": 0 },
  { "pattern": "Envisia.*",        "delay_seconds": 0 },
  { "pattern": "some.risky.pkg",   "delay_seconds": 1209600 }
]
```

Each entry matches the package id, case-insensitively, by exactly one of:

- `selector`: a content selector's name (**Admin → Content selectors**), with
  its include and exclude globs, as RBAC uses them. One selector can serve
  several proxies, and editing it changes the packages every one of them
  exempts. A selector an override names cannot be deleted (409) until no
  override names it.
- `pattern`: a glob of its own, in the same syntax (`Microsoft.*`,
  `@acme/*`).

`delay_seconds` is the delay of the packages the entry matches, from `0`
(none) to a year. A value above the default holds them back longer.

In the web UI the overrides are edited under the proxy's **Package delay**,
one row per entry, in order. The admin API takes the whole list on create
and update (`PUT /admin/repositories/{name}`, `[]` clears it) and refuses an
unknown selector, a glob that does not compile, an entry with both or
neither of `selector` and `pattern`, and a delay below 0 or above a year.

A change takes effect at once, on every instance, without waiting for the
metadata TTL: editing the overrides, or a content selector they name,
touches the repository, which makes the proxy read its upstream's listings
again. A version that a new override exempts is served at its next
request, and one an override now holds back longer disappears from the
listings until its delay is over.

The package's page shows the delay that applies to it and what decides it
(the default, or the override), and the badge of a version an override
exempts says so: "no delay: trusted-vendors".

## Releasing one version early

A security fix released today should be installable today, without turning
the delay off for the whole proxy. An administrator releases that one
version from the delay: it is served at once, while the package's other
versions keep their delay.

- In the web UI: **Release now** next to the delayed version on the
  package's page, or **Released early** on the proxy's page, by package id
  and version.
- Through the admin API, with a reason, which is required:

  ```bash
  curl -u admin@example.com:<admin-token> -X POST -H 'content-type: application/json' \
    https://forge.example.com/admin/repositories/nuget-org/packages/Newtonsoft.Json/versions/13.0.4/release-delay \
    -d '{"reason": "CVE-2026-1234: the fix must ship today"}'
  ```

The release keeps the reason, the administrator and the time, and is
written to the audit log (`forge::audit`). Releasing a released version
again keeps the first release (200 instead of 201).

A version the proxy has not seen yet, because the upstream has not
published it so far, can be released by name too: it is served as soon as
the upstream lists it. The release answers `"seen": false` until then.

`GET /admin/repositories/{name}/delay-releases` lists a proxy's releases,
and `DELETE` on the release's path withdraws one: the version waits out its
delay again. Repointing the proxy to another upstream (`remote_url`)
forgets its releases, which were decisions about the previous upstream's
packages.

## Groups

A group serves what its members serve: a version a delayed proxy member
holds back is not served through the group either, unless another member
has it. A group in front of a delayed and an undelayed proxy of the same
upstream therefore serves every version undelayed. Use overrides on one
proxy instead of a second proxy without a delay.
