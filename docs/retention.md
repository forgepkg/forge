# Retention

Retention removes what a repository no longer needs: old and unused
versions of packages, prereleases a release superseded, versions unlisted
long ago, cold proxy caches, stale image tags and files, and whatever a
size budget evicts. Each hosted or proxy repository can have one retention
policy; group repositories hold nothing of their own and take none.

A policy is set on the repository's **Retention** screen in the web UI
(Repositories → the repository → Retention), or through the admin API:

```bash
curl -u admin@example.com:<admin-token> -X PUT -H 'content-type: application/json' \
  https://forge.example.com/admin/repositories/nuget-ci/retention -d '{"policy": {…}}'
```

It is stored in the database with the repository, never in `forge.toml`.
**Admin → Retention** switches runs on or off for every repository and sets
how long the audit log is kept; `[retention]` in `forge.toml` only tunes the
worker (how often an instance looks for a due repository, 30 seconds by
default).

## Contents

- [The policy](#the-policy)
- [When a policy runs](#when-a-policy-runs)
- [Package rules](#package-rules)
  - [Filters](#filters)
  - [Protections](#protections)
  - [Triggers](#triggers)
  - [Examples](#examples)
- [Proxy rules](#proxy-rules)
- [Formats: what "newest" and "prerelease" mean](#formats-what-newest-and-prerelease-mean)
- [Raw file rules](#raw-file-rules)
- [Image rules](#image-rules)
- [Preview, runs and the audit log](#preview-runs-and-the-audit-log)
- [Size budgets](#size-budgets)

## The policy

Every policy has the same envelope, with rules of the repository's kind:
package rules for NuGet, npm and the other package formats, file rules for
raw repositories, image rules for Docker repositories (Helm charts
included).

```json
{
  "version": 1,
  "enabled": true,
  "dry_run_only": false,
  "schedule": "0 3 * * *",
  "schedule_timezone": "Europe/Berlin",
  "max_run_seconds": 3600,
  "rules": [ … ]
}
```

| Field | |
| --- | --- |
| `version` | Always `1`. |
| `enabled` | Default `true`. A disabled policy is stored and never runs. |
| `dry_run_only` | Default `false`. Runs record in the audit log what they would remove, and remove nothing. |
| `min_run_interval_seconds` | Default 3600: the policy runs at most this often. Ignored when `schedule` is set. |
| `schedule` | A cron pattern of 5 fields: the policy runs at its times instead ([When a policy runs](#when-a-policy-runs)). |
| `schedule_timezone` | The IANA time zone of `schedule`'s times (`Europe/Berlin`, `America/New_York`); UTC without one. Only with a `schedule`. |
| `max_run_seconds` | How long a run may take, from 60 seconds to a week; without it a run takes as long as it needs. |
| `size_budget` | A logical size limit ([Size budgets](#size-budgets)). |
| `rules` | The rules. May be empty when a size budget is set. |

Unknown fields are refused (422), so a misspelled one is never dropped
silently, and an invalid value is a 400 that names its rule and field.

## When a policy runs

The retention worker runs on every instance; each repository is evaluated by
one instance at a time.

- **At an interval** (`min_run_interval_seconds`, the default): a run at most
  every hour, or whatever the policy says.
- **On a schedule** (`schedule`): at the times of a 5-field cron pattern,
  `minute hour day-of-month month day-of-week`, in `schedule_timezone`:

  | `schedule` | Runs |
  | --- | --- |
  | `0 3 * * *` | at 03:00 every day |
  | `30 1 * * 6` | at 01:30 on Saturdays |
  | `0 22 * * 1-5` | at 22:00 Monday to Friday |
  | `0 */6 * * *` | every six hours, on the hour |
  | `@daily`, `@weekly` | at midnight every day, every Sunday |

  Lists (`1,15`), ranges (`1-5`), steps (`*/15`, `0-30/10`) and names
  (`MON-FRI`, `JAN`) work as in Vixie cron. The times keep their local time
  across daylight-saving changes: `0 3 * * *` in `Europe/Berlin` runs at
  03:00 Berlin time all year, which is 02:00 UTC in winter and 01:00 UTC in
  summer. A time that falls into the hour the clocks skip (`30 2 * * *` on
  the last Sunday of March in Berlin) runs once, right after the change, at
  03:00; a time in the hour they repeat (`30 2 * * *` on the last Sunday of
  October) runs once, at its first occurrence.

  A policy saved with a schedule waits for its next time: it does not run
  as soon as it is saved. The worker never starts a run less than a minute
  after the previous one started. A time missed while no worker ran (every
  instance down, or runs switched off in **Admin → Retention**) is made up
  once, as soon as the worker runs again; set `max_run_seconds` to keep such
  a run short.
- **Run now** (`POST /admin/repositories/<name>/retention/run`) runs the
  stored policy at the worker's next poll, whatever its schedule or interval
  says. The run after it is at the schedule's next time again.

The **Retention** screen shows the schedule and the next run, and a preview
of a draft with a schedule lists its next five run times.

**`max_run_seconds`** ends a run at the end of a maintenance window. The
run applies its decisions in batches (up to 100 versions of one package, or
files of one directory, or tags and manifests of one image); once the time
is up, it stops before the next batch. The run summary counts what it left
as `deferred`. The next run evaluates the repository again and goes on with
what is left, so a cleanup larger than one window spreads over several runs.
The first batch of a run always goes, so a run makes progress even when
evaluating the repository alone takes longer than the window.

## Package rules

A package rule selects versions and unlists or deletes them:

```json
{
  "id": "ci-prereleases",
  "action": "hard_delete",
  "release_type": "prereleases",
  "package_name_prefix": "acme.",
  "selector": "ci-feeds",
  "version_pattern": "*-ci.*",
  "exclude_version_pattern": "*-ci.0",
  "criteria": {
    "keep_last_n": 3,
    "prerelease_superseded_for_days": 14
  }
}
```

| Field | |
| --- | --- |
| `id` | Recorded on every audit row the rule produces; unique in the policy. `size_budget` is reserved. |
| `action` | `unlist` (the version stays downloadable by its exact version) or `hard_delete` (the version and its files are gone). |
| `scope` | `hosted` (the default) on hosted repositories, `proxy_cached` on proxies ([Proxy rules](#proxy-rules)). |
| `release_type`, `package_name_prefix`, `selector`, `version_pattern`, `exclude_version_pattern` | [Filters](#filters): the versions the rule looks at. |
| `criteria` | [Protections](#protections) and [triggers](#triggers). |

How rules combine:

- A version goes when **any** rule selects it. A rule selects a version
  when its filters admit it and **every** trigger it sets holds.
- What **any** rule protects is never unlisted or deleted, by any rule and
  whatever trigger selects it.
- When two rules select a version, deleting wins over unlisting.
- A version a package tag names (npm's `latest`, `next`, …) is never
  touched.
- Unlisting a version that is unlisted already does nothing, and is not
  audited again.

### Filters

All optional; a rule without filters looks at every version.

| Filter | Admits |
| --- | --- |
| `release_type` | `any` (default), `releases`, `prereleases` or `snapshots`: the class the repository's format gives the version ([Formats](#formats-what-newest-and-prerelease-mean)). For NuGet and npm a prerelease has a label after a dash (`2.0.0-beta.1`). |
| `package_name_prefix` | Packages whose id starts with it, ignoring case (`acme.`). |
| `selector` | Packages a [content selector](deployment.md#access-levels) (**Admin → Content selectors**) admits, by its name: its include and exclude globs on the package id, as a grant scoped by it reads them. The selector must exist when the policy is saved; one that is deleted since fails the policy's runs (nothing is removed), and a selector a policy names cannot be deleted until no rule names it. |
| `version_pattern` | Versions this glob matches, ignoring case: `*` any characters, `?` one, `[0-9]` a set, `{*-ci.*,*-pr.*}` either. The glob covers the whole normalized version. |
| `exclude_version_pattern` | Never the versions this glob matches. |

### Protections

| Protection | Keeps |
| --- | --- |
| `keep_last_n` | The newest N **listed** versions of each package, among the versions the rule's filters admit. Unlisted versions neither count nor are kept by it, so after a broken release is unlisted, the N newest installable versions are still kept. |
| `keep_n_most_downloaded` | The N versions of each package downloaded last, listed or not; never-downloaded versions rank last, newest first. |

A protection counts within the rule's own filters: a `releases` rule with
`keep_last_n: 3` keeps the three newest releases, never prereleases. A rule
needs a trigger; a rule with protections only is refused.

### Triggers

| Trigger | Selects a version |
| --- | --- |
| `older_than_days` | published at least N days ago. |
| `not_downloaded_for_days` | not downloaded for N days; a version never downloaded counts from its publication. |
| `prerelease_superseded_for_days` | that is a prerelease (or a snapshot) once its package has had, for N days, a **listed release that comes after it**: for SemVer, a release of the same or a higher version, so `2.3.0-ci.417` goes 14 days after `2.3.0` (or `2.4.0`) was published. The clock starts at the first such release's publication. A release is never selected. |
| `unlisted_for_days` | that has been unlisted for N days (a listed version never). Only on `hard_delete` rules: the second step of "unlist, then delete later". |
| `max_versions_per_package` | that is not among the N newest versions of its package (listed or not) the rule's filters admit. A pure count: no age needed. |

Every count and day value is at least 1. The audit log and the preview give
each decision its reason: the triggers that held, the release that
superseded a prerelease (`superseded_by`), and a version's place past the
cap (`rank`).

**When a version was unlisted.** Every version records it
(`component.unlisted_at`), whichever way it was unlisted: by a client
(NuGet's delete, npm), by a retention rule, pushed or imported unlisted.
Listing it again clears it. Versions unlisted before Forge recorded it take
the time of their last change, which is never earlier than their unlisting.

### Examples

CI prereleases go 14 days after their release, and no package keeps more
than 50 prereleases at all:

```json
{
  "version": 1,
  "schedule": "0 2 * * *",
  "schedule_timezone": "Europe/Berlin",
  "rules": [
    { "id": "superseded", "action": "hard_delete", "release_type": "prereleases",
      "criteria": { "prerelease_superseded_for_days": 14 } },
    { "id": "too-many", "action": "hard_delete", "release_type": "prereleases",
      "criteria": { "max_versions_per_package": 50 } }
  ]
}
```

Pull-request builds go after 7 days, except the newest of each package:

```json
{ "id": "pr-builds", "action": "hard_delete", "version_pattern": "*-pr.*",
  "criteria": { "older_than_days": 7, "keep_last_n": 1 } }
```

Unlist, then delete later: releases unused for a year are unlisted, and
deleted 90 days after that, unless someone relisted them meanwhile; the
three newest releases of each package stay:

```json
{
  "version": 1,
  "rules": [
    { "id": "unlist-cold", "action": "unlist", "release_type": "releases",
      "criteria": { "not_downloaded_for_days": 365, "keep_last_n": 3 } },
    { "id": "delete-unlisted", "action": "hard_delete",
      "criteria": { "unlisted_for_days": 90 } }
  ]
}
```

Only the packages of the `ci-feeds` content selector, outside working hours,
an hour at most per night:

```json
{
  "version": 1,
  "schedule": "0 1 * * 1-5",
  "schedule_timezone": "America/New_York",
  "max_run_seconds": 3600,
  "rules": [
    { "id": "ci", "action": "hard_delete", "selector": "ci-feeds",
      "criteria": { "older_than_days": 30, "keep_last_n": 10 } }
  ]
}
```

## Proxy rules

A proxy repository's rules say `"scope": "proxy_cached"` and evict cached
versions: their bytes are deleted, the version stays listed, and its next
pull fetches it from the upstream again. Proxy versions are never unlisted.

| Trigger | Evicts a cached version |
| --- | --- |
| `not_pulled_for_days` | not pulled for N days; one never pulled counts from when the proxy first saw it. |
| `max_versions_per_package` | not among the N newest cached versions of its package the rule's filters admit, however recently pulled. |

The filters and protections work as on hosted rules, over each package's
cached versions: `keep_last_n` keeps the newest N cached versions the
upstream lists, `keep_n_most_downloaded` the N pulled last. The hosted
triggers (`older_than_days`, `not_downloaded_for_days`,
`prerelease_superseded_for_days`, `unlisted_for_days`) are refused here.

```json
{ "id": "evict-cold", "action": "hard_delete", "scope": "proxy_cached",
  "criteria": { "not_pulled_for_days": 30, "keep_last_n": 5, "keep_n_most_downloaded": 5 } }
```

keeps the 5 newest and the 5 most recently pulled cached versions of each
package and evicts any other one nobody pulled for 30 days.

## Formats: what "newest" and "prerelease" mean

Versions are ordered by the repository's format, never as text: NuGet orders
`1.10.0` after `1.9.0` and a prerelease before its release. Two retention
hooks of the format contract
([format plugins](format-plugins.md#retention)) say the rest:

- **The version class**: release, prerelease or snapshot. `release_type`
  filters on it, and `prerelease_superseded_for_days` deletes what is not a
  release.
- **The partition** keep-N counts within (`keep_last_n`,
  `keep_n_most_downloaded`, `max_versions_per_package`): the whole package
  unless the format splits it.

NuGet and npm use the generic rules: a version with a `-` is a prerelease,
any other a release, and a package is one partition. Helm charts are stored
in Docker repositories and follow the [image rules](#image-rules). apt
([apt.md](apt.md)) has no prereleases (a `-` starts the Debian revision, so
every version is a release), orders versions as dpkg does, and counts per
package and architecture: its package ids are `<name>:<architecture>`.
Maven brings its own rules when it arrives: its `-SNAPSHOT` builds are
snapshots counted per snapshot version (the newest N builds of each), its
releases per `groupId:artifactId`, and `prerelease_superseded_for_days`
removes a version's snapshots once its release exists.

## Raw file rules

Raw repositories have file rules: `path_prefix` (only files under it),
`keep_newest_per_directory` (the N most recently deployed files of each
directory stay), and the triggers `older_than_days` and
`not_downloaded_for_days`. See [Raw file repositories](raw.md#retention).

```json
{ "id": "nightlies", "path_prefix": "nightly/", "keep_newest_per_directory": 5,
  "older_than_days": 14 }
```

## Image rules

Docker repositories have image rules: per image (`image_prefix`), tag rules
with `keep_last_n_tags`, `protected_tags`, `tag_older_than_days` and
`tag_not_pulled_for_days`, and `delete_untagged_after_days` for manifests
left without a tag. A tag rule looks at the tags `tag_pattern` matches and
`exclude_tag_pattern` does not (all tags without either); `protected_tags`
takes names and globs. See [Docker / OCI registry](docker.md#retention-and-garbage-collection).

```json
{ "id": "pr-tags", "tag_pattern": "pr-*", "tag_older_than_days": 7,
  "protected_tags": ["latest", "release-*"] }
```

deletes `pr-*` tags a week after their push, whatever else the image has.

## Preview, runs and the audit log

- `POST /admin/repositories/<name>/retention/preview` evaluates the stored
  policy, or a draft sent as `{"policy": {…}}` (checked like a `PUT` of it,
  never stored, evaluated even when disabled), and lists what a run would do
  now, with the rule and the reason of each decision. It changes nothing.
  A draft with a schedule also lists its next runs (`next_runs`).
- A run re-checks each batch before it applies it: it stops when the policy
  changed or it lost its lease (the next run goes on under the policy as it
  is then), and skips what the repository's current state no longer
  warrants (a version downloaded, relisted or protected since).
- `GET /admin/repositories/<name>/retention` returns the policy and the run
  state: the next run, the last run's times, error and summary (`evaluated`,
  `unlisted`, `deleted`, `skipped`, `deferred`, the blobs queued for
  deletion, and a size budget's sizes).
- `GET …/retention/audit` lists every decision of every run, dry runs
  included, newest first, filtered by `run_id` and paged with `before`.

Deleted content goes through the blob outbox: a blob is deleted from the
object store only once nothing references it any more.

## Size budgets

Hosted and proxy package repositories, raw file repositories, and Docker
repositories can set a logical size budget in their retention policy. Add
`size_budget` to the policy envelope:

```json
{
  "version": 1,
  "size_budget": {
    "max_bytes": 536870912000,
    "target_bytes": 483183820800
  },
  "rules": []
}
```

`max_bytes` must be greater than zero. If `target_bytes` is omitted, it
defaults to 90% of `max_bytes`; it cannot be greater than `max_bytes`. The
budget may be the policy's only content, so `rules` can be empty when a budget
is set. Without a budget, at least one rule is required. `enabled` and
`dry_run_only` apply to the budget as they do to retention rules.

The budget measures **logical repository size**, not physical object-store
usage: package and raw-file size is the sum of their asset/file sizes. Docker
size is the sum of distinct blobs linked by the repository's manifests. A blob
shared between repositories counts toward each repository's logical size;
evicting it from one repository may not free physical storage while another
repository still references it.

Rules are applied first. If content still exceeds `max_bytes`, the budget
evicts unprotected content in least-recently-used order until it reaches
`target_bytes` or has no eligible content left:

- Packages: versions are ordered by last download, or publication/first-seen
  time if never downloaded. Hosted repositories retain each package's newest
  listed version; proxy versions are evicted from the cache and can be fetched
  again.
- Raw files: ordered by the later of their last download and their
  deployment, so a file deployed again counts as used then.
- Docker: untagged manifests go first, ordered by last pull, or push time if
  never pulled. Then tagged manifests, ordered by the later of their last pull
  and their newest tag's push (as `tag_not_pulled_for_days` judges a tag): the
  budget deletes all of a manifest's tags together, and the manifest with
  them. It never deletes a tag whose manifest would stay, since that frees
  nothing: not an alias of a manifest a protected tag also names, and not the
  tags of a manifest that holds its image's last tags. An image always keeps
  a tag. Freed size counts only blobs no remaining manifest in the repository
  links.

The protections of ordinary rules also apply to budget eviction, including
keep-N rules, protected tags, and Docker index children and referrers. If
protected content alone is larger than the target, eligible content is still
removed and the run reports that it could not reach the target.

Retention preview reports budget decisions with reason `size_budget` and
includes the size before and projected size after. The retention API reports
the repository's current logical size, and the run summary records the
before/after sizes, target, and whether it was reached. The **Retention**
screen edits the maximum and the target in GB or GiB, displays the current size
against the configured maximum, and warns when the last run could not reach
its target.
