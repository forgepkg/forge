# Retention size budgets

Hosted and proxy package repositories, raw file repositories, and Docker
repositories can set a logical size budget in their retention policy. Configure
it through the repository's **Retention** screen or
`PUT /admin/repositories/<name>/retention`; it is stored with the policy, not
in `forge.toml`. Group repositories do not have their own retention policy.

Add `size_budget` to the policy envelope:

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
- Raw files: ordered by last download, or deployment time if never downloaded.
- Docker: untagged manifests are considered before tags; manifests are ordered
  by last pull, or push time if never pulled. The last tag of an image is
  retained. Freed size counts only blobs no remaining manifest in the
  repository links.

The protections of ordinary rules also apply to budget eviction, including
keep-N rules, protected tags, and Docker index children and referrers. If
protected content alone is larger than the target, eligible content is still
removed and the run reports that it could not reach the target.

Retention preview reports budget decisions with reason `size_budget` and
includes the size before and projected size after. The retention API reports
the repository's current logical size, and the run summary records the
before/after sizes, target, and whether it was reached. The **Retention**
screen displays the current size against the configured maximum and warns when
a run could not reach its target.
