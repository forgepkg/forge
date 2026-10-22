# Changelog fragments

A change does not edit [CHANGELOG.md](../../CHANGELOG.md). It adds its entry
here, as a file of its own:

```
docs/changes/<milestone>/<ref>.<kind>.md
```

The release folds the fragments into the changelog. Changes merged side by
side therefore never conflict over the changelog. An entry also never lands
under a release it is not part of, because a fragment has no section until a
release takes it in.

- **`<milestone>`** is the version the change is planned for, named like the
  issue's GitHub milestone (`1.2.0`). An issue without a milestone takes the
  next release's.
- **`<ref>`** is the number of the issue the change fixes (`205`). The entry
  links it, and a pull request's number works too. When an issue has two
  entries of one kind, add a short name (`205-registry-tokens`). A change
  without an issue takes a short name of lowercase letters, digits and `-`
  (`oidc-docs`), and its entry has no link.
- **`<kind>`** is the section the entry goes under:

  | `<kind>` | Section |
  | --- | --- |
  | `upgrade` | Upgrade notes |
  | `feature` | Features |
  | `fixed` | Fixed |
  | `security` | Security |
  | `docs` | Documentation |
  | `limitation` | Known limitations |

The file holds the entry's text alone, written for the people who run Forge:
no `- `, no heading and no link, since the fold adds them. For example,
`docs/changes/1.2.0/205.fixed.md`:

```markdown
A database failure while checking a browser session or its CSRF token
answered 500; it answers 503 with `Retry-After`, like the token and
password checks, which now send `Retry-After` too.
```

becomes, under `### Fixed`:

```markdown
- A database failure while checking a browser session or its CSRF token
  answered 500; it answers 503 with `Retry-After`, like the token and
  password checks, which now send `Retry-After` too.
  ([#205](https://github.com/schmitch/forge/issues/205))
```

A change that also needs an upgrade note writes a second fragment,
`205.upgrade.md`.

## Folding

- **`cargo xtask release <version>`** folds `docs/changes/<version>/` into the
  version's section and deletes the directory in the release commit. Each
  entry goes under its kind's heading, after the entries already under
  `[Unreleased]`, ordered by issue number. The release is refused while
  another milestone has fragments: their changes are on `main` and ship in
  this release, so move them to `docs/changes/<version>/` first.
- **`cargo xtask changelog <milestone>`** does the same fold into
  `[Unreleased]` ahead of the release. Commit the result in a pull request of
  its own, to edit the notes and write the release's introduction. Fragments
  merged after that pull request are folded by the release.
- **`cargo xtask changelog --check`** runs in CI. It refuses a file here that
  is not a fragment, and a fragment whose milestone is released already (not
  newer than the workspace version in `Cargo.toml`). If a pull request was
  written before a release and merged after it, move its fragment to the next
  milestone: `git mv docs/changes/1.2.0/205.fixed.md docs/changes/1.3.0/`.
- **The release workflow** refuses a tag whose tree still has fragments,
  because their entries would be missing from the release notes.
