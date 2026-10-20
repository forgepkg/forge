# CLA signatures

This branch stores the Contributor License Agreement signatures that the `CLA`
workflow (`.github/workflows/cla.yml` on `main`) records. `version1/` holds the
signatures for version 1 of [CLA.md](https://github.com/schmitch/forge/blob/main/CLA.md).

The workflow commits to this branch with the repository's `GITHUB_TOKEN`, so:

- do not protect this branch, or signing fails;
- do not delete it or merge it into `main`;
- do not edit `cla.json` by hand.
