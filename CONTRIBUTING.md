# Contributing to Forge

Thank you for helping. This page covers what you need before a pull request
can be merged. To set up a development environment, run the stack and run the
tests, see [DEVELOPMENT.md](./DEVELOPMENT.md). To report a vulnerability, see
[SECURITY.md](./SECURITY.md); please do not open a public issue for it.

## Contributor License Agreement

Every contributor signs the [Contributor License Agreement](./CLA.md) (CLA)
once. Forge belongs to the forgepkg organization, and the CLA lets forgepkg
relicense contributions, for example to move the project to the MIT License,
without asking every contributor again.

The agreement grants forgepkg a broad, non-exclusive license to your
contributions, including the right to license them under other terms. You
keep the copyright, and you can still use your own code however you like.
Read [CLA.md](./CLA.md) for the full text.

### Signing

When you open your first pull request, the **CLA** check fails and a bot
comments with the agreement. To sign, post this exact comment on the pull
request:

```text
I have read the CLA Document and I hereby sign the CLA
```

The check then passes. You only sign once per GitHub account; later pull
requests pass without a comment. If the check does not update, comment
`recheck`.

### Every commit needs a signed GitHub account

The check looks at the **author of every commit** in the pull request, not
only at the person who opened it:

- **Link the commit email to your GitHub account.** A commit made with an
  email address that GitHub does not know cannot be signed for. Add the
  address to your account under *Settings → Emails*, or rewrite the commits
  with an address that is already there.
- **Co-authors need to sign too.** Everyone whose commits are in the pull
  request has to sign before it can be merged.
- **Commits by AI coding agents.** Some agents (for example, Claude Code on
  the web) author commits under their own GitHub identity, which cannot sign
  the CLA. You are responsible for that code as your contribution, so make
  yourself the author before you push:

  ```bash
  git rebase --exec 'git commit --amend --no-edit --reset-author' upstream/main
  git push --force-with-lease
  ```

  Replace `upstream/main` with the name your clone uses for this
  repository's `main` branch.

### Contributing on behalf of your employer

If your employer has rights to the code you write, make sure you are allowed
to contribute it under the CLA before you sign (see CLA.md, section 5). If
your employer wants a separate agreement with forgepkg, ask in an issue
before you open the pull request.
