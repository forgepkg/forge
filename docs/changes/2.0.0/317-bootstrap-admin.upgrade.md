`auth.bootstrap_admin.username` (`FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME`)
defaults to `admin@example.com`, which the `admin` of an install from before
2.0 is renamed to, together with its "created once" marker: a bootstrap admin
deleted before the upgrade stays deleted. Startup refuses a configured name
that is no UPN; name the account's new one. The shipped configs, the Helm
chart's examples and the kustomize env files name `admin@example.com`, and
`cargo xtask dev` signs in as `admin@example.com` / `changeme`.
