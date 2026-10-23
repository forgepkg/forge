`auth.bootstrap_admin.username` (`FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME`)
defaults to `admin@example.com` instead of `admin`, and startup refuses a
configured name that is no UPN. The shipped configs, the Helm chart's
examples and the kustomize env files name `admin@example.com`, and `cargo
xtask dev` signs in as `admin@example.com` / `changeme`.
