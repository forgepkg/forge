`auth.bootstrap_admin.username` (`FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME`) no
longer defaults to `admin`. While the bootstrap admin still has to be
created, startup refuses a missing or non-UPN name; set a UPN such as
`admin@example.com`. An install whose bootstrap admin exists, or was created
and deleted since, starts as before without a change. The shipped configs,
the Helm chart's examples and the kustomize env files name
`admin@example.com`, and `cargo xtask dev` signs in as
`admin@example.com` / `changeme`.
