**Breaking:** credential-forwarding realms create no accounts and forward the
local part of the account's UPN: `alice@example.com` signs in as the
upstream's `alice`. Create each account under **Admin → Users**, with the
realm as its sign-in (`POST /admin/users` with `"realm"` and no password); a
login the upstream accepts that names no account of the realm is refused.
Existing accounts keep signing in, renamed `<name>@example.com` (they forward
their old name); one already named by a UPN, such as `alice@corp.example`, now
forwards `alice`. The admin API refuses `auto_provision: true` on a
credential-forwarding realm, the setting is dropped from stored realms, and
the `[auth.upstream_basic]` block's `auto_provision` is ignored. New OIDC
accounts are no longer namespaced while a forwarding realm is enabled.
