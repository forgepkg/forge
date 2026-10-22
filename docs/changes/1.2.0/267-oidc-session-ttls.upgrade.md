`oidc.session_idle_ttl_seconds` and `oidc.session_absolute_ttl_seconds` are
deprecated and will be removed in 2.0.0: set `auth.session_idle_ttl_seconds`
and `auth.session_absolute_ttl_seconds`, which apply to every browser
session, instead. While the `auth` keys are unset the `oidc` ones still stand
in for them; startup warns about either.
