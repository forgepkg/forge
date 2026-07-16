-- One enabled workload-identity realm owns one normalized issuer.
--
-- Realm routing is issuer-based and terminal after a match. Allowing two
-- enabled rows for the same issuer would make behavior priority-dependent and
-- leave the later policy unreachable. The admin API provides a friendly
-- pre-check; this index closes the concurrent-write and direct-SQL race.

CREATE UNIQUE INDEX auth_realm_enabled_wif_issuer_uq
    ON auth_realm ((rtrim(btrim(config ->> 'issuer'), '/')))
    WHERE kind = 'workload_identity' AND enabled;
