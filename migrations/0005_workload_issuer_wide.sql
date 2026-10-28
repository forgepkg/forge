-- ---------------------------------------------------------------------------
-- An exchanged workload key remembers an issuer-wide match (#626)
--
-- A `workload_identity` realm rule may trust every workload of a self-managed
-- issuer (`issuer_wide`). Such a workload holds its role's grants capped at
-- `read`, and so must the key the token exchange issues for it: the key
-- authorizes as the principal captured at exchange time, and the cap is part
-- of that principal. Keys issued before this column existed matched a rule
-- pinned to a workload identity, which is what the default says.
-- ---------------------------------------------------------------------------
ALTER TABLE workload_api_key
    ADD COLUMN issuer_wide boolean NOT NULL DEFAULT false;
