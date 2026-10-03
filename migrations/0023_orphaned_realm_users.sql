-- ---------------------------------------------------------------------------
-- 0023: users of a deleted realm are orphans, not wildcards (security review)
-- ---------------------------------------------------------------------------
--
-- Deleting a credential-forwarding realm set its users' `realm_id` to NULL,
-- and upstream provisioning treated a NULL realm as "any realm": the next
-- realm whose directory knew the same username adopted the account, with its
-- roles and tokens. A NULL realm is no longer a wildcard anywhere. Instead an
-- account is flagged `realm_orphaned` when its realm is deleted, and an
-- orphaned upstream account is never matched by any realm again: an
-- administrator deletes it (the next upstream login then provisions a fresh
-- account) or keeps it for its tokens.
ALTER TABLE app_user
    ADD COLUMN realm_orphaned boolean NOT NULL DEFAULT false;

CREATE FUNCTION app_user_orphan_on_realm_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE app_user SET realm_orphaned = true, updated_at = now()
    WHERE realm_id = OLD.id;
    RETURN OLD;
END
$$;

CREATE TRIGGER app_user_orphan_on_realm_delete
    BEFORE DELETE ON auth_realm
    FOR EACH ROW EXECUTE FUNCTION app_user_orphan_on_realm_delete();

-- Existing credential-forwarding accounts without a realm are either orphans
-- of a realm deleted earlier or were provisioned before realms existed; the
-- two cannot be told apart, so neither may be adopted by a realm any more.
UPDATE app_user
SET realm_orphaned = true
WHERE auth_source = 'upstream-basic'
  AND realm_id IS NULL;
