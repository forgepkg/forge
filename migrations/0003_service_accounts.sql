-- ---------------------------------------------------------------------------
-- Service accounts (#508)
--
-- An account stands for a person (`kind = 'user'`) or for a machine or a
-- network (`kind = 'service'`): a CI pipeline, a build agent, a network the
-- load balancer admits. Nobody signs in to a service account. It
-- authenticates with the API tokens an administrator issues for it, or
-- through the trusted-header realm it belongs to (`realm_id`), which alone
-- may name it. The kind is set when the account is created and never
-- changes; the accounts that exist are users.
--
-- A service account has no password, invitation or email, never holds the
-- built-in `admin` role, and is never linked to an identity provider's
-- identity. Its `auth_source` is `'service'`, so every sign-in path keyed on
-- the source passes it by: the local password realm, credential forwarding
-- and OIDC's link by username.
-- ---------------------------------------------------------------------------
ALTER TABLE app_user
    ADD COLUMN kind text NOT NULL DEFAULT 'user'
        CONSTRAINT app_user_kind_check CHECK (kind IN ('user', 'service')),
    -- What a service account is for and who owns it.
    ADD COLUMN description text;

ALTER TABLE app_user DROP CONSTRAINT app_user_auth_source_check;
ALTER TABLE app_user ADD CONSTRAINT app_user_auth_source_check
    CHECK (auth_source IN ('local', 'upstream-basic', 'oidc', 'trusted-header', 'service'));

-- A service account is exactly an account of the source 'service'.
ALTER TABLE app_user ADD CONSTRAINT app_user_service_auth_source_check
    CHECK ((kind = 'service') = (auth_source = 'service'));

-- Nobody signs in to a service account: no password, no invitation to
-- choose one, and no email to send one to.
ALTER TABLE app_user ADD CONSTRAINT app_user_service_account_check
    CHECK (kind <> 'service' OR (password_hash IS NULL AND NOT invited AND email IS NULL));

-- An account's kind never changes (and with it, by the CHECK above, whether
-- its source is 'service').
CREATE FUNCTION app_user_kind_unchanged() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind THEN
        RAISE EXCEPTION 'the kind of account % never changes', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER app_user_kind_unchanged
    BEFORE UPDATE OF kind ON app_user
    FOR EACH ROW EXECUTE FUNCTION app_user_kind_unchanged();

-- A service account belongs to a trusted-header realm, or to none.
CREATE FUNCTION app_user_service_realm_check() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM auth_realm WHERE id = NEW.realm_id AND kind = 'trusted_header'
    ) THEN
        RAISE EXCEPTION 'service account % may belong to a trusted-header realm only', NEW.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER app_user_service_realm_check
    BEFORE INSERT OR UPDATE OF realm_id ON app_user
    FOR EACH ROW
    WHEN (NEW.kind = 'service' AND NEW.realm_id IS NOT NULL)
    EXECUTE FUNCTION app_user_service_realm_check();

-- A service account never holds the built-in `admin` role: admin automation
-- uses an administrator's token with the `admin` scope.
CREATE FUNCTION user_role_service_admin_check() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM app_user u, role r
        WHERE u.id = NEW.user_id AND u.kind = 'service'
          AND r.id = NEW.role_id AND r.name = 'admin'
    ) THEN
        RAISE EXCEPTION 'service account % cannot hold the admin role', NEW.user_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER user_role_service_admin_check
    BEFORE INSERT OR UPDATE ON user_role
    FOR EACH ROW EXECUTE FUNCTION user_role_service_admin_check();

-- Nor is a service account ever linked to an identity provider's identity.
CREATE FUNCTION external_identity_service_account_check() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM app_user WHERE id = NEW.user_id AND kind = 'service') THEN
        RAISE EXCEPTION 'service account % is never linked to an identity', NEW.user_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER external_identity_service_account_check
    BEFORE INSERT OR UPDATE OF user_id ON external_identity
    FOR EACH ROW EXECUTE FUNCTION external_identity_service_account_check();
