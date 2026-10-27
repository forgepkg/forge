-- ---------------------------------------------------------------------------
-- An account of a trusted-header realm never holds `admin` (#547)
--
-- The headers of a trusted-header realm never make anyone an administrator:
-- the admin API refuses a request they authenticate, and such an account has
-- no password or identity link to sign in to otherwise. Holding the built-in
-- `admin` role it would still count as an administrator, so the last real
-- one could be deactivated or deleted, leaving nobody who can administer.
-- Like a service account (0003), it never holds the role.
-- ---------------------------------------------------------------------------
CREATE FUNCTION user_role_trusted_header_admin_check() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM app_user u, role r
        WHERE u.id = NEW.user_id AND u.auth_source = 'trusted-header'
          AND r.id = NEW.role_id AND r.name = 'admin'
    ) THEN
        RAISE EXCEPTION 'account % of a trusted-header realm cannot hold the admin role', NEW.user_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER user_role_trusted_header_admin_check
    BEFORE INSERT OR UPDATE ON user_role
    FOR EACH ROW EXECUTE FUNCTION user_role_trusted_header_admin_check();
