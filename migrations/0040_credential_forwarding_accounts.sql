-- Credential forwarding creates no accounts any more (#317): an administrator
-- creates each account of a credential-forwarding realm, and a login signs in
-- only an existing one. The realm setting that turned provisioning on goes.
UPDATE auth_realm
SET config = config - 'auto_provision',
    updated_at = now()
WHERE kind = 'credential_forwarding'
  AND config ? 'auto_provision';
