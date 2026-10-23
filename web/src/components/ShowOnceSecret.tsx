import { SecretOnce } from '~/components/ui'

/**
 * Renders a freshly-issued secret (a token plaintext) **once**, with a copy
 * affordance and a prominent warning that it cannot be retrieved again. This
 * mirrors the backend behavior: `POST /admin/users/{id}/tokens` returns
 * the plaintext exactly once (`CreatedToken.token`); the value is never written
 * into a query cache nor re-fetched, so the caller holds it in transient state
 * and renders it here until the user dismisses it.
 */
export function ShowOnceSecret({
  secret,
  label = 'Secret',
  onDismiss,
}: {
  secret: string
  label?: string
  onDismiss?: () => void
}) {
  return <SecretOnce value={secret} label={label} onDismiss={onDismiss} />
}
