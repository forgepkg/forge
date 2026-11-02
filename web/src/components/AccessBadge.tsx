import type { AccessLevel } from '~/api/rbac'
import { StatusBadge, type Tone } from '~/components/ui'

const ACCESS_TONES: Record<AccessLevel, Tone> = {
  admin: 'heat',
  writer: 'neutral',
  reader: 'neutral',
  roles_only: 'neutral',
}

const ACCESS_LABELS: Record<AccessLevel, string> = {
  admin: 'admin',
  writer: 'writer',
  reader: 'reader',
  roles_only: 'roles only',
}

/** A user's built-in access level (`accessLevel` in `~/api/rbac`). */
export function AccessBadge({ level }: { level: AccessLevel }) {
  return (
    <StatusBadge tone={ACCESS_TONES[level]} dot={level !== 'admin'}>
      {ACCESS_LABELS[level]}
    </StatusBadge>
  )
}
