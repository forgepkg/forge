import type { AccessLevel } from '~/api/rbac'
import { Badge } from '~/components/catalyst/badge'

const ACCESS_COLORS: Record<AccessLevel, 'red' | 'sky' | 'zinc'> = {
  admin: 'red',
  writer: 'sky',
  reader: 'zinc',
}

/** A user's built-in access level (`accessLevel` in `~/api/rbac`). */
export function AccessBadge({ level }: { level: AccessLevel }) {
  return <Badge color={ACCESS_COLORS[level]}>{level}</Badge>
}
