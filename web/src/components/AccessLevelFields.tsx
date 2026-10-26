import type { AccessLevel } from '~/api/rbac'
import { RadioGroup } from '~/components/ui'

/** The access levels an admin chooses between, most limited first. */
export const ACCESS_LEVEL_OPTIONS: ReadonlyArray<{
  level: AccessLevel
  label: string
  description: string
}> = [
  {
    level: 'reader',
    label: 'Reader',
    description:
      'No built-in role: reads what the user’s other roles and anonymous access allow, and publishes nothing.',
  },
  {
    level: 'writer',
    label: 'Writer',
    description:
      'Reads and publishes packages on every repository. Deletes nothing and administers nothing.',
  },
  {
    level: 'admin',
    label: 'Admin',
    description:
      'Administers the instance: repositories, users, roles and authentication.',
  },
]

/** The levels a service account may have: it never holds `admin`. */
export const SERVICE_ACCOUNT_LEVELS: readonly AccessLevel[] = ['reader', 'writer']

/**
 * A radio group of the built-in access levels (`ACCESS_LEVEL_OPTIONS`): the
 * user page picks one with it. `levels` limits the choice (a service
 * account's: `SERVICE_ACCOUNT_LEVELS`).
 */
export function AccessLevelFields({
  value,
  onChange,
  disabled = false,
  levels,
}: {
  value: AccessLevel
  onChange: (level: AccessLevel) => void
  disabled?: boolean
  levels?: readonly AccessLevel[]
}) {
  const options = levels
    ? ACCESS_LEVEL_OPTIONS.filter((option) => levels.includes(option.level))
    : ACCESS_LEVEL_OPTIONS
  return (
    <RadioGroup<AccessLevel>
      legend="Access level"
      value={value}
      onChange={onChange}
      disabled={disabled}
      options={options.map((option) => ({
        value: option.level,
        label: option.label,
        description: option.description,
      }))}
    />
  )
}
