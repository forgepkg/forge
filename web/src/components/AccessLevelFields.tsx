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

/**
 * A radio group of the built-in access levels (`ACCESS_LEVEL_OPTIONS`): the
 * user page picks one with it.
 */
export function AccessLevelFields({
  value,
  onChange,
  disabled = false,
}: {
  value: AccessLevel
  onChange: (level: AccessLevel) => void
  disabled?: boolean
}) {
  return (
    <RadioGroup<AccessLevel>
      legend="Access level"
      value={value}
      onChange={onChange}
      disabled={disabled}
      options={ACCESS_LEVEL_OPTIONS.map((option) => ({
        value: option.level,
        label: option.label,
        description: option.description,
      }))}
    />
  )
}
