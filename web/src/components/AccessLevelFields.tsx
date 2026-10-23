import type { AccessLevel } from '~/api/rbac'
import { Description, Fieldset, Label, Legend } from '~/components/catalyst/fieldset'
import { Radio, RadioField, RadioGroup } from '~/components/catalyst/radio'

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
 * create-user page and the user page pick one with it.
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
    <Fieldset disabled={disabled}>
      <Legend>Access</Legend>
      <RadioGroup
        value={value}
        onChange={(v) => onChange(v as AccessLevel)}
        aria-label="Access"
      >
        {ACCESS_LEVEL_OPTIONS.map((option) => (
          <RadioField key={option.level}>
            <Radio value={option.level} />
            <Label>{option.label}</Label>
            <Description>{option.description}</Description>
          </RadioField>
        ))}
      </RadioGroup>
    </Fieldset>
  )
}
