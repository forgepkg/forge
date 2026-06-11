import { Input, InputGroup } from '~/components/catalyst/input'

/**
 * Controlled search input (Catalyst input group with a leading magnifier).
 * Debouncing + URL-state sync live in the parent route; this stays a thin
 * presentational control so it is trivially testable.
 */
export function SearchBox({
  value,
  onChange,
  placeholder = 'Search packages…',
  label = 'Search packages',
}: {
  value: string
  onChange: (next: string) => void
  placeholder?: string
  label?: string
}) {
  return (
    <InputGroup>
      <MagnifierIcon />
      <Input
        type="search"
        aria-label={label}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    </InputGroup>
  )
}

function MagnifierIcon() {
  return (
    <svg data-slot="icon" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M9 3.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11ZM2 9a7 7 0 1 1 12.452 4.391l3.328 3.329a.75.75 0 1 1-1.06 1.06l-3.329-3.328A7 7 0 0 1 2 9Z"
        clipRule="evenodd"
      />
    </svg>
  )
}
