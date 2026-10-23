import { SearchField } from '~/components/ui'

/**
 * Controlled search input with the search icon. Debouncing + URL-state sync
 * live in the parent route; this stays a thin presentational control so it
 * is trivially testable.
 */
export function SearchBox({
  value,
  onChange,
  placeholder = 'Search packages…',
  label = 'Search packages',
  className,
}: {
  value: string
  onChange: (next: string) => void
  placeholder?: string
  label?: string
  className?: string
}) {
  return (
    <SearchField
      label={label}
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      className={className}
    />
  )
}
