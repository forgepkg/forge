/**
 * Controlled search input. Debouncing + URL-state sync live in the parent
 * route; this stays a thin presentational control so it is trivially testable.
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
    <input
      type="search"
      aria-label={label}
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-slate-400 focus:outline-none focus:ring-1 focus:ring-slate-400"
    />
  )
}
