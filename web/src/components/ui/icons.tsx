import clsx from 'clsx'

/**
 * The design system's line icons: a 20px grid, 1.5px stroke, round caps and
 * joins, drawn in the colour of the text around them. 16px in the interface,
 * 14px in small buttons and badges, 20px in headers and empty states.
 *
 * Formats use generic glyphs with their names, never trademark logos: NuGet
 * `Package`, Docker `Layers`, Helm charts `Wheel`. `Folder`, `File`, `Mail` and
 * `Overview` are the app's additions in the same style.
 */

function circ(x: number, y: number, r: number): string {
  return `M${x - r} ${y}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`
}

const EYE = 'M2 10s3-5.5 8-5.5 8 5.5 8 5.5-3 5.5-8 5.5S2 10 2 10z'

const ICONS = {
  Search: [circ(8.5, 8.5, 5.5), 'M12.6 12.6L17 17'],
  Copy: ['M7.5 7.5h9v9h-9z', 'M12.5 7.5v-4h-9v9h4'],
  Check: ['M4 10.5l3.8 3.8L16 6'],
  CheckCircle: [circ(10, 10, 7), 'M7 10.2l2.1 2.1L13.2 8'],
  ChevronRight: ['M8 5l5 5-5 5'],
  ChevronLeft: ['M12 5l-5 5 5 5'],
  ChevronDown: ['M5 8l5 5 5-5'],
  Package: ['M3 6.5L10 3l7 3.5v7L10 17l-7-3.5z', 'M3 6.5L10 10l7-3.5', 'M10 10v7'],
  Layers: ['M10 3l7 3.5-7 3.5-7-3.5z', 'M3 10l7 3.5 7-3.5', 'M3 13.5L10 17l7-3.5'],
  Wheel: [
    circ(10, 10, 6),
    circ(10, 10, 2),
    'M10 2v6',
    'M10 12v6',
    'M2 10h6',
    'M12 10h6',
    'M4.3 4.3l4.3 4.3',
    'M11.4 11.4l4.3 4.3',
    'M15.7 4.3l-4.3 4.3',
    'M8.6 11.4l-4.3 4.3',
  ],
  Repository: ['M3 3.5h14V9H3z', 'M3 11h14v5.5H3z', 'M7 6.25h6', 'M7 13.75h6'],
  Database: [
    'M4 5c0-1.1 2.7-2 6-2s6 .9 6 2-2.7 2-6 2-6-.9-6-2z',
    'M4 5v10c0 1.1 2.7 2 6 2s6-.9 6-2V5',
    'M4 10c0 1.1 2.7 2 6 2s6-.9 6-2',
  ],
  Grid: ['M3 3h6v6H3z', 'M11 3h6v6h-6z', 'M3 11h6v6H3z', 'M11 11h6v6h-6z'],
  Key: [circ(6.5, 10, 3.5), 'M10 10h7.5', 'M14.5 10v3', 'M17.5 10v2.5'],
  Users: [
    circ(7.5, 7, 3),
    'M2 16.5c.6-2.8 2.8-4.5 5.5-4.5s4.9 1.7 5.5 4.5',
    'M13 4.2a3 3 0 0 1 0 5.6',
    'M15 12.3c1.3.7 2.1 2.2 2.5 4.2',
  ],
  Shield: ['M10 2.5l6 2.3v4.7c0 3.8-2.5 6.6-6 8-3.5-1.4-6-4.2-6-8V4.8z'],
  Sliders: [
    'M3 5.5h2.5',
    'M8.5 5.5H17',
    circ(7, 5.5, 1.5),
    'M3 10h8.5',
    'M14.5 10H17',
    circ(13, 10, 1.5),
    'M3 14.5h3.5',
    'M9.5 14.5H17',
    circ(8, 14.5, 1.5),
  ],
  Filter: ['M3 4h14l-5.5 6.5V16l-3-1.5v-4z'],
  Plus: ['M10 4v12', 'M4 10h12'],
  Pencil: ['M13.5 3.5l3 3L7 16H4v-3z', 'M11.5 5.5l3 3'],
  Trash: ['M3.5 5.5h13', 'M8 5.5v-2h4v2', 'M5 5.5l.8 11h8.4l.8-11'],
  External: ['M11.5 3.5h5v5', 'M16.5 3.5L9 11', 'M14 12v4.5H3.5V6H8'],
  More: [circ(4.5, 10, 0.9), circ(10, 10, 0.9), circ(15.5, 10, 0.9)],
  Grip: [
    circ(7.5, 5, 0.8),
    circ(12.5, 5, 0.8),
    circ(7.5, 10, 0.8),
    circ(12.5, 10, 0.8),
    circ(7.5, 15, 0.8),
    circ(12.5, 15, 0.8),
  ],
  Eye: [EYE, circ(10, 10, 2.5)],
  EyeOff: [EYE, circ(10, 10, 2.5), 'M3 3l14 14'],
  Clock: [circ(10, 10, 7), 'M10 6v4l2.5 2.5'],
  Activity: ['M2.5 10.5h3l2.2-5.5 4.6 10 2.2-4.5h3'],
  Alert: ['M10 3l8 14H2z', 'M10 8.5V12', 'M10 14.6v.1'],
  Info: [circ(10, 10, 7), 'M10 9v5', 'M10 6.4v.1'],
  X: ['M5 5l10 10', 'M15 5L5 15'],
  Sun: [
    circ(10, 10, 3.5),
    'M10 2v2',
    'M10 16v2',
    'M2 10h2',
    'M16 10h2',
    'M4.3 4.3l1.4 1.4',
    'M14.3 14.3l1.4 1.4',
    'M15.7 4.3l-1.4 1.4',
    'M5.7 14.3l-1.4 1.4',
  ],
  Moon: ['M16 12.5A6.5 6.5 0 0 1 7.5 4a6.5 6.5 0 1 0 8.5 8.5z'],
  LogOut: ['M8 3.5H3.5v13H8', 'M12.5 6l4 4-4 4', 'M16.5 10h-9'],
  Upload: ['M10 13V3.5', 'M6 7.5l4-4 4 4', 'M3.5 13v3.5h13V13'],
  Download: ['M10 3.5V13', 'M6 9l4 4 4-4', 'M3.5 13v3.5h13V13'],
  Lock: ['M4.5 9h11v8h-11z', 'M7 9V6.5a3 3 0 0 1 6 0V9'],
  Globe: [circ(10, 10, 7), 'M3 10h14', 'M10 3c2 2 3 4.5 3 7s-1 5-3 7c-2-2-3-4.5-3-7s1-5 3-7z'],
  Terminal: ['M2.5 4h15v12h-15z', 'M6 8l2.5 2L6 12', 'M10.5 12.5H14'],
  Refresh: ['M16 4v4h-4', 'M4 16v-4h4', 'M15.6 8A6 6 0 0 0 5 6.2', 'M4.4 12A6 6 0 0 0 15 13.8'],
  Menu: ['M3 6h14', 'M3 10h14', 'M3 14h14'],
  ArrowUp: ['M10 16V4', 'M5 9l5-5 5 5'],
  ArrowDown: ['M10 4v12', 'M5 11l5 5 5-5'],
  Folder: ['M2.5 5.5a1 1 0 0 1 1-1h4l2 2h7a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1h-13a1 1 0 0 1-1-1z'],
  File: ['M5 2.5h6.5L15 6v11.5H5z', 'M11.5 2.5V6H15'],
  Mail: ['M2.5 4.5h15v11h-15z', 'M2.5 5l7.5 6 7.5-6'],
  Overview: ['M3 3h6v8H3z', 'M11 3h6v4h-6z', 'M11 9h6v8h-6z', 'M3 13h6v4H3z'],
} satisfies Record<string, string[]>

export type IconName = keyof typeof ICONS

/** The names of every icon, for previews and tests. */
export const ICON_NAMES = Object.keys(ICONS) as IconName[]

/**
 * One icon. Decorative by default (`aria-hidden`); pass `title` only when the
 * icon carries meaning alone, and prefer a visible word.
 */
export function Icon({
  name,
  size = 16,
  strokeWidth = 1.5,
  title,
  className,
}: {
  name: IconName
  size?: number
  strokeWidth?: number
  title?: string
  className?: string
}) {
  const a11y = title
    ? { role: 'img' as const, 'aria-label': title }
    : { 'aria-hidden': true as const }
  return (
    <svg
      viewBox="0 0 20 20"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      focusable="false"
      className={clsx('fg-icon', className)}
      {...a11y}
    >
      {ICONS[name].map((d, i) => (
        <path key={i} d={d} />
      ))}
    </svg>
  )
}

const MARK = 'M3 9L9 3H23L29 9V20H3Z M3 23H29V29H3Z'
const WORD_FORGE =
  'M42.71 26.5V15.14H40.63V12.4H42.71V10.39Q42.71 8.52 43.7 7.52Q44.7 6.52 46.6 6.52H49.05V9.27H46.16V12.4H49.05V15.14H46.16V26.5ZM56.85 26.82Q54.83 26.82 53.37 25.92Q51.9 25.02 51.11 23.35Q50.31 21.69 50.31 19.44Q50.31 17.17 51.11 15.52Q51.9 13.88 53.37 12.98Q54.83 12.07 56.85 12.07Q58.86 12.07 60.33 12.98Q61.79 13.88 62.59 15.52Q63.39 17.17 63.39 19.44Q63.39 21.69 62.59 23.35Q61.79 25.02 60.33 25.92Q58.86 26.82 56.85 26.82ZM56.85 24.03Q58.2 24.03 58.99 23.19Q59.77 22.35 59.77 20.76V18.14Q59.77 16.53 58.99 15.7Q58.2 14.87 56.85 14.87Q55.52 14.87 54.72 15.7Q53.93 16.53 53.93 18.14V20.76Q53.93 22.35 54.72 23.19Q55.52 24.03 56.85 24.03ZM69.7 26.5H66.24V12.4H69.7V15.32H69.83Q70.02 14.57 70.47 13.91Q70.93 13.24 71.69 12.82Q72.45 12.4 73.57 12.4H74.31V15.66H73.23Q72.07 15.66 71.28 15.9Q70.49 16.13 70.09 16.6Q69.7 17.08 69.7 17.87ZM89.37 27.68Q89.37 29.15 88.64 30.16Q87.91 31.18 86.29 31.7Q84.67 32.22 81.97 32.22Q79.6 32.22 78.16 31.83Q76.72 31.43 76.07 30.68Q75.42 29.93 75.42 28.89Q75.42 27.72 76.09 27.05Q76.76 26.38 77.94 26.19V25.89Q77.06 25.67 76.6 25.05Q76.13 24.42 76.13 23.57Q76.13 22.48 76.91 21.89Q77.69 21.29 78.7 21.08V20.97Q77.44 20.38 76.79 19.32Q76.14 18.26 76.14 16.86Q76.14 15.43 76.81 14.35Q77.48 13.27 78.78 12.67Q80.08 12.07 81.97 12.07Q82.67 12.07 83.29 12.16Q83.92 12.25 84.44 12.42V11.97Q84.44 10.95 84.96 10.43Q85.47 9.92 86.43 9.92H88.62V12.57H85.63V12.95Q86.73 13.55 87.27 14.57Q87.81 15.58 87.81 16.86Q87.81 18.26 87.16 19.34Q86.5 20.41 85.2 21Q83.89 21.59 81.98 21.59Q81.38 21.59 80.83 21.52Q80.28 21.45 79.81 21.34Q79.42 21.53 79.12 21.84Q78.83 22.14 78.83 22.6Q78.83 23.15 79.28 23.41Q79.73 23.67 80.66 23.67H84.43Q87.02 23.67 88.19 24.73Q89.37 25.78 89.37 27.68ZM86.12 28.11Q86.12 27.42 85.59 27.05Q85.05 26.67 83.73 26.67H78.93Q78.55 26.95 78.37 27.32Q78.19 27.7 78.19 28.12Q78.19 28.93 78.87 29.38Q79.55 29.84 81.18 29.84H82.91Q84.58 29.84 85.35 29.41Q86.12 28.97 86.12 28.11ZM81.98 19.23Q83.22 19.23 83.87 18.68Q84.52 18.12 84.52 17.07V16.61Q84.52 15.54 83.87 15Q83.22 14.45 81.98 14.45Q80.75 14.45 80.09 15Q79.44 15.54 79.44 16.61V17.07Q79.44 18.12 80.09 18.68Q80.75 19.23 81.98 19.23ZM96.88 26.82Q94.8 26.82 93.31 25.92Q91.82 25.02 91.03 23.35Q90.24 21.69 90.24 19.44Q90.24 17.21 91.01 15.55Q91.78 13.9 93.24 12.99Q94.71 12.07 96.77 12.07Q98.97 12.07 100.39 13.05Q101.81 14.02 102.5 15.63Q103.19 17.25 103.19 19.18V20.32H93.82V20.66Q93.82 22.19 94.68 23.12Q95.55 24.06 97.24 24.06Q98.53 24.06 99.36 23.51Q100.2 22.97 100.83 22.15L102.69 24.23Q101.83 25.4 100.33 26.11Q98.83 26.82 96.88 26.82ZM96.82 14.68Q95.91 14.68 95.23 15.1Q94.56 15.51 94.19 16.25Q93.82 16.99 93.82 17.98V18.19H99.59V17.93Q99.59 16.95 99.27 16.23Q98.96 15.5 98.34 15.09Q97.72 14.68 96.82 14.68Z'
const WORD_W = 105

/**
 * The Forge mark (an ingot on an anvil plate), alone or with the wordmark,
 * drawn inline so it follows the theme: the wordmark takes the text colour,
 * the mark is `heat` (`rail-heat` in the rail). `size` is the height in px.
 */
export function Logo({
  variant = 'lockup',
  size = 24,
  className,
}: {
  variant?: 'lockup' | 'mark'
  size?: number
  className?: string
}) {
  const mark = <path d={MARK} className="fg-logo-mark" />
  if (variant === 'mark') {
    return (
      <svg
        viewBox="0 0 32 32"
        width={size}
        height={size}
        role="img"
        aria-label="Forge"
        className={clsx('fg-logo', className)}
      >
        {mark}
      </svg>
    )
  }
  return (
    <svg
      viewBox={`0 0 ${WORD_W} 34`}
      width={Math.round((size * WORD_W) / 34)}
      height={size}
      role="img"
      aria-label="Forge"
      className={clsx('fg-logo', className)}
    >
      {mark}
      <path d={WORD_FORGE} className="fg-logo-word" />
    </svg>
  )
}

function initials(name: string): string {
  const parts = String(name || '?')
    .split(/[\s._@-]+/)
    .filter(Boolean)
  return ((parts[0] ?? '?')[0] + (parts[1] ? parts[1][0] : '')).toUpperCase()
}

/** A person's initials in a neutral circle (Forge has no profile pictures). */
export function Avatar({
  name,
  size = 28,
  decorative = false,
  className,
}: {
  name: string
  size?: number
  decorative?: boolean
  className?: string
}) {
  return (
    <span
      className={clsx('fg-avatar', className)}
      title={decorative ? undefined : name}
      aria-hidden={decorative ? true : undefined}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.4) }}
    >
      {initials(name)}
    </span>
  )
}
