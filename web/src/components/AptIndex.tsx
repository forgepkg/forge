import { useState } from 'react'
import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'

import { httpClient, type ApiError } from '~/lib/httpClient'
import {
  EmptyState,
  FactList,
  Notice,
  Panel,
  SelectField,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Toolbar,
} from '~/components/ui'

/** One deb822 paragraph: its fields by name, values with continuation lines. */
export type Paragraph = Record<string, string>

/** Parse deb822 text (`Release`, `Packages`) into its paragraphs. */
export function parseParagraphs(text: string): Paragraph[] {
  const paragraphs: Paragraph[] = []
  let current: Paragraph = {}
  let last: string | null = null
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '')
    if (line.trim() === '') {
      if (Object.keys(current).length > 0) paragraphs.push(current)
      current = {}
      last = null
      continue
    }
    if (/^[ \t]/.test(line)) {
      if (last) current[last] += `\n${line.trim()}`
      continue
    }
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    last = line.slice(0, colon)
    current[last] = line.slice(colon + 1).trim()
  }
  if (Object.keys(current).length > 0) paragraphs.push(current)
  return paragraphs
}

/** The words of a `Release` field (`Components`, `Architectures`). */
export function words(value: string | undefined): string[] {
  return (value ?? '').split(/\s+/).filter((w) => w !== '')
}

/** A package of a `Packages` index, as the table lists it. */
export interface IndexedPackage {
  name: string
  version: string
  architecture: string
  section?: string
  summary?: string
}

/** The packages a `Packages` index lists, by name then as listed. */
export function indexedPackages(text: string): IndexedPackage[] {
  return parseParagraphs(text)
    .filter((p) => p.Package)
    .map((p) => ({
      name: p.Package,
      version: p.Version ?? '',
      architecture: p.Architecture ?? '',
      section: p.Section,
      summary: p.Description?.split('\n')[0],
    }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
}

function useIndexFile(repo: string, path: string, enabled = true) {
  return useQuery<string, ApiError>({
    queryKey: ['apt-index', repo, path],
    queryFn: ({ signal }) =>
      httpClient.get<string>(`/repository/${encodeURIComponent(repo)}/${path}`, { signal }),
    enabled,
  })
}

/**
 * An apt repository's distribution, browsed as `apt-get` reads it: the
 * `Release` file's components and architectures and, for a hosted
 * repository, the packages its `Packages` index lists for one component and
 * architecture (each linking to the package). A proxy's indexes are its
 * upstream's, which can be large: its `Release` is shown, its packages are
 * the ones clients download through it.
 */
export function AptIndex({
  repo,
  kind,
  distribution,
}: {
  repo: string
  kind: string
  distribution: string
}) {
  const dist = encodeURIComponent(distribution)
  const release = useIndexFile(repo, `dists/${dist}/Release`)
  const info = release.data ? (parseParagraphs(release.data)[0] ?? {}) : {}
  const components = words(info.Components)
  const architectures = words(info.Architectures)
  const concrete = architectures.filter((a) => a !== 'all')
  const [component, setComponent] = useState<string | null>(null)
  const [architecture, setArchitecture] = useState<string | null>(null)
  const chosenComponent = component ?? components[0]
  const chosenArchitecture = architecture ?? concrete[0] ?? architectures[0]
  const hosted = kind === 'hosted'
  const packages = useIndexFile(
    repo,
    `dists/${dist}/${encodeURIComponent(chosenComponent ?? '')}/binary-${encodeURIComponent(chosenArchitecture ?? '')}/Packages`,
    hosted && !!chosenComponent && !!chosenArchitecture,
  )
  const listed = packages.data ? indexedPackages(packages.data) : []

  return (
    <Panel
      title={`Distribution ${distribution}`}
      description={
        hosted
          ? 'What apt-get update reads: the signed Release file, and the packages of each component and architecture.'
          : 'The upstream’s signed Release file, passed through unchanged; packages are cached as clients download them.'
      }
      flush={hosted}
    >
      {release.isLoading && <Skeleton lines={3} label="Loading the Release file…" />}
      {release.isError && (
        <Notice tone="danger" title="Could not load the Release file">
          {release.error.body || release.error.message}
        </Notice>
      )}
      {release.data && (
        <div className={hosted ? 'px-4 pt-3' : undefined}>
          <FactList
            items={[
              { term: 'Suite', value: info.Suite ?? info.Codename ?? distribution, mono: true },
              { term: 'Date', value: info.Date ?? '—' },
              { term: 'Components', value: components.join(' ') || '—', mono: true },
              { term: 'Architectures', value: architectures.join(' ') || '—', mono: true },
            ]}
          />
        </div>
      )}
      {hosted && release.data && components.length > 0 && (
        <>
          <Toolbar>
            <SelectField
              label="Component"
              value={chosenComponent}
              onChange={(e) => setComponent(e.target.value)}
            >
              {components.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </SelectField>
            <SelectField
              label="Architecture"
              value={chosenArchitecture}
              onChange={(e) => setArchitecture(e.target.value)}
            >
              {architectures.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </SelectField>
          </Toolbar>
          {packages.isLoading && <Skeleton variant="table" label="Loading packages…" />}
          {packages.isError && (
            <Notice tone="danger" title="Could not load the packages">
              {packages.error.body || packages.error.message}
            </Notice>
          )}
          {packages.data !== undefined && listed.length === 0 && (
            <EmptyState bordered={false} title="No packages">
              Nothing in {chosenComponent} for {chosenArchitecture} yet.
            </EmptyState>
          )}
          {listed.length > 0 && (
            <Table caption={`Packages of ${chosenComponent} for ${chosenArchitecture}`} dense>
              <TableHead>
                <TableHeader>Package</TableHeader>
                <TableHeader>Version</TableHeader>
                <TableHeader>Architecture</TableHeader>
                <TableHeader>Section</TableHeader>
              </TableHead>
              <TableBody>
                {listed.map((p) => (
                  <TableRow key={`${p.name}:${p.architecture}:${p.version}`}>
                    <TableCell lead>
                      <Link
                        to="/packages/$repo/$id"
                        params={{ repo, id: `${p.name}:${p.architecture}` }}
                        className="fg-link font-mono"
                      >
                        {p.name}
                      </Link>
                      {p.summary && <div className="fg-field-desc">{p.summary}</div>}
                    </TableCell>
                    <TableCell nowrap className="font-mono">
                      {p.version}
                    </TableCell>
                    <TableCell nowrap className="font-mono">
                      {p.architecture}
                    </TableCell>
                    <TableCell nowrap>{p.section ?? '—'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </>
      )}
    </Panel>
  )
}
