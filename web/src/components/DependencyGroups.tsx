import { Fragment } from 'react'
import { Link } from '@tanstack/react-router'

import type { DetailDependencyGroup } from '~/api/packages'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Version,
} from '~/components/ui'

/**
 * The dependencies of a package's versions, per version and target framework,
 * as one table. Each dependency links to its own package within the same
 * repository (the most useful default; cross-repo resolution is not modeled
 * in the browse API).
 */
export function DependencyGroups({
  repo,
  byVersion,
  caption,
}: {
  repo: string
  /** Dependency groups keyed by version, as the detail API returns them. */
  byVersion: Record<string, DetailDependencyGroup[]>
  caption?: string
}) {
  return (
    <Table caption={caption}>
      <TableHead>
        <TableHeader width="150px">Version</TableHeader>
        <TableHeader width="170px">Target framework</TableHeader>
        <TableHeader>Package</TableHeader>
        <TableHeader width="160px">Version range</TableHeader>
      </TableHead>
      <TableBody>
        {Object.entries(byVersion).map(([version, groups]) => (
          <Fragment key={version}>
            {groups.length === 0 ? (
              <TableRow>
                <TableCell lead>
                  <Version value={version} />
                </TableCell>
                <TableCell colSpan={3}>No dependencies.</TableCell>
              </TableRow>
            ) : (
              groups.map((group, gi) => {
                const framework = group.target_framework ?? 'Any framework'
                if (group.dependencies.length === 0) {
                  return (
                    <TableRow key={`${framework}-${gi}`}>
                      <TableCell lead>{gi === 0 && <Version value={version} />}</TableCell>
                      <TableCell>
                        <span className="fg-mono">{framework}</span>
                      </TableCell>
                      <TableCell colSpan={2}>No dependencies.</TableCell>
                    </TableRow>
                  )
                }
                return group.dependencies.map((dep, di) => (
                  <TableRow key={`${framework}-${gi}-${dep.id}`}>
                    <TableCell lead>
                      {gi === 0 && di === 0 && <Version value={version} />}
                    </TableCell>
                    <TableCell>
                      {di === 0 && <span className="fg-mono">{framework}</span>}
                    </TableCell>
                    <TableCell>
                      <Link
                        to="/packages/$repo/$id"
                        params={{ repo, id: dep.id.toLowerCase() }}
                        className="fg-link-strong"
                      >
                        {dep.id}
                      </Link>
                    </TableCell>
                    <TableCell>
                      {dep.range && <span className="fg-mono">{dep.range}</span>}
                    </TableCell>
                  </TableRow>
                ))
              })
            )}
          </Fragment>
        ))}
      </TableBody>
    </Table>
  )
}
