import { describe, expect, it } from 'vitest'

import { connectSnippets } from './PackageConnect'

describe('connectSnippets', () => {
  it('gives a format without commands of its own its URL', () => {
    expect(
      connectSnippets('example', 'pkgs', 'https://forge.example.com/repository/pkgs', true),
    ).toEqual([
      {
        label: 'Repository URL',
        command: 'https://forge.example.com/repository/pkgs',
        copyLabel: 'Copy repository URL',
      },
    ])
  })

  it('leaves the push command out unless the repository takes pushes', () => {
    const labels = (canPush: boolean) =>
      connectSnippets('helm', 'charts', 'https://f/repository/charts', canPush).map(
        (s) => s.label,
      )
    expect(labels(true)).toEqual([
      'Add the repository',
      'Install a chart',
      'Push a chart',
    ])
    expect(labels(false)).toEqual(['Add the repository', 'Install a chart'])
  })
})
