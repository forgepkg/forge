import { describe, expect, it } from 'vitest'

import { parseSearch, searchFlag, searchInt, stringifySearch } from './search'

describe('parseSearch', () => {
  it.each([
    ['?tag=1.36', { tag: '1.36' }],
    ['?tag=1.10', { tag: '1.10' }],
    ['?tag=2', { tag: '2' }],
    ['?q=1.0', { q: '1.0' }],
    ['?q=true', { q: 'true' }],
    ['?q=null', { q: 'null' }],
    ['?q=%5B1%5D', { q: '[1]' }],
    ['?q=%7B%7D', { q: '{}' }],
    ['?path=2026', { path: '2026' }],
    ['?tag=latest', { tag: 'latest' }],
    ['?q=', { q: '' }],
    ['', {}],
  ])('keeps %s as strings', (search, expected) => {
    expect(parseSearch(search)).toEqual(expected)
  })

  it('reads a JSON string literal, as the default stringifier wrote it', () => {
    expect(parseSearch('?tag=%221.36%22')).toEqual({ tag: '1.36' })
    expect(parseSearch('?q=%22%5C%22a%5C%22%22')).toEqual({ q: '"a"' })
  })

  it('keeps a value that only starts like a JSON string', () => {
    expect(parseSearch('?q=%22a')).toEqual({ q: '"a' })
    expect(parseSearch('?q=%22a%22b')).toEqual({ q: '"a"b' })
  })

  it('decodes the query and keeps the first of a repeated key', () => {
    expect(parseSearch('path=pdfium%2Fa+b%2F&after=x&after=y')).toEqual({
      path: 'pdfium/a b/',
      after: 'x',
    })
  })
})

describe('stringifySearch', () => {
  it('writes strings as they are, numbers and booleans as JSON', () => {
    expect(stringifySearch({ tag: '1.36', q: '1.0', skip: 20, prerelease: true })).toBe(
      '?tag=1.36&q=1.0&skip=20&prerelease=true',
    )
  })

  it('leaves out undefined values and an empty search', () => {
    expect(stringifySearch({ q: undefined, path: 'a/' })).toBe('?path=a%2F')
    expect(stringifySearch({})).toBe('')
  })

  it('quotes a string that would read back as another one', () => {
    expect(stringifySearch({ q: '"a"' })).toBe('?q=%22%5C%22a%5C%22%22')
    expect(stringifySearch({ q: '"a' })).toBe('?q=%22a')
  })

  it.each(['1.10', '2', 'true', 'null', '', '"a"', '"a', '"', 'a b/&c=d', '[1]'])(
    'reads %j back unchanged',
    (value) => {
      expect(parseSearch(stringifySearch({ v: value }))).toEqual({ v: value })
    },
  )
})

describe('searchInt', () => {
  it('takes a non-negative integer from the URL or from navigate', () => {
    expect(searchInt('20')).toBe(20)
    expect(searchInt('0')).toBe(0)
    expect(searchInt(20)).toBe(20)
    expect(searchInt(20.7)).toBe(20)
  })

  it.each(['', '-1', '1.5', '1e3', 'abc', ' 2', '9'.repeat(16), -1, Number.NaN, true, null, undefined])(
    'refuses %j',
    (value) => {
      expect(searchInt(value)).toBeUndefined()
    },
  )
})

describe('searchFlag', () => {
  it('is true only for true and "true"', () => {
    expect(searchFlag(true)).toBe(true)
    expect(searchFlag('true')).toBe(true)
    expect(searchFlag('false')).toBe(false)
    expect(searchFlag('1')).toBe(false)
    expect(searchFlag(undefined)).toBe(false)
  })
})
