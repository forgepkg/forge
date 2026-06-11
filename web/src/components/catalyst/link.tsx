/**
 * Catalyst's client-side-router integration point, wired to TanStack Router
 * (per https://catalyst.tailwindui.com/docs#client-side-router-integration).
 *
 * Catalyst components address links with an `href` string; TanStack Router
 * navigates by `to`. Call sites inside Catalyst (Button, NavbarItem, table
 * rows, …) pass concrete paths (e.g. `/repos/nuget`), so `href` is forwarded
 * as an untyped `to` — the typed `Link` from `@tanstack/react-router` remains
 * the tool of choice for app code outside the kit.
 */

import * as Headless from '@headlessui/react'
import { createLink } from '@tanstack/react-router'
import React, { forwardRef } from 'react'

const RouterAnchor = forwardRef(function RouterAnchor(
  props: React.ComponentPropsWithoutRef<'a'>,
  ref: React.ForwardedRef<HTMLAnchorElement>,
) {
  return <a {...props} ref={ref} />
})

const RouterLink = createLink(RouterAnchor)

export const Link = forwardRef(function Link(
  props: { href: string } & React.ComponentPropsWithoutRef<'a'>,
  ref: React.ForwardedRef<HTMLAnchorElement>,
) {
  const { href, ...rest } = props
  return (
    <Headless.DataInteractive>
      <RouterLink to={href} {...rest} ref={ref} />
    </Headless.DataInteractive>
  )
})
