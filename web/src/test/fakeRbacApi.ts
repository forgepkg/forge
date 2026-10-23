import type { Me } from '~/api/me'
import type { BrowseRepo } from '~/api/packages'
import type {
  Action,
  EffectiveView,
  GrantView,
  RoleView,
  SelectorView,
} from '~/api/rbac'
import type { RepoView } from '~/api/repositories'
import type { TokenView } from '~/api/tokens'
import type { UserView } from '~/api/users'

/**
 * An in-memory stand-in for the admin RBAC API (roles, grants, members,
 * content selectors, user roles, effective access, tokens and their scopes),
 * for the screen tests: a test seeds it, drives the real route tree against
 * it, and asserts on its state and on the requests it got. It answers like
 * the server where the screens depend on it: 400 for `admin` on one
 * repository, 403 for deleting a built-in role, 409 for taking `admin` from
 * the last administrator, cascading deletes, and the selector match.
 */

export const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

export function repo(over: Partial<RepoView>): RepoView {
  return {
    id: 1,
    name: 'hosted-1',
    format: 'nuget',
    kind: 'hosted',
    anonymous_read: false,
    online: true,
    remote_url: null,
    package_delay_seconds: 0,
    upstream_username: null,
    has_upstream_password: false,
    metadata_ttl_seconds: null,
    not_found_ttl_seconds: null,
    allow_redeploy: false,
    prefer_hosted: false,
    reserved_prefixes: [],
    host: null,
    immutable_tags: false,
    latest_mutable: false,
    writable_member: null,
    max_upload_bytes: null,
    ...over,
  }
}

export function user(over: Partial<UserView>): UserView {
  return {
    id: 1,
    username: 'alice',
    is_admin: false,
    active: true,
    auth_source: 'local',
    captured_password_at: null,
    roles: [],
    ...over,
  }
}

export function token(over: Partial<TokenView>): TokenView {
  return {
    id: 1,
    user_id: 2,
    name: 'ci',
    expires_at: null,
    revoked_at: null,
    last_used_at: null,
    created_at: '2026-01-01T00:00:00Z',
    scope: null,
    ...over,
  }
}

type Role = Omit<RoleView, 'grant_count' | 'user_count'>

export interface FakeState {
  me: Me
  users: Omit<UserView, 'roles'>[]
  roles: Role[]
  grants: GrantView[]
  /** `[userId, roleId]` pairs. */
  assignments: Array<[number, number]>
  repos: RepoView[]
  selectors: SelectorView[]
  tokens: TokenView[]
  myTokens: TokenView[]
  browseRepos: BrowseRepo[]
}

export interface FakeRequest {
  method: string
  path: string
  body: unknown
}

/** The built-in roles, as a fresh install seeds them. */
export const BUILTIN_ROLES: Role[] = [
  { id: 1, name: 'admin', description: 'Full administrative access.', builtin: true },
  { id: 2, name: 'anonymous', description: 'Unauthenticated callers.', builtin: true },
  { id: 3, name: 'authenticated', description: 'Legacy open access.', builtin: true },
  {
    id: 4,
    name: 'writer',
    description: 'Read and publish packages on every repository; no administration.',
    builtin: true,
  },
]

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function text(body: string, status: number): Response {
  return new Response(body, { status })
}

const noContent = () => new Response(null, { status: 204 })

/** The server's selector semantics on the lowercased name (`*`, `?` only). */
function globMatches(pattern: string, name: string): boolean {
  const re = pattern
    .toLowerCase()
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.')
  return new RegExp(`^${re}$`).test(name.toLowerCase())
}

export class FakeRbacApi {
  state: FakeState
  requests: FakeRequest[] = []
  private nextId = 100

  constructor(seed: Partial<FakeState> = {}) {
    this.state = {
      me: adminMe,
      users: [],
      roles: [...BUILTIN_ROLES],
      grants: [],
      assignments: [],
      repos: [],
      selectors: [],
      tokens: [],
      myTokens: [],
      browseRepos: [],
      ...seed,
    }
  }

  /** Requests of `method` to a path matching `path`. */
  sent(method: string, path: RegExp): FakeRequest[] {
    return this.requests.filter((r) => r.method === method && path.test(r.path))
  }

  private roleView(r: Role): RoleView {
    return {
      ...r,
      grant_count: this.state.grants.filter((g) => g.role_id === r.id).length,
      user_count: this.state.assignments.filter(([, rid]) => rid === r.id).length,
    }
  }

  private userView(u: Omit<UserView, 'roles'>): UserView {
    const roles = this.state.assignments
      .filter(([uid]) => uid === u.id)
      .map(([, rid]) => this.state.roles.find((r) => r.id === rid)?.name)
      .filter((n): n is string => n != null)
      .sort()
    return { ...u, roles }
  }

  private roleNamed(name: string) {
    return this.state.roles.find((r) => r.name === name)
  }

  readonly fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const path = new URL(raw, 'http://localhost').pathname
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = init?.body ? JSON.parse(init.body as string) : undefined
    this.requests.push({ method, path, body })
    return Promise.resolve(this.answer(method, path, body))
  }

  private answer(method: string, path: string, body: any): Response {
    const s = this.state
    let m: RegExpMatchArray | null

    if (path === '/admin/me') return json(s.me)
    if (path === '/admin/formats') {
      return json([
        { id: 'nuget', name: 'NuGet', builtin: true, kinds: ['hosted', 'proxy', 'group'], mount: '/v3' },
      ])
    }

    // --- roles -----------------------------------------------------------
    if (path === '/admin/roles') {
      if (method === 'GET') return json(s.roles.map((r) => this.roleView(r)))
      if (method === 'POST') {
        if (this.roleNamed(body.name)) return text('role name already exists', 409)
        const r: Role = {
          id: this.nextId++,
          name: body.name,
          description: body.description ?? '',
          builtin: false,
        }
        s.roles.push(r)
        return json(this.roleView(r), 201)
      }
    }
    if ((m = path.match(/^\/admin\/roles\/(\d+)$/))) {
      const id = Number(m[1])
      const r = s.roles.find((x) => x.id === id)
      if (!r) return text('role not found', 404)
      if (method === 'GET') return json(this.roleView(r))
      if (method === 'PATCH') {
        r.description = body.description
        return json(this.roleView(r))
      }
      if (method === 'DELETE') {
        if (r.builtin) return text('built-in roles cannot be deleted', 403)
        s.roles = s.roles.filter((x) => x.id !== id)
        s.grants = s.grants.filter((g) => g.role_id !== id)
        s.assignments = s.assignments.filter(([, rid]) => rid !== id)
        return noContent()
      }
    }
    if ((m = path.match(/^\/admin\/roles\/(\d+)\/users$/))) {
      const id = Number(m[1])
      return json(
        s.assignments
          .filter(([, rid]) => rid === id)
          .map(([uid]) => s.users.find((u) => u.id === uid)!)
          .map((u) => ({
            id: u.id,
            username: u.username,
            auth_source: u.auth_source,
            active: u.active,
          })),
      )
    }
    if ((m = path.match(/^\/admin\/roles\/(\d+)\/grants$/))) {
      const id = Number(m[1])
      if (method === 'GET') return json(s.grants.filter((g) => g.role_id === id))
      if (method === 'PUT') {
        if (body.action === 'admin' && body.repository_id != null) {
          return text('repository admin is not supported', 400)
        }
        s.grants.push({
          id: this.nextId++,
          role_id: id,
          repository_id: body.repository_id ?? null,
          action: body.action as Action,
          selector_id: body.selector_id ?? null,
        })
        return new Response(null, { status: 201 })
      }
    }
    if ((m = path.match(/^\/admin\/roles\/(\d+)\/grants\/(\d+)$/)) && method === 'DELETE') {
      const gid = Number(m[2])
      s.grants = s.grants.filter((g) => g.id !== gid)
      return noContent()
    }

    // --- users and their roles --------------------------------------------
    if (path === '/admin/users' && method === 'GET') {
      return json(s.users.map((u) => this.userView(u)))
    }
    if (path === '/admin/users' && method === 'POST') {
      const u = {
        id: this.nextId++,
        username: body.username,
        is_admin: body.is_admin,
        active: body.active,
        auth_source: 'local',
        captured_password_at: null,
      }
      s.users.push(u)
      if (u.is_admin) s.assignments.push([u.id, this.roleNamed('admin')!.id])
      return json(this.userView(u), 201)
    }
    if ((m = path.match(/^\/admin\/users\/(\d+)\/roles$/))) {
      const uid = Number(m[1])
      if (method === 'GET') {
        return json(
          s.assignments
            .filter(([u]) => u === uid)
            .map(([, rid]) => this.roleView(s.roles.find((r) => r.id === rid)!)),
        )
      }
      if (method === 'PUT') {
        const rid = body.role_id as number
        if (!s.roles.some((r) => r.id === rid)) return text('role not found', 404)
        if (!s.assignments.some(([u, r]) => u === uid && r === rid)) {
          s.assignments.push([uid, rid])
        }
        return noContent()
      }
    }
    if ((m = path.match(/^\/admin\/users\/(\d+)\/roles\/(\d+)$/)) && method === 'DELETE') {
      const uid = Number(m[1])
      const rid = Number(m[2])
      const admin = this.roleNamed('admin')!
      if (rid === admin.id) {
        const admins = s.assignments.filter(([, r]) => r === admin.id)
        if (admins.length === 1 && admins[0][0] === uid) {
          return text(
            'this would leave no active administrator; make another user an admin first',
            409,
          )
        }
      }
      s.assignments = s.assignments.filter(([u, r]) => !(u === uid && r === rid))
      return noContent()
    }
    if ((m = path.match(/^\/admin\/users\/(\d+)\/effective$/))) {
      const uid = Number(m[1])
      const held = s.assignments.filter(([u]) => u === uid).map(([, r]) => r)
      const view: EffectiveView = {
        is_admin: held.includes(this.roleNamed('admin')!.id),
        grants: s.grants
          .filter((g) => held.includes(g.role_id))
          .map((g) => {
            const sel = s.selectors.find((x) => x.id === g.selector_id)
            return {
              action: g.action,
              repository_id: g.repository_id,
              selector_id: g.selector_id,
              includes: sel?.includes ?? null,
              excludes: sel?.excludes ?? null,
            }
          }),
      }
      return json(view)
    }

    // --- tokens -----------------------------------------------------------
    if ((m = path.match(/^\/admin\/users\/(\d+)\/tokens$/))) {
      const uid = Number(m[1])
      if (method === 'GET') return json(s.tokens.filter((t) => t.user_id === uid))
      if (method === 'POST') {
        const t = token({ id: this.nextId++, user_id: uid, name: body.name, scope: body.scope ?? null })
        s.tokens.push(t)
        return json({ ...t, token: 'plaintext-secret' }, 201)
      }
    }
    if ((m = path.match(/^\/admin\/tokens\/(\d+)\/scope$/)) && method === 'PATCH') {
      const t = s.tokens.find((x) => x.id === Number(m![1]))
      if (!t) return text('token not found or revoked', 404)
      t.scope = body.scope
      return noContent()
    }
    if (path === '/admin/me/tokens') {
      if (method === 'GET') return json(s.myTokens)
      if (method === 'POST') {
        const t = token({ id: this.nextId++, user_id: s.me.user.id, name: body.name, scope: body.scope ?? null })
        s.myTokens.push(t)
        return json({ ...t, token: 'my-plaintext-secret' }, 201)
      }
    }

    // --- repositories -----------------------------------------------------
    if (path === '/admin/repositories' && method === 'GET') return json(s.repos)
    if ((m = path.match(/^\/admin\/repositories\/([^/]+)$/)) && method === 'GET') {
      const r = s.repos.find((x) => x.name === decodeURIComponent(m![1]))
      return r ? json(r) : text('repository not found', 404)
    }
    if (path === '/browse/repos') return json(s.browseRepos)

    // --- content selectors ------------------------------------------------
    if (path === '/admin/content-selectors/match' && method === 'POST') {
      const bad = [...body.includes, ...body.excludes].find((p: string) => p.includes('['))
      if (bad) return text(`invalid content-selector glob: ${bad}`, 400)
      const name = String(body.name)
      const excluded = body.excludes.some((p: string) => globMatches(p, name))
      const included =
        body.includes.length === 0 || body.includes.some((p: string) => globMatches(p, name))
      return json({ matches: included && !excluded })
    }
    if (path === '/admin/content-selectors') {
      if (method === 'GET') return json(s.selectors)
      if (method === 'POST') {
        const sel: SelectorView = {
          id: this.nextId++,
          name: body.name,
          description: body.description ?? '',
          includes: body.includes ?? [],
          excludes: body.excludes ?? [],
        }
        s.selectors.push(sel)
        return json(sel, 201)
      }
    }
    if ((m = path.match(/^\/admin\/content-selectors\/(\d+)$/))) {
      const id = Number(m[1])
      const sel = s.selectors.find((x) => x.id === id)
      if (!sel) return text('content selector not found', 404)
      if (method === 'PATCH') {
        Object.assign(sel, body)
        return json(sel)
      }
      if (method === 'DELETE') {
        s.selectors = s.selectors.filter((x) => x.id !== id)
        s.grants = s.grants.filter((g) => g.selector_id !== id)
        return noContent()
      }
    }
    if ((m = path.match(/^\/admin\/content-selectors\/(\d+)\/grants$/))) {
      const id = Number(m[1])
      return json(s.grants.filter((g) => g.selector_id === id))
    }

    return text('not found', 404)
  }
}
