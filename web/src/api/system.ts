import { httpClient } from '~/lib/httpClient'

/**
 * Admin system API: the secret encryption at rest and the local blob cache
 * (`crates/server/src/admin/crypto.rs`, `blob_cache.rs`).
 *
 *  - `GET /admin/crypto/keys` lists key **metadata** (never key bytes) of the
 *    KEK and DEK layers, and the root key version.
 *  - `POST /admin/crypto/rotate/{dek|kek|root}` rotates one layer now. A 409
 *    means another rotation (the worker's, or another admin's) holds the
 *    cluster-wide lock; it can simply be retried.
 *  - `GET /admin/blob-cache` reports the local blob cache of the instance
 *    that answered (`instance`); each replica has a cache of its own.
 *  - `GET /admin/addresses` (`crates/server/src/admin/addresses.rs`) names
 *    the public base URL and the alias base URLs the server is reached
 *    under, as `forge.toml` sets them (read-only here).
 */

/** A key layer: `kek` (wraps the DEKs) or `dek` (encrypts the secrets). */
export type KeyLayer = 'kek' | 'dek'

/** `active` (in use), `retiring` (still unwraps, no longer wraps), `revoked`. */
export type KeyState = 'active' | 'retiring' | 'revoked'

/** Metadata of one key (`KeyView`). */
export interface KeyView {
  layer: KeyLayer
  version: number
  algorithm: string
  state: KeyState
  scope: string
  created_at: string
  rotated_at: string | null
  /** KEKs: the root key that wrapped it. */
  root_key_id?: string
  /** KEKs: the root key version that wrapped it. */
  root_key_version?: string
  /** DEKs: the KEK version that wrapped it. */
  wrapping_kek_version?: number
}

/** `GET /admin/crypto/keys`. */
export interface CryptoKeys {
  /** The root key version KEKs are wrapped under now. */
  root_key_version: string
  keys: KeyView[]
}

/** What a rotation rotates: a new DEK, a new KEK, or a re-wrap under the root. */
export type RotationLayer = 'dek' | 'kek' | 'root'

/** `POST /admin/crypto/rotate/{layer}` answers. */
export type RotationResult =
  | { rotated: 'dek'; new_version: number; resealed_secrets: number; revoked_deks: number }
  | { rotated: 'kek'; new_version: number }
  | { rotated: 'root'; rewrapped_keks: number }

/** The instance that answered (host name, start time). */
export interface InstanceView {
  host: string | null
  started_at: string
}

/** `GET /admin/blob-cache`. */
export type BlobCacheStats =
  | { enabled: false; instance: InstanceView }
  | {
      enabled: true
      instance: InstanceView
      path: string
      /** S3 is unreachable right now; the cache serves what it holds. */
      object_store_down: boolean
      entries: number
      size_bytes: number
      reserved_bytes: number
      limit_bytes: number
      /** The limit is derived from the volume's free space (`auto`). */
      limit_auto: boolean
      /** Hits over hits plus misses since startup; `0` before the first read. */
      hit_ratio: number
      hits: number
      hit_bytes: number
      hits_while_store_down: number
      misses: number
      fills: number
      fill_failures: number
      corrupt: number
      evictions: number
      evicted_bytes: number
      bypassed: number
    }

/**
 * `GET /admin/addresses`: `server.public_base_url`, and
 * `server.alias_base_urls`, further host names (an old Nexus host pointed
 * at Forge) whose clients are handed URLs on the alias they asked.
 */
export interface ServerAddresses {
  public_base_url: string
  alias_base_urls: string[]
}

/** Query keys of the system screen. */
export const systemKeys = {
  cryptoKeys: () => ['system', 'crypto-keys'] as const,
  blobCache: () => ['system', 'blob-cache'] as const,
  addresses: () => ['system', 'addresses'] as const,
}

/** `GET /admin/crypto/keys`. */
export function fetchCryptoKeys(signal?: AbortSignal): Promise<CryptoKeys> {
  return httpClient.get<CryptoKeys>('/admin/crypto/keys', { signal })
}

/** `POST /admin/crypto/rotate/{layer}`. */
export function rotateKeys(layer: RotationLayer): Promise<RotationResult> {
  return httpClient.post<RotationResult>(`/admin/crypto/rotate/${layer}`)
}

/** `GET /admin/blob-cache`. */
export function fetchBlobCache(signal?: AbortSignal): Promise<BlobCacheStats> {
  return httpClient.get<BlobCacheStats>('/admin/blob-cache', { signal })
}

/** `GET /admin/addresses`. */
export function fetchAddresses(signal?: AbortSignal): Promise<ServerAddresses> {
  return httpClient.get<ServerAddresses>('/admin/addresses', { signal })
}
