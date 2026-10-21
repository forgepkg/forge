import { httpClient } from '~/lib/httpClient'

/**
 * Read-side browse API of **docker** repositories (images, tags, manifests).
 *
 * Types mirror the Rust DTOs in `crates/server/src/browse_images.rs`. The same
 * rules as the package browse apply: a signed-in user (401 otherwise), per-repo
 * read authorization (403), and a 404 for an unknown repository (to an admin)
 * or an image with nothing visible. A group lists what its readable members
 * hold, the highest-priority member first.
 *
 * Image names are OCI repository names and may contain `/` (`team/app`); the
 * pull name of an image is `<pull_prefix>/<image>` — `pull_prefix` is
 * `<registry>/<repo>`, or the repository's own host when one is configured.
 */

/** One image of a repository listing (`ImageItem`). */
export interface ImageItem {
  /** Image name within the repository, e.g. `team/app`. */
  image: string
  /** Number of tags. */
  tag_count: number
  /** Number of manifests (tagged or not, index children included). */
  manifest_count: number
  /** When the newest manifest was pushed (or first cached by a proxy). */
  last_pushed_at: string
}

/** `GET /browse/images?repo=…` response (paginated). */
export interface ImagesResult {
  /** Total images matching the query (pre-paging). */
  total: number
  /** The requested page. */
  items: ImageItem[]
  /** `host[:port]` clients log in to: `docker login <registry>`. */
  registry: string
  /** What image names are prefixed with: `<pull_prefix>/<image>`. */
  pull_prefix: string
}

/** One tag of an image (`TagItem`). */
export interface ImageTag {
  tag: string
  /** Digest of the manifest the tag points at (`sha256:…`). */
  digest: string
  media_type: string
  /**
   * Compressed size of the image's layers (for an index: of every platform's
   * image Forge holds); `null` when unknown.
   */
  size: number | null
  /** `os/arch[/variant]` the tagged manifest runs on. */
  platforms: string[]
}

/** One manifest of an image (`ManifestItem`). */
export interface ImageManifest {
  digest: string
  /** Manifest media type (image manifest, index / manifest list, …). */
  media_type: string
  /**
   * The manifest's artifact type (OCI 1.1), or its config media type; `null`
   * when the manifest names neither.
   */
  artifact_type: string | null
  /** The manifest this one refers to (a signature, SBOM, attestation, …). */
  subject_digest: string | null
  /** Byte size of the manifest document itself. */
  manifest_size: number
  /** See {@link ImageTag.size}. */
  size: number | null
  platforms: string[]
  /** Tags pointing at this manifest. */
  tags: string[]
  /** An index's child manifests (digests). */
  children: string[]
  /** Pushed (hosted) / first cached (proxy). */
  created_at: string
  last_pulled_at: string | null
  /** The member repository the manifest comes from (groups only). */
  source?: string
}

/** `GET /browse/images/{repo}/{image…}` response (`ImageDetail`). */
export interface ImageDetail {
  repo: string
  repo_kind: string
  image: string
  /** `host[:port]` clients log in to. */
  registry: string
  /** `docker pull <pull_name>:<tag>` / `docker pull <pull_name>@<digest>`. */
  pull_name: string
  tags: ImageTag[]
  manifests: ImageManifest[]
}

/** Search parameters for one repository's image list (`ImagesQuery`). */
export interface ImageSearchParams {
  /** The docker repository (required by the endpoint). */
  repo: string
  /** Image-name substring. Empty matches all. */
  q?: string
  /** Pagination offset. */
  skip?: number
  /** Page size (backend clamps to 200; 0 / unset => 50). */
  take?: number
}

/**
 * Query-key factory for the image resource, mirroring `pkgKeys`: arrays from a
 * single factory so `keepPreviousData` pagination shares stable keys.
 */
export const imageKeys = {
  all: () => ['images'] as const,
  search: (params: ImageSearchParams) =>
    [
      'images',
      'search',
      {
        repo: params.repo,
        q: params.q ?? '',
        skip: params.skip ?? 0,
        take: params.take ?? 0,
      },
    ] as const,
  detail: (repo: string, image: string) =>
    ['images', 'detail', repo, image] as const,
}

/** Fetch a page of one docker repository's images. */
export function fetchImages(
  params: ImageSearchParams,
  signal?: AbortSignal,
): Promise<ImagesResult> {
  return httpClient.get<ImagesResult>('/browse/images', {
    query: {
      repo: params.repo,
      q: params.q || undefined,
      skip: params.skip || undefined,
      take: params.take || undefined,
    },
    signal,
  })
}

/**
 * Fetch one image's tags and manifests. The image name keeps its `/`
 * separators in the path (`/browse/images/docker-hosted/team/app`); each
 * component is encoded on its own.
 */
export function fetchImageDetail(
  repo: string,
  image: string,
  signal?: AbortSignal,
): Promise<ImageDetail> {
  const path = image.split('/').map(encodeURIComponent).join('/')
  return httpClient.get<ImageDetail>(
    `/browse/images/${encodeURIComponent(repo)}/${path}`,
    { signal },
  )
}
