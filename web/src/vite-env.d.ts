/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Absolute API base for the cross-origin dev variant. Unset => relative. */
  readonly VITE_FORGE_API_BASE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
