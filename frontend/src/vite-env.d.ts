/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string
  readonly VITE_SSE_URL?: string
  readonly VITE_AUTH_ISSUER?: string
  readonly VITE_AUTH_CLIENT_ID?: string
  readonly VITE_ENVIRONMENT?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
