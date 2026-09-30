const env = import.meta.env

function configuredUrl(value: string | undefined): string | undefined {
  if (!value?.trim()) return undefined
  try {
    const parsed = new URL(value)
    return parsed.toString().replace(/\/$/, '')
  } catch {
    return undefined
  }
}

export const appConfiguration = {
  environment: env.VITE_ENVIRONMENT?.trim() || 'Development (Local Lab)',
  apiBaseUrl: configuredUrl(env.VITE_API_BASE_URL) || 'http://127.0.0.1:8000',
  eventStreamUrl: configuredUrl(env.VITE_SSE_URL),
  authIssuer: configuredUrl(env.VITE_AUTH_ISSUER),
  authClientId: env.VITE_AUTH_CLIENT_ID?.trim() || undefined,
  get apiConfigured() {
    return Boolean(this.apiBaseUrl)
  },
  get eventsConfigured() {
    return Boolean(this.eventStreamUrl)
  },
  get authenticationConfigured() {
    return Boolean(this.authIssuer && this.authClientId)
  },
}

export async function apiRequest<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const base = appConfiguration.apiBaseUrl || 'http://127.0.0.1:8000'
  const url = `${base}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  })
  if (!res.ok) {
    const errText = await res.text()
    throw new Error(`API Error ${res.status}: ${errText}`)
  }
  return res.json() as Promise<T>
}
