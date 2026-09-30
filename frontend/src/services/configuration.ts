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
  environment: env.VITE_ENVIRONMENT?.trim() || 'Unspecified',
  apiBaseUrl: configuredUrl(env.VITE_API_BASE_URL),
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
