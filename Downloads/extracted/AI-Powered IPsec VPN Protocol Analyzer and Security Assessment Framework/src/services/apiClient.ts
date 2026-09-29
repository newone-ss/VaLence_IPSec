import { appConfiguration } from './configuration'

export class ApiConfigurationError extends Error {
  constructor(message = 'The API base URL is not configured.') {
    super(message)
    this.name = 'ApiConfigurationError'
  }
}

/**
 * Transport boundary for the backend contract. Callers must supply a path and
 * response type from the project's API specification; this client defines no endpoints.
 */
export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  if (!appConfiguration.apiBaseUrl) throw new ApiConfigurationError()
  if (!path || path.startsWith('/')) {
    throw new Error('API paths must be supplied as contract-defined relative paths.')
  }

  const response = await fetch(`${appConfiguration.apiBaseUrl}/${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...init?.headers,
    },
  })

  if (!response.ok) {
    throw new Error(`Backend request failed with HTTP ${response.status}.`)
  }

  return (await response.json()) as T
}
