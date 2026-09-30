import { appConfiguration } from './configuration'

export type EventStreamState = 'disconnected' | 'live' | 'error'

/** Opens only the explicitly configured SSE URL; event names and payloads remain backend-defined. */
export function connectEventStream(
  onState: (state: EventStreamState) => void,
  onMessage: (event: MessageEvent<string>) => void,
): EventSource | undefined {
  if (!appConfiguration.eventStreamUrl) {
    onState('disconnected')
    return undefined
  }

  const source = new EventSource(appConfiguration.eventStreamUrl)
  source.onopen = () => onState('live')
  source.onerror = () => onState('error')
  source.onmessage = onMessage
  return source
}
