import { onBeforeUnmount, ref } from 'vue'
import { ensureFreshToken, getToken } from '../auth/keycloak'

export interface KopfEvent {
  uid: string
  name: string
  namespace: string
  resourceVersion: string
  involvedKind: string
  involvedName: string
  reason: string
  message: string
  type: string
  count: number
  firstTimestamp: string
  lastTimestamp: string
  eventTime: string
  sourceComponent: string
}

export interface IntegrityStreamError {
  code: string
  message: string
  recoverable: boolean
  details?: Record<string, any>
}

export interface UseIntegrityStreamOptions {
  onSnapshot: (payload: any) => void
  onEvents: (events: KopfEvent[]) => void
  /** Receives a structured error frame (`integrity.error` SSE events).
   *  Replaces the old free-text `onError(message)` signature. */
  onError?: (error: IntegrityStreamError) => void
  onFallback?: () => void
}

/**
 * Subscribe to the integrity SSE stream. Browsers can't set headers on
 * EventSource, so the bearer token rides as `?access_token=`. Falls back
 * gracefully when the connection drops more than 3 times in a row, so the
 * caller can resume polling.
 */
export function useIntegrityStream(options: UseIntegrityStreamOptions) {
  const eventSource = ref<EventSource | null>(null)
  const isConnected = ref(false)
  let consecutiveErrors = 0
  let stopped = false

  async function start(namespace: string, name: string) {
    stop()
    stopped = false
    await ensureFreshToken(30).catch(() => undefined)
    const token = getToken() || ''
    const url = `/api/v1/integrity/applications/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/stream${
      token ? `?access_token=${encodeURIComponent(token)}` : ''
    }`
    const es = new EventSource(url)
    eventSource.value = es

    es.addEventListener('integrity.snapshot', (ev) => {
      consecutiveErrors = 0
      isConnected.value = true
      try { options.onSnapshot(JSON.parse((ev as MessageEvent).data)) } catch { /* ignore */ }
    })
    es.addEventListener('event.kopf', (ev) => {
      try { options.onEvents(JSON.parse((ev as MessageEvent).data) as KopfEvent[]) } catch { /* ignore */ }
    })
    es.addEventListener('integrity.error', (ev) => {
      try {
        const data = JSON.parse((ev as MessageEvent).data) || {}
        const err: IntegrityStreamError = {
          code: String(data.code || 'unknown'),
          message: String(data.message || 'integrity stream error'),
          recoverable: data.recoverable !== false,
          details: data.details,
        }
        options.onError?.(err)
        if (!err.recoverable && !stopped) {
          stop()
          options.onFallback?.()
        }
      } catch {
        options.onError?.({ code: 'parse-error', message: 'integrity error frame could not be parsed', recoverable: true })
      }
    })
    es.onerror = () => {
      isConnected.value = false
      consecutiveErrors += 1
      if (consecutiveErrors >= 3 && !stopped) {
        stop()
        options.onError?.({
          code: 'transport-error',
          message: 'SSE connection lost after 3 consecutive failures; switching to polling.',
          recoverable: true,
        })
        options.onFallback?.()
      }
    }
  }

  function stop() {
    if (eventSource.value) {
      eventSource.value.close()
      eventSource.value = null
    }
    isConnected.value = false
    stopped = true
  }

  onBeforeUnmount(() => stop())

  return { start, stop, isConnected }
}
