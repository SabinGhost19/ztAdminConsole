import axios, { type InternalAxiosRequestConfig } from 'axios'

import { ensureFreshToken, getToken, isBypass } from '../../auth/keycloak'
import { useNotificationStore } from '../../store/notification'

type RequestMetadata = {
  traceId: string
  startedAt: number
}

type RequestConfigWithMetadata = InternalAxiosRequestConfig & {
  metadata?: RequestMetadata
  retry?: number
  authRetried?: boolean
  skipGlobalErrorAlert?: boolean
}

function createTraceId(prefix = 'REQ') {
  return `${prefix}-${Math.random().toString(36).substring(2)}-${Date.now().toString(36)}`
}

export const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use(async (config) => {
  const typedConfig = config as RequestConfigWithMetadata
  const traceId = createTraceId()
  typedConfig.headers = typedConfig.headers || {}
  typedConfig.headers['X-Request-ID'] = traceId

  // Inject Bearer token unless we are in bypass mode (local dev).
  if (!isBypass()) {
    try {
      await ensureFreshToken(30)
    } catch {
      // ignore - the response interceptor will catch the eventual 401
    }
    const token = getToken()
    if (token) {
      typedConfig.headers['Authorization'] = `Bearer ${token}`
    } else {
      // eslint-disable-next-line no-console
      console.warn('[auth][request] No Keycloak token available for request', {
        method: String(typedConfig.method || 'GET').toUpperCase(),
        url: typedConfig.url,
        traceId,
      })
    }
  }

  typedConfig.metadata = {
    traceId,
    startedAt: Date.now(),
  }
  return typedConfig
})

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const notifyStore = useNotificationStore()
    const { response } = error
    const config = error.config as RequestConfigWithMetadata | undefined
    if (config?.skipGlobalErrorAlert) {
      return Promise.reject(error)
    }
    const traceId = response?.data?.trace_id || config?.metadata?.traceId || createTraceId('ERR')
    const durationMs = config?.metadata?.startedAt ? Date.now() - config.metadata.startedAt : undefined

    if (config && typeof config.retry !== 'number') {
      config.retry = 0
    }
    const retryCount = config?.retry ?? 0

    // 401: try a token refresh once before giving up. This handles the
    // race where the JWT just expired between two API calls.
    if (response?.status === 401 && config && !config.authRetried && !isBypass()) {
      // eslint-disable-next-line no-console
      console.warn('[auth][response] 401 received, attempting one token refresh retry', {
        url: config?.url,
        method: String(config?.method || 'GET').toUpperCase(),
        traceId,
        backendMessage: response?.data?.message,
        backendCode: response?.data?.error_code,
      })
      config.authRetried = true
      try {
        await ensureFreshToken(0)
        const token = getToken()
        if (token) {
          config.headers = config.headers || {}
          config.headers['Authorization'] = `Bearer ${token}`
          return api(config)
        }
        // eslint-disable-next-line no-console
        console.error('[auth][response] Refresh succeeded but token still missing', {
          url: config?.url,
          method: String(config?.method || 'GET').toUpperCase(),
          traceId,
        })
      } catch {
        // eslint-disable-next-line no-console
        console.error('[auth][response] Token refresh failed after 401', {
          url: config?.url,
          method: String(config?.method || 'GET').toUpperCase(),
          traceId,
        })
      }
    }

    if (config && retryCount < 3 && (!response || (response.status >= 502 && response.status <= 504))) {
      const nextRetryCount = retryCount + 1
      config.retry = nextRetryCount
      notifyStore.addAlert({
        error_code: 'NETWORK_RETRY_INITIATED',
        message: 'Conexiune instabilă, reîncercare comunicare...',
        technical_details: `Retry timeout: ${nextRetryCount} at attempt. Request: ${String(config?.method || 'GET').toUpperCase()} ${config?.url || 'unknown-url'}`,
        component: 'FRONTEND_RESILIENCE',
        trace_id: traceId,
        action_required: 'Așteptați rezolvarea automată.',
        request_method: String(config?.method || 'GET').toUpperCase(),
        request_path: config?.url,
        timestamp: new Date().toISOString(),
        source: 'network',
        details: durationMs ? { durationMs } : null,
        type: 'warning',
      })
      const backoff = new Promise((resolve) => setTimeout(resolve, 2 ** (nextRetryCount - 1) * 1000))
      await backoff
      return api(config)
    }

    if (error.response && error.response.data) {
      const data = error.response.data

      notifyStore.addAlert({
        error_code: data.error_code || (response?.status === 403 ? 'FORBIDDEN' : 'UNKNOWN_ERROR'),
        message: data.message || (response?.status === 403
          ? 'Nu ai permisiunile necesare pentru această acțiune.'
          : 'S-a produs o eroare neașteptată în comunicarea cu backend-ul.'),
        technical_details: data.technical_details || (typeof data.detail === 'object' ? JSON.stringify(data.detail) : data.detail) || error.message,
        component: data.component || 'FRONTEND_AXIOS',
        trace_id: traceId,
        action_required: data.action_required || (response?.status === 403
          ? 'Solicită aprobare către un platform-engineer sau security-auditor.'
          : 'Verificați logurile sau contactați SecOps.'),
        status_code: data.status_code || error.response.status,
        request_method: data.request_method || String(config?.method || 'GET').toUpperCase(),
        request_path: data.request_path || config?.url,
        timestamp: data.timestamp || new Date().toISOString(),
        source: 'backend',
        details: data.details || data.detail || (durationMs ? { durationMs } : null),
        type: error.response.status >= 500 ? 'warning' : 'error',
      })
    } else {
      notifyStore.addAlert({
        error_code: 'CRITICAL_NETWORK_FAILURE',
        message: 'Sistem indisponibil. Lanțul de încredere a eșuat la conexiunea cu API-ul din cluster.',
        technical_details: error.message,
        component: 'FRONTEND_CONNECTION',
        trace_id: traceId,
        action_required: 'Verificați dacă FastAPI Backend Rulează în cluster!',
        request_method: String(config?.method || 'GET').toUpperCase(),
        request_path: config?.url,
        timestamp: new Date().toISOString(),
        source: 'network',
        details: durationMs ? { durationMs } : null,
        type: 'error',
      })
    }

    return Promise.reject(error)
  },
)
