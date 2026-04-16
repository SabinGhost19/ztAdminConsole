import axios, { type InternalAxiosRequestConfig } from 'axios'
import { useNotificationStore } from '../../store/notification'

type RequestMetadata = {
  traceId: string
  startedAt: number
}

type RequestConfigWithMetadata = InternalAxiosRequestConfig & {
  metadata?: RequestMetadata
  retry?: number
}

function createTraceId(prefix = 'REQ') {
  return `${prefix}-${Math.random().toString(36).substring(2)}-${Date.now().toString(36)}`
}

export const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    // Simulăm Keycloak / Identity Proxy header, care e obligatoriu acum de backend
    'X-Forwarded-Email': 'devsecops@admin.local',
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const typedConfig = config as RequestConfigWithMetadata
  const traceId = createTraceId()
  typedConfig.headers = typedConfig.headers || {}
  typedConfig.headers['X-Request-ID'] = traceId
  typedConfig.metadata = {
    traceId,
    startedAt: Date.now(),
  }
  return typedConfig
})

// Retry mechanism pt erorile de tip 502/503/504
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const notifyStore = useNotificationStore()
    const { response } = error;
    const config = error.config as RequestConfigWithMetadata | undefined
    const traceId = response?.data?.trace_id || config?.metadata?.traceId || createTraceId('ERR')
    const durationMs = config?.metadata?.startedAt ? Date.now() - config.metadata.startedAt : undefined
    
    if (config && typeof config.retry !== 'number') {
      config.retry = 0;
    }
    const retryCount = config?.retry ?? 0

    if (config && retryCount < 3 && (!response || (response.status >= 502 && response.status <= 504))) {
      const nextRetryCount = retryCount + 1
      config.retry = nextRetryCount;
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
        type: 'warning'
      })
      const backoff = new Promise(resolve => setTimeout(resolve, nextRetryCount * 1000));
      await backoff;
      return api(config);
    }
    
    if (error.response && error.response.data) {
      const data = error.response.data
      
      notifyStore.addAlert({
        error_code: data.error_code || 'UNKNOWN_ERROR',
        message: data.message || 'S-a produs o eroare neașteptată în comunicarea cu backend-ul.',
        technical_details: data.technical_details || error.message,
        component: data.component || 'FRONTEND_AXIOS',
        trace_id: traceId,
        action_required: data.action_required || 'Verificați logurile sau contactați SecOps.',
        status_code: data.status_code || error.response.status,
        request_method: data.request_method || String(config?.method || 'GET').toUpperCase(),
        request_path: data.request_path || config?.url,
        timestamp: data.timestamp || new Date().toISOString(),
        source: 'backend',
        details: data.details || (durationMs ? { durationMs } : null),
        type: error.response.status >= 500 ? 'warning' : 'error'
      })
    } else {
      // Eroare Critical Fatal (Backend Total Offline)
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
        type: 'error'
      })
    }

    return Promise.reject(error)
  }
)

