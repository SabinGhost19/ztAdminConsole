import axios from 'axios'
import { useNotificationStore } from '../../store/notification'

export const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    // Simulăm Keycloak / Identity Proxy header, care e obligatoriu acum de backend
    'X-Forwarded-Email': 'devsecops@admin.local',
    'Content-Type': 'application/json',
  },
})

// Retry mechanism pt erorile de tip 502/503/504
api.interceptors.response.use(
  undefined,
  async (error) => {
    const notifyStore = useNotificationStore()
    const { config, message, response } = error;
    
    if (!config || !config.retry) {
      config.retry = 0;
    }

    if (config.retry < 3 && (!response || (response.status >= 502 && response.status <= 504))) {
      config.retry += 1;
      notifyStore.addAlert({
        error_code: 'NETWORK_RETRY_INITIATED',
        message: 'Conexiune instabilă, reîncercare comunicare...',
        technical_details: `Retry timeout: ${config.retry} at attempt`,
        component: 'FRONTEND_RESILIENCE',
        trace_id: `NET-${Math.random().toString(36).substring(2)}`,
        action_required: 'Așteptați rezolvarea automată.',
        type: 'warning'
      })
      const backoff = new Promise(resolve => setTimeout(resolve, config.retry * 1000));
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
        trace_id: data.trace_id || `FE-${Math.random().toString(36).substring(2)}`,
        action_required: data.action_required || 'Verificați logurile sau contactați SecOps.',
        type: error.response.status >= 500 ? 'warning' : 'error' // 403 Forbidden = roșu persistent
      })
    } else {
      // Eroare Critical Fatal (Backend Total Offline)
      notifyStore.addAlert({
        error_code: 'CRITICAL_NETWORK_FAILURE',
        message: 'Sistem indisponibil. Lanțul de încredere a eșuat la conexiunea cu API-ul din cluster.',
        technical_details: error.message,
        component: 'FRONTEND_CONNECTION',
        trace_id: `ERR-${Math.random().toString(36).substring(2)}`,
        action_required: 'Verificați dacă FastAPI Backend Rulează în cluster!',
        type: 'error'
      })
    }

    return Promise.reject(error)
  }
)

