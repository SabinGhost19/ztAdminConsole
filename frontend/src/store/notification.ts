import { defineStore } from 'pinia'

export interface AppError {
  id: string;
  error_code: string;
  message: string;
  technical_details: string;
  component: string;
  trace_id: string;
  action_required: string;
  timestamp?: string;
  status_code?: number;
  request_method?: string;
  request_path?: string;
  source?: 'backend' | 'frontend' | 'network';
  details?: Record<string, any> | null;
  type: 'error' | 'warning';
}

export const useNotificationStore = defineStore('notification', {
  state: () => ({
    alerts: [] as AppError[],
    history: [] as AppError[],
  }),
  actions: {
    addAlert(errorData: Omit<AppError, 'id'>) {
      const id = Math.random().toString(36).substring(2, 9);
      const alert = { ...errorData, id };
      this.alerts.unshift(alert);
      this.history.unshift(alert);
      this.history = this.history.slice(0, 200);
      
      // Auto-dismiss warnings after 5s
      if (errorData.type === 'warning') {
        setTimeout(() => this.removeAlert(id), 5000);
      }
    },
    removeAlert(id: string) {
      this.alerts = this.alerts.filter(a => a.id !== id);
    },
    clearAlerts() {
      this.alerts = [];
    },
    clearHistory() {
      this.history = [];
    }
  }
})