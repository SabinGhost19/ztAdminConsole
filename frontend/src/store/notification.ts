import { defineStore } from 'pinia'

export interface AppError {
  id: string;
  error_code: string;
  message: string;
  technical_details: string;
  component: string;
  trace_id: string;
  action_required: string;
  type: 'error' | 'warning';
}

export const useNotificationStore = defineStore('notification', {
  state: () => ({
    alerts: [] as AppError[]
  }),
  actions: {
    addAlert(errorData: Omit<AppError, 'id'>) {
      const id = Math.random().toString(36).substring(2, 9);
      this.alerts.push({ ...errorData, id });
      
      // Auto-dismiss warnings after 5s
      if (errorData.type === 'warning') {
        setTimeout(() => this.removeAlert(id), 5000);
      }
    },
    removeAlert(id: string) {
      this.alerts = this.alerts.filter(a => a.id !== id);
    }
  }
})