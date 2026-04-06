import { defineStore } from 'pinia'
import { api } from '../api/axios'

export interface JitSession {
  id: string;
  user: string;
  namespace: string;
  role: string;
  duration: number; // in minutes
  expiresAt: string; // ISO string
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'PENDING';
}

export const useJitStore = defineStore('jit', {
  state: () => ({
    sessions: [] as JitSession[],
    isLoading: false,
    isSubmitting: false,
  }),
  actions: {
    async fetchSessions() {
      this.isLoading = true;
      try {
        const response = await api.get('/jit/sessions');
        
        // Pydantic/K8s CRD map mapping to the UI format 
        // using the Custom Objects API output from FastAPI Backend.
        this.sessions = response.data.map((crt: any) => ({
           id: crt.metadata.name,
           user: crt.metadata.annotations?.['jit.devsecops/user'] || 'Unknown',
           namespace: crt.spec.targetNamespace,
           role: crt.spec.role,
           duration: crt.spec.durationMinutes,
           expiresAt: crt.status?.expiresAt || new Date(Date.now() + crt.spec.durationMinutes * 60000).toISOString(),
           status: crt.status?.state || 'PENDING'
        }));
      } catch (error) {
        console.error('Fetch sessions failed', error);
      } finally {
        this.isLoading = false;
      }
    },
    
    async requestAccess(data: { namespace: string, role: string, duration: number }) {
      this.isSubmitting = true;
      try {
        await api.post('/jit/request', data);
        await this.fetchSessions();
      } catch (error) {
        console.error('Request failed', error);
        throw error;
      } finally {
        this.isSubmitting = false;
      }
    },

    async revokeSession(namespace: string, name: string) {
      try {
        await api.delete(`/jit/revoke/${namespace}/${name}`);
        await this.fetchSessions();
      } catch (error) {
        console.error('Revoke failed', error);
      }
    }
  }
})