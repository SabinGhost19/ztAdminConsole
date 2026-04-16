import { defineStore } from 'pinia'
import { api } from '../api/axios'

export interface JitSession {
  id: string;
  namespace: string;
  user: string;
  role: string;
  duration: number; // in minutes
  expiresAt: string; // ISO string
  status: 'ACTIVE' | 'APPROVED' | 'EXPIRED' | 'REVOKED' | 'PENDING' | 'DENIED';
  message?: string;
  sessionId?: string;
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
        this.sessions = response.data.map((crt: any) => ({
           id: crt.metadata?.name || crt.summary?.sessionId || 'jit-unknown',
           namespace: crt.metadata?.namespace || crt.summary?.targetNamespace || 'default',
           user: crt.summary?.developerId || crt.metadata?.annotations?.['jit.devsecops/user'] || 'Unknown',
           role: crt.summary?.requestedRole || 'view',
           duration: parseDurationMinutes(crt.summary?.duration),
           expiresAt: crt.summary?.expiresAt || new Date().toISOString(),
           status: normalizeStatus(crt.summary?.state),
           message: crt.summary?.message,
           sessionId: crt.summary?.sessionId,
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
        throw error;
      }
    }
  }
})

function parseDurationMinutes(duration: string | undefined) {
  if (!duration) return 0
  const normalized = String(duration).trim().toLowerCase()
  if (normalized.endsWith('m')) return Number.parseInt(normalized, 10) || 0
  if (normalized.endsWith('h')) return (Number.parseInt(normalized, 10) || 0) * 60
  return Number.parseInt(normalized, 10) || 0
}

function normalizeStatus(value: string | undefined): JitSession['status'] {
  const state = String(value || 'PENDING').toUpperCase()
  if (state === 'RUNNING') return 'ACTIVE'
  if (state === 'APPROVED') return 'APPROVED'
  if (state === 'ACTIVE') return 'ACTIVE'
  if (state === 'EXPIRED') return 'EXPIRED'
  if (state === 'REVOKED') return 'REVOKED'
  if (state.startsWith('DENIED') || state.startsWith('BLOCKED')) return 'DENIED'
  return 'PENDING'
}