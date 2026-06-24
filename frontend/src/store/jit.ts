import { defineStore } from 'pinia'
import { api } from '../api/axios'

export interface JitSession {
  id: string;
  namespace: string;
  user: string;
  role: string;
  duration: number;
  expiresAt: string;
  status: 'ACTIVE' | 'APPROVED' | 'EXPIRED' | 'REVOKED' | 'PENDING' | 'PENDING_APPROVAL' | 'DENIED' | 'TAMPERED';
  message?: string;
  sessionId?: string;
  temporaryToken?: string;
  commandToUse?: string;
  tokenIssued?: boolean;
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
        this.sessions = response.data.map(mapSession);
      } catch (error) {
        console.error('Fetch sessions failed', error);
      } finally {
        this.isLoading = false;
      }
    },
    
    async requestAccess(data: { namespace: string, role: string, duration: number, reason?: string }) {
      this.isSubmitting = true;
      try {
        await api.post('/jit/request', data);
      } catch (error) {
        console.error('Request failed', error);
        throw error;
      } finally {
        this.isSubmitting = false;
      }
    },

    async fetchMySessions() {
      this.isLoading = true;
      try {
        const response = await api.get('/jit/my-requests');
        this.sessions = response.data.map(mapSession);
      } catch (error) {
        console.error('Fetch my sessions failed', error);
      } finally {
        this.isLoading = false;
      }
    },

    async revokeSession(namespace: string, name: string) {
      try {
        await api.delete(`/jit/revoke/${namespace}/${name}`);
      } catch (error) {
        console.error('Revoke failed', error);
        throw error;
      }
    },

    async dismissSession(namespace: string, name: string) {
      try {
        await api.delete(`/jit/request/${namespace}/${name}`);
      } catch (error) {
        console.error('Dismiss failed', error);
        throw error;
      }
    },

    async approveSession(namespace: string, name: string) {
      try {
        await api.post(`/jit/request/${namespace}/${name}/approve`);
      } catch (error) {
        console.error('Approve failed', error);
        throw error;
      }
    },

    applySnapshot(raw: any[]) {
      this.sessions = (raw || []).map(mapSession);
    }
  }
})

function mapSession(crt: any): JitSession {
  return {
    id: crt.metadata?.name || crt.summary?.sessionId || 'jit-unknown',
    namespace: crt.metadata?.namespace || crt.summary?.targetNamespace || 'default',
    user: (crt.summary?.developerId || '').trim() || (crt.metadata?.annotations?.['jit.devsecops/user'] || '').trim() || crt.metadata?.name || 'Unknown',
    role: crt.summary?.requestedRole || 'view',
    duration: parseDurationMinutes(crt.summary?.duration),
    expiresAt: crt.summary?.expiresAt || new Date().toISOString(),
    status: normalizeStatus(crt.summary?.state),
    message: crt.summary?.message,
    sessionId: crt.summary?.sessionId,
    temporaryToken: crt.summary?.temporaryToken,
    commandToUse: crt.summary?.commandToUse,
    tokenIssued: crt.summary?.tokenIssued === true,
  }
}

function parseDurationMinutes(duration: string | undefined) {
  if (!duration) return 0
  const normalized = String(duration).trim().toLowerCase()
  if (normalized.endsWith('m')) return Number.parseInt(normalized, 10) || 0
  if (normalized.endsWith('h')) return (Number.parseInt(normalized, 10) || 0) * 60
  return Number.parseInt(normalized, 10) || 0
}

function normalizeStatus(value: string | undefined): JitSession['status'] {
  const state = String(value || 'PENDING').toUpperCase()
  if (state === 'RUNNING' || state === 'ACTIVE') return 'ACTIVE'
  if (state === 'APPROVED') return 'APPROVED'
  if (state === 'PENDING_APPROVAL') return 'PENDING_APPROVAL'
  if (state === 'EXPIRED') return 'EXPIRED'
  if (state === 'REVOKED' || state === 'TAMPERED') return 'REVOKED'
  // Anti-abuse rejections: coarse CRD enum (RATE_LIMITED/QUOTA_EXCEEDED/REJECTED) plus the
  // legacy granular DENIED_*/BLOCKED_* codes. All collapse to the 'DENIED' UI bucket so the
  // color/icon/filters already keyed off 'DENIED' keep working.
  if (
    state.startsWith('DENIED') ||
    state.startsWith('BLOCKED') ||
    state === 'RATE_LIMITED' ||
    state === 'QUOTA_EXCEEDED' ||
    state === 'REJECTED'
  ) return 'DENIED'
  return 'PENDING'
}