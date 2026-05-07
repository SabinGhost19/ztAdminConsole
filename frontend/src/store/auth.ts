import { defineStore } from 'pinia'

import { api } from '../api/axios'
import {
  bootstrapAuth,
  ensureFreshToken,
  getKeycloak,
  isBypass,
  login as kcLogin,
  logout as kcLogout,
} from '../auth/keycloak'

interface PermissionMatrix {
  groups: string[]
  permissions: string[]
  matrix: Record<string, string[]>
}

interface IdentityState {
  email: string
  subject: string
  preferred_username: string
  name: string
  groups: string[]
  permissions: string[]
  is_bypass: boolean
}

interface AuthStoreState {
  ready: boolean
  authenticated: boolean
  bypass: boolean
  identity: IdentityState | null
  matrix: PermissionMatrix | null
  initError: string | null
}

const EMPTY_IDENTITY: IdentityState = {
  email: '',
  subject: '',
  preferred_username: '',
  name: '',
  groups: [],
  permissions: [],
  is_bypass: false,
}

export const useAuthStore = defineStore('auth', {
  state: (): AuthStoreState => ({
    ready: false,
    authenticated: false,
    bypass: false,
    identity: null,
    matrix: null,
    initError: null,
  }),
  getters: {
    /**
     * Permission check. The frontend mirror of `Identity.can(p)`. The
     * matrix is the authoritative answer; if the matrix has not loaded
     * yet (race during bootstrap) we fall back to the identity payload.
     */
    can(state) {
      const known = new Set(state.identity?.permissions || [])
      return (permission: string): boolean => known.has(permission)
    },
    canAny(state) {
      const known = new Set(state.identity?.permissions || [])
      return (...permissions: string[]): boolean => permissions.some((p) => known.has(p))
    },
    canAll(state) {
      const known = new Set(state.identity?.permissions || [])
      return (...permissions: string[]): boolean => permissions.every((p) => known.has(p))
    },
    hasGroup(state) {
      const set = new Set(state.identity?.groups || [])
      return (...groups: string[]): boolean => groups.some((g) => set.has(g))
    },
    initials(state): string {
      const name = state.identity?.name || state.identity?.email || ''
      if (!name) return '?'
      return name
        .split(/[\s.@_-]+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((p) => p.charAt(0).toUpperCase())
        .join('')
    },
  },
  actions: {
    async bootstrap() {
      if (this.ready) return

      try {
        const result = await bootstrapAuth()
        this.bypass = result.bypass
        if (result.authenticated) {
          this.authenticated = true
          await this.loadIdentity()
        }
        await this.loadMatrix()
      } catch (err: any) {
        this.initError = err?.message || 'Authentication failed to initialise.'
      } finally {
        this.ready = true
      }
    },

    async loadIdentity() {
      try {
        const response = await api.get('/auth/me', { skipGlobalErrorAlert: true } as any)
        this.identity = { ...EMPTY_IDENTITY, ...(response.data?.identity || {}) }
      } catch (err: any) {
        // eslint-disable-next-line no-console
        console.error('[auth][store] Failed to load /auth/me', {
          status: err?.response?.status,
          backendCode: err?.response?.data?.error_code,
          backendMessage: err?.response?.data?.message,
          traceId: err?.response?.data?.trace_id,
          requestPath: err?.response?.data?.request_path,
        })
        this.identity = null
        this.authenticated = false
      }
    },

    async loadMatrix() {
      try {
        const response = await api.get('/auth/permissions', { skipGlobalErrorAlert: true } as any)
        this.matrix = {
          groups: response.data?.groups || [],
          permissions: response.data?.permissions || [],
          matrix: response.data?.matrix || {},
        }
      } catch {
        this.matrix = null
      }
    },

    async login() {
      if (this.bypass) return
      if (this.initError) {
        throw new Error(`Auth bootstrap failed before login: ${this.initError}`)
      }
      await kcLogin()
    },

    async logout() {
      if (this.bypass) return
      this.identity = null
      this.authenticated = false
      await kcLogout()
    },

    async refresh() {
      if (this.bypass) return
      const kc = getKeycloak()
      if (!kc) return
      await ensureFreshToken(30)
    },

    isPlatformOperator(): boolean {
      return (
        this.bypass ||
        this.hasGroup('platform-engineer') ||
        this.hasGroup('sre-oncall')
      )
    },

    isAuditor(): boolean {
      return this.bypass || this.hasGroup('security-auditor')
    },

    isDeveloper(): boolean {
      return this.bypass || this.hasGroup('developer')
    },

    /**
     * Re-export the bypass state explicitly so router guards don't have
     * to import the keycloak module directly.
     */
    inBypassMode(): boolean {
      return isBypass()
    },
  },
})
