import { defineStore } from 'pinia'
import { api } from '../api/axios'

type AnyRecord = Record<string, any>

export const useDashboardStore = defineStore('dashboard', {
  state: () => ({
    overview: null as AnyRecord | null,
    loadingOverview: false,
    jitAnalytics: null as AnyRecord | null,
    applications: [] as AnyRecord[],
    loadingApplications: false,
    secrets: [] as AnyRecord[],
    loadingSecrets: false,
    policies: [] as AnyRecord[],
    loadingPolicies: false,
    driftItems: [] as AnyRecord[],
    loadingDrift: false,
    loadingIntegrity: false,
    integrityCache: {} as Record<string, AnyRecord>,
  }),
  getters: {
    summary(state) {
      return state.overview?.summary || {
        applications: 0,
        verifiedApplications: 0,
        degradedApplications: 0,
        secretBindings: 0,
        supplyChainPolicies: 0,
        jitRequests: 0,
      }
    },
    trustScore(state) {
      return state.overview?.trustScore || {
        value: 0,
        verified: 0,
        total: 0,
        distribution: {},
      }
    },
    operatorHealth(state) {
      return state.overview?.operatorHealth || []
    },
    recentEvents(state) {
      return state.overview?.recentEvents || []
    },
    applicationOptions(state) {
      return state.applications.map((item) => ({
        title: `${item.metadata?.namespace || 'default'}/${item.metadata?.name || 'unknown'}`,
        value: `${item.metadata?.namespace || 'default'}/${item.metadata?.name || 'unknown'}`,
      }))
    },
    secretOptions(state) {
      return state.secrets.map((item) => ({
        title: `${item.metadata?.namespace || 'default'}/${item.metadata?.name || 'unknown'}`,
        value: `${item.metadata?.namespace || 'default'}/${item.metadata?.name || 'unknown'}`,
      }))
    },
    policyOptions(state) {
      return state.policies.map((item) => ({
        title: item.metadata?.name || 'unknown',
        value: item.metadata?.name || 'unknown',
      }))
    },
    driftOptions(state) {
      return state.driftItems.map((item, index) => ({
        title: `${item.namespace}/${item.name}`,
        value: index,
      }))
    },
  },
  actions: {
    async fetchOverview(force = false) {
      if (this.overview && !force) {
        return this.overview
      }

      this.loadingOverview = true
      try {
        const response = await api.get('/overview/')
        this.overview = response.data
        try {
          const jitAnalyticsResponse = await api.get('/jit/analytics')
          this.jitAnalytics = jitAnalyticsResponse.data
        } catch {
          this.jitAnalytics = null
        }
        return response.data
      } finally {
        this.loadingOverview = false
      }
    },
    async fetchApplications(force = false) {
      if (this.applications.length && !force) {
        return this.applications
      }

      this.loadingApplications = true
      try {
        const response = await api.get('/zta/')
        this.applications = response.data
        return response.data
      } finally {
        this.loadingApplications = false
      }
    },
    async fetchSecrets(force = false) {
      if (this.secrets.length && !force) {
        return this.secrets
      }

      this.loadingSecrets = true
      try {
        const response = await api.get('/zts/')
        this.secrets = response.data
        return response.data
      } finally {
        this.loadingSecrets = false
      }
    },
    async fetchPolicies(force = false) {
      if (this.policies.length && !force) {
        return this.policies
      }

      this.loadingPolicies = true
      try {
        const response = await api.get('/sca/')
        this.policies = response.data
        return response.data
      } finally {
        this.loadingPolicies = false
      }
    },
    async fetchDrift(force = false) {
      if (this.driftItems.length && !force) {
        return this.driftItems
      }

      this.loadingDrift = true
      try {
        const response = await api.get('/drift/')
        this.driftItems = response.data
        return response.data
      } finally {
        this.loadingDrift = false
      }
    },
    async fetchIntegrity(namespace: string, name: string, force = false) {
      const key = `${namespace}/${name}`
      if (this.integrityCache[key] && !force) {
        return this.integrityCache[key]
      }

      this.loadingIntegrity = true
      try {
        const response = await api.get(`/integrity/applications/${namespace}/${name}`)
        this.integrityCache[key] = response.data
        return response.data
      } finally {
        this.loadingIntegrity = false
      }
    },
    setIntegrity(namespace: string, name: string, payload: AnyRecord) {
      this.integrityCache[`${namespace}/${name}`] = payload
    },
  },
})