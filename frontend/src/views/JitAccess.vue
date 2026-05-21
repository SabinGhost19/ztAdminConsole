<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api/axios'
import { useJitStore, JitSession } from '../store/jit'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'
import { useAuthStore } from '../store/auth'
import { ensureFreshToken, getToken, isBypass } from '../auth/keycloak'

const jitStore = useJitStore()
const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()
const auth = useAuthStore()

const canApprove = computed(() => auth.can('jit:approve'))
const canRevoke = computed(() => auth.can('jit:revoke'))
const canRequest = computed(() => auth.can('jit:request'))
const canWritePolicy = computed(() => auth.can('jit:policy:write'))
const canReadAll = computed(() => auth.can('jit:read'))
const canReadLimited = computed(() => auth.can('jit:read-limited'))

const sessions = computed(() => jitStore.sessions)
const isLoading = computed(() => jitStore.isLoading)
const isSubmitting = computed(() => jitStore.isSubmitting)
const pendingCount = computed(() => jitStore.sessions.filter(s => s.status === 'PENDING_APPROVAL' || s.status === 'PENDING').length)

type SessionFilter = 'all' | 'pending' | 'active' | 'expired'
const sessionFilter = ref<SessionFilter>('all')

function sessionTimestamp(sess: JitSession): number {
  // Use expiresAt when present; otherwise fall back to 0 so unknown sorts last.
  const t = sess.expiresAt ? new Date(sess.expiresAt).getTime() : 0
  return Number.isNaN(t) ? 0 : t
}

const visibleSessions = computed<JitSession[]>(() => {
  const list = [...jitStore.sessions]
  const filtered = list.filter(s => {
    if (sessionFilter.value === 'all') return true
    if (sessionFilter.value === 'pending') return s.status === 'PENDING_APPROVAL' || s.status === 'PENDING'
    if (sessionFilter.value === 'active') return s.status === 'ACTIVE' || s.status === 'APPROVED'
    if (sessionFilter.value === 'expired') return s.status === 'EXPIRED' || s.status === 'REVOKED' || s.status === 'TAMPERED' || s.status.startsWith('DENIED')
    return true
  })
  // Most-recent-first by expiresAt; pending sessions float to top so they aren't lost.
  return filtered.sort((a, b) => {
    const aPending = a.status === 'PENDING_APPROVAL' || a.status === 'PENDING' ? 1 : 0
    const bPending = b.status === 'PENDING_APPROVAL' || b.status === 'PENDING' ? 1 : 0
    if (aPending !== bPending) return bPending - aPending
    return sessionTimestamp(b) - sessionTimestamp(a)
  })
})

function liveTimeLeft(expiresAt?: string): string {
  if (!expiresAt) return ''
  const diff = new Date(expiresAt).getTime() - now.value
  if (diff <= 0) return '00:00'
  const h = Math.floor(diff / 3600000).toString().padStart(2, '0')
  const m = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0')
  const s = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0')
  return parseInt(h) > 0 ? `${h}:${m}:${s}` : `${m}:${s}`
}

const generatedCommand = ref('')
const copySuccess = ref(false)
const selectedSessionId = ref<string | null>(null)

const selectedSession = computed<JitSession | null>(() => {
  if (!selectedSessionId.value) return null
  return jitStore.sessions.find(s => s.id === selectedSessionId.value) || null
})

const tokenPanel = computed(() => {
  const sess = selectedSession.value
  if (!sess) {
    return generatedCommand.value
      ? { kind: 'legacy' as const, body: generatedCommand.value, status: '' }
      : null
  }
  if (sess.status === 'PENDING_APPROVAL') {
    return { kind: 'pending' as const, body: '# Awaiting platform approval. Token will appear here as soon as the request is approved.', status: sess.status }
  }
  if (sess.status === 'PENDING') {
    return { kind: 'provisioning' as const, body: '# Provisioning… operator is issuing the token.', status: sess.status }
  }
  if (sess.status === 'ACTIVE' || sess.status === 'APPROVED') {
    if (isTokenUsable(sess) && sess.commandToUse) {
      return { kind: 'ready' as const, body: sess.commandToUse, status: sess.status }
    }
    if (sess.expiresAt && new Date(sess.expiresAt).getTime() <= now.value) {
      return { kind: 'gone' as const, body: '# Token expired. Request a new JIT session.', status: sess.status }
    }
    return { kind: 'provisioning' as const, body: '# Approved. Waiting for operator to publish the token…', status: sess.status }
  }
  if (sess.status === 'EXPIRED' || sess.status === 'REVOKED') {
    return { kind: 'gone' as const, body: '# Session terminated. Token is no longer valid.', status: sess.status }
  }
  return { kind: 'denied' as const, body: `# Request ${sess.status.toLowerCase()} — no token issued.`, status: sess.status }
})

function selectSession(sessionId: string) {
  selectedSessionId.value = sessionId
  copySuccess.value = false
}

async function dismissSession(session: any) {
  try {
    await jitStore.dismissSession(session.namespace || session.app_name, session.session_id)
    if (selectedSessionId.value === session.session_id) {
      selectedSessionId.value = null
    }
    notifyStore.addAlert({
      error_code: 'JIT_DISMISSED',
      message: `Session ${session.session_id} dismissed from the list.`,
      technical_details: 'The CRD has been removed from the cluster.',
      component: 'JIT_MODULE',
      trace_id: Math.random().toString(36).substring(2),
      action_required: '',
      type: 'warning'
    })
  } catch (err) {
    console.error('Dismiss failed', err)
  }
}
const jitAnalytics = ref<any | null>(null)
const jitPolicies = ref<any | null>(null)
const isLoadingPolicies = ref(false)
const isSavingPolicies = ref(false)

const policyForm = ref({
  blockedUsers: [] as string[],
  maxActiveSessions: 1,
  cooldownMinutes: 15,
  maxRequestsPerDay: 5,
  maxDurationMinutes: 120,
})

const iamUsers = ref<{ id?: string; email?: string; username?: string; firstName?: string; lastName?: string }[]>([])
const isLoadingIamUsers = ref(false)

const iamUserOptions = computed(() => {
  const seen = new Set<string>()
  const out: { title: string; subtitle: string; value: string }[] = []
  // Real Keycloak users
  for (const u of iamUsers.value) {
    const id = (u.email || u.username || '').trim()
    if (!id || seen.has(id.toLowerCase())) continue
    seen.add(id.toLowerCase())
    const name = [u.firstName, u.lastName].filter(Boolean).join(' ').trim() || u.username || id
    out.push({ title: name, subtitle: id, value: id })
  }
  // Surface identities already seen acting in JIT requests (in case Keycloak list omits them)
  for (const sess of jitStore.sessions) {
    const id = (sess.user || '').trim()
    if (!id || id.toLowerCase() === 'unknown' || seen.has(id.toLowerCase())) continue
    seen.add(id.toLowerCase())
    out.push({ title: id, subtitle: 'from JIT activity', value: id })
  }
  // Make sure already-blocked entries that aren't in either list still render as chips
  for (const id of policyForm.value.blockedUsers) {
    if (!id || seen.has(id.toLowerCase())) continue
    seen.add(id.toLowerCase())
    out.push({ title: id, subtitle: 'manual entry', value: id })
  }
  return out.sort((a, b) => a.title.localeCompare(b.title))
})

async function loadIamUsers() {
  if (!auth.can('iam:read')) return
  isLoadingIamUsers.value = true
  try {
    const response = await api.get('/jit/iam/users')
    iamUsers.value = response.data?.users || []
  } catch (err) {
    console.error('Failed to load IAM users', err)
  } finally {
    isLoadingIamUsers.value = false
  }
}

const form = ref({
  namespace: 'default',
  role: 'view',
  duration: 60,  // minimum 10 — K8s TokenRequest requires >= 600s
  reason: ''
})

const roles = ['view', 'edit', 'admin']

const activeTab = ref('k8s')
const webApps = ref<any[]>([])
const isLoadingWebApps = ref(false)
const k8sNamespaces = ref<string[]>(['default'])
const isLoadingNamespaces = ref(false)

const webForm = ref({
  appName: '',
  duration: 60,
  reason: ''
})

const isConfirmRevokeOpen = ref(false)
const sessionToRevoke = ref<JitSession | null>(null)
const isRevoking = ref(false)

// Phase 5: JIT Sessions State Management
const jitSessionStats = ref<any | null>(null)
const isLoadingSessions = ref(false)

let timerId: ReturnType<typeof setInterval>
let eventSource: EventSource | null = null
const now = ref(Date.now())

function applyStreamSnapshot(items: any[]) {
  jitStore.applySnapshot(items)
  const s = jitStore.sessions
  jitSessionStats.value = {
    total_sessions: s.length,
    pending: s.filter(x => x.status === 'PENDING' || x.status === 'PENDING_APPROVAL').length,
    active: s.filter(x => x.status === 'ACTIVE' || x.status === 'APPROVED').length,
    expired: s.filter(x => x.status === 'EXPIRED' || x.status === 'REVOKED' || x.status === 'TAMPERED').length,
  }
  // Auto-select the most recently active session when nothing is selected yet,
  // so the token panel surfaces the fresh token without forcing a click.
  if (!selectedSessionId.value) {
    const freshActive = s.find(x => (x.status === 'ACTIVE' || x.status === 'APPROVED') && x.tokenIssued)
    if (freshActive) selectedSessionId.value = freshActive.id
  } else if (!s.find(x => x.id === selectedSessionId.value)) {
    // Selected session was deleted upstream; clear selection
    selectedSessionId.value = null
  }
}

async function startEventStream() {
  if (eventSource) return
  try {
    const base = (api.defaults.baseURL || '').replace(/\/$/, '')
    let url = `${base}/jit/stream`
    if (!isBypass()) {
      try { await ensureFreshToken(60) } catch { /* ignore */ }
      const token = getToken()
      if (token) url += `?access_token=${encodeURIComponent(token)}`
    }
    eventSource = new EventSource(url, { withCredentials: true })
    eventSource.addEventListener('jit.snapshot', (ev: MessageEvent) => {
      try {
        const items = JSON.parse(ev.data)
        applyStreamSnapshot(items)
      } catch (err) {
        console.warn('Bad SSE payload', err)
      }
    })
    eventSource.addEventListener('jit.error', (ev: MessageEvent) => {
      console.warn('JIT stream error', ev.data)
    })
    eventSource.onerror = () => {
      // Browser will auto-reconnect. If permanently failing, fall back to manual fetch.
      console.warn('SSE connection error; will auto-reconnect.')
    }
  } catch (err) {
    console.error('Failed to open SSE', err)
  }
}

function stopEventStream() {
  if (eventSource) {
    eventSource.close()
    eventSource = null
  }
}

async function approveSession(session: any) {
  try {
    await jitStore.approveSession(session.namespace || session.app_name, session.session_id)
    notifyStore.addAlert({
      error_code: 'JIT_APPROVED',
      message: `Request ${session.session_id} approved.`,
      technical_details: `The operator will issue the token in a few seconds.`,
      component: 'JIT_OPERATOR',
      trace_id: Math.random().toString(36).substring(2),
      action_required: '',
      type: 'warning'
    })
  } catch (err) {
    console.error('Approve failed', err)
  }
}

async function fetchJitSessions() {
  isLoadingSessions.value = true
  try {
    if (canReadAll.value || canReadLimited.value) {
      await jitStore.fetchSessions()
    } else {
      await jitStore.fetchMySessions()
    }
    // Stats derived from CRD sessions
    const s = jitStore.sessions
    jitSessionStats.value = {
      total_sessions: s.length,
      pending: s.filter(x => x.status === 'PENDING' || x.status === 'PENDING_APPROVAL').length,
      active: s.filter(x => x.status === 'ACTIVE' || x.status === 'APPROVED').length,
      expired: s.filter(x => x.status === 'EXPIRED' || x.status === 'REVOKED' || x.status === 'TAMPERED').length,
    }
  } catch (err) {
    console.error('Failed to fetch JIT sessions', err)
  } finally {
    isLoadingSessions.value = false
  }
}

async function fetchWebApps() {
  isLoadingWebApps.value = true
  try {
    const response = await api.get('/jit/web/apps')
    webApps.value = response.data.apps || []
  } catch (err) {
    console.error('Failed to fetch web apps', err)
  } finally {
    isLoadingWebApps.value = false
  }
}

async function fetchK8sNamespaces() {
  isLoadingNamespaces.value = true
  try {
    const response = await api.get('/jit/namespaces')
    k8sNamespaces.value = response.data.namespaces || ['default']
  } catch (err) {
    console.error('Failed to fetch namespaces', err)
  } finally {
    isLoadingNamespaces.value = false
  }
}

onMounted(() => {
  fetchJitSessions()
  fetchK8sNamespaces()
  startEventStream()
  if (canReadAll.value) {
    loadJitAdmin().catch(() => undefined)
    loadIamUsers().catch(() => undefined)
  }
  if (auth.can('apps:read')) {
    fetchWebApps()
  }
  dashboardStore.fetchOverview().catch(() => undefined)
  timerId = setInterval(() => {
    now.value = Date.now()
  }, 1000)
})

onUnmounted(() => {
  clearInterval(timerId)
  stopEventStream()
})

async function submitRequest() {
  try {
    await jitStore.requestAccess({
      namespace: form.value.namespace,
      role: form.value.role,
      duration: form.value.duration
    })
    await dashboardStore.fetchOverview()
    if (canReadAll.value) {
      await loadJitAdmin().catch(() => undefined)
    }
    generatedCommand.value = '# Awaiting platform approval...'
    activeTab.value = 'sessions'
    notifyStore.addAlert({
        error_code: 'JIT_PENDING_APPROVAL',
        message: 'JIT request is awaiting approval.',
        technical_details: `Role ${form.value.role} in ns ${form.value.namespace} for ${form.value.duration} minutes. ${form.value.reason || 'No additional justification.'}`,
        component: 'JIT_OPERATOR',
        trace_id: Math.random().toString(36).substring(2),
        action_required: 'A platform-engineer must approve the request. The token will appear here in real-time.',
        type: 'warning'
    })
  } catch (err) {
    console.error('JIT request failed', err)
  }
}

async function submitWebRequest() {
  if (!webForm.value.appName) return
  jitStore.isSubmitting = true
  try {
    await api.post('/jit/web/request', {
      app_name: webForm.value.appName,
      duration: webForm.value.duration
    })
    
    notifyStore.addAlert({
      error_code: 'WEB_JIT_CREATED',
      message: `Acces web acordat temporar pentru ${webForm.value.appName}.`,
      technical_details: `Approved duration: ${webForm.value.duration} minutes. Refresh the page (F5) to verify ingress access.`,
      component: 'KEYCLOAK_IAM',
      trace_id: Math.random().toString(36).substring(2),
      action_required: '',
      type: 'warning'
    })
    // Simulate refreshing active sessions since web sessions are tracked dynamically
    await jitStore.fetchSessions()
  } catch (err) {
    console.error('Web JIT request failed', err)
  } finally {
    jitStore.isSubmitting = false
  }
}

function isTokenUsable(session: JitSession | null | undefined): boolean {
  if (!session) return false
  if (!session.tokenIssued) return false
  if (session.status !== 'ACTIVE' && session.status !== 'APPROVED') return false
  if (session.expiresAt) {
    const exp = new Date(session.expiresAt).getTime()
    if (!Number.isNaN(exp) && exp <= now.value) return false
  }
  return true
}

function copyCommand() {
  const payload = (tokenPanel.value && tokenPanel.value.kind === 'ready')
    ? tokenPanel.value.body
    : generatedCommand.value
  if (!payload) return
  navigator.clipboard.writeText(payload)
  copySuccess.value = true
  notifyStore.addAlert({
    error_code: 'COPIED',
    message: 'Kubeconfig command copied to clipboard.',
    technical_details: payload,
    component: 'JIT_UI',
    trace_id: Math.random().toString(36).substring(2),
    action_required: '',
    type: 'warning'
  })
  setTimeout(() => (copySuccess.value = false), 2000)
}

function promptRevoke(session: JitSession) {
  sessionToRevoke.value = session
  isConfirmRevokeOpen.value = true
}

async function confirmRevoke() {
  if (!sessionToRevoke.value) return
  isRevoking.value = true
  try {
    await jitStore.revokeSession(sessionToRevoke.value.namespace, sessionToRevoke.value.id)
    await fetchJitSessions()
    await dashboardStore.fetchOverview(true)
    await loadJitAdmin()
    notifyStore.addAlert({
      error_code: 'JIT_REVOKED',
      message: `Session ${sessionToRevoke.value.id} revoked.`,
      technical_details: `Namespace=${sessionToRevoke.value.namespace}, user=${sessionToRevoke.value.user}`,
      component: 'JIT_OPERATOR',
      trace_id: Math.random().toString(36).substring(2),
      action_required: '',
      type: 'warning'
    })
    isConfirmRevokeOpen.value = false
  } catch (err) {
    console.error('JIT revoke failed', err)
  } finally {
    isRevoking.value = false
    sessionToRevoke.value = null
  }
}

function formatTimeLeft(expiresAtStr: string) {
  const diff = new Date(expiresAtStr).getTime() - now.value
  if (diff <= 0) return '00:00'
  const h = Math.floor(diff / 3600000).toString().padStart(2, '0')
  const m = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0')
  const s = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0')
  return parseInt(h) > 0 ? `${h}:${m}:${s}` : `${m}:${s}`
}

function getStatusColor(status: string) {
  if (status === 'ACTIVE' || status === 'APPROVED') return 'success'
  if (status === 'EXPIRED') return 'secondary'
  if (status === 'REVOKED') return 'error'
  if (status.startsWith('DENIED') || status.startsWith('BLOCKED')) return 'error'
  if (status === 'PENDING_APPROVAL') return 'orange'
  if (status === 'PENDING') return 'warning'
  return 'secondary'
}

function getStatusIcon(status: string) {
  if (status === 'ACTIVE' || status === 'APPROVED') return 'mdi-check-circle'
  if (status === 'EXPIRED') return 'mdi-progress-clock'
  if (status === 'REVOKED') return 'mdi-cancel'
  if (status.startsWith('DENIED') || status.startsWith('BLOCKED')) return 'mdi-alert'
  if (status === 'PENDING_APPROVAL') return 'mdi-account-clock'
  if (status === 'PENDING') return 'mdi-dots-horizontal-circle'
  return 'mdi-help-circle'
}

function getTTLPercentage(expiresAtStr: string, durationMin: number) {
  const diff = new Date(expiresAtStr).getTime() - now.value
  const total = Math.max(durationMin * 60000, 1)
  return Math.max(0, Math.min(100, (diff / total) * 100))
}

function getTTLColor(expiresAtStr: string) {
  const diff = new Date(expiresAtStr).getTime() - now.value
  if (diff < 300000) return 'error'
  if (diff < 900000) return 'warning'
  return 'success'
}

function getTTLColorClass(expiresAtStr: string) {
  const color = getTTLColor(expiresAtStr)
  return `text-${color}`
}

function copyTokenCommand(session: JitSession) {
  const cmd = session.commandToUse || `kubectl --token='${session.temporaryToken}' -n ${session.namespace} get pods`
  navigator.clipboard.writeText(cmd)
  generatedCommand.value = cmd
  notifyStore.addAlert({
    error_code: 'TOKEN_COPIED',
    message: 'Kubectl token command copiat.',
    technical_details: `Session: ${session.id} | Expires: ${session.expiresAt}`,
    component: 'JIT_MODULE',
    trace_id: `SYS-${Math.random().toString(36).substring(2)}`,
    action_required: '',
    type: 'warning'
  })
}

function copyKubeconfig(sessionId: string) {
  navigator.clipboard.writeText(`export KUBECONFIG=~/.kube/cache/${sessionId}.yaml\nkubectl config view`)
  notifyStore.addAlert({
    error_code: 'CLIPBOARD_SUCCESS',
    message: 'Kubeconfig command copied.',
    technical_details: `Stored command for session ${sessionId}`,
    component: 'JIT_MODULE',
    trace_id: `SYS-${Math.random().toString(36).substring(2)}`,
    action_required: '',
    type: 'warning'
  })
}

async function loadJitAdmin() {
  isLoadingPolicies.value = true
  try {
    const [analyticsResponse, policiesResponse] = await Promise.all([
      api.get('/jit/analytics'),
      api.get('/jit/policies')
    ])
    jitAnalytics.value = analyticsResponse.data
    jitPolicies.value = policiesResponse.data
    policyForm.value = {
      blockedUsers: Array.isArray(policiesResponse.data.blockedUsers) ? [...policiesResponse.data.blockedUsers] : [],
      maxActiveSessions: policiesResponse.data.antiAbuse?.maxActiveSessions || 1,
      cooldownMinutes: policiesResponse.data.antiAbuse?.cooldownMinutes || 15,
      maxRequestsPerDay: policiesResponse.data.antiAbuse?.maxRequestsPerDay || 5,
      maxDurationMinutes: policiesResponse.data.antiAbuse?.maxDurationMinutes || 120,
    }
  } finally {
    isLoadingPolicies.value = false
  }
}

async function savePolicies() {
  isSavingPolicies.value = true
  try {
    const payload = {
      blockedUsers: Array.from(new Set((policyForm.value.blockedUsers || []).map(u => String(u).trim()).filter(Boolean))),
      antiAbuse: {
        maxActiveSessions: policyForm.value.maxActiveSessions,
        cooldownMinutes: policyForm.value.cooldownMinutes,
        maxRequestsPerDay: policyForm.value.maxRequestsPerDay,
        maxDurationMinutes: policyForm.value.maxDurationMinutes,
      },
    }
    const response = await api.put('/jit/policies', payload)
    jitPolicies.value = response.data
    await loadJitAdmin()
    notifyStore.addAlert({
      error_code: 'JIT_POLICIES_UPDATED',
      message: 'Anti-abuse policies have been updated in the ConfigMap.',
      technical_details: JSON.stringify(response.data, null, 2),
      component: 'JIT_POLICY_EDITOR',
      trace_id: Math.random().toString(36).substring(2),
      action_required: 'Check the effect on active JIT requests immediately.',
      type: 'warning'
    })
  } finally {
    isSavingPolicies.value = false
  }
}
</script>

<template>
  <div>
    <div class="d-flex align-center justify-space-between mb-4">
      <h1 class="text-h5 font-weight-medium text-primary">JIT Access Portal</h1>
      <v-chip :color="pendingCount > 0 ? 'warning' : 'primary'" variant="tonal" class="font-weight-medium">
        <v-icon start size="small">{{ pendingCount > 0 ? 'mdi-account-clock' : 'mdi-shield-account' }}</v-icon>
        {{ pendingCount }} Pending Request{{ pendingCount === 1 ? '' : 's' }}
      </v-chip>
    </div>
    
    <v-row>
      <v-col cols="12" md="5" lg="4">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary">Ephemeral Access Wizard (IAM)</v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary mb-4">Choose the resource type for temporary JIT privilege escalation.</p>
            
            <v-tabs v-model="activeTab" density="compact" color="primary" class="mb-4 text-caption border-b">
              <v-tab value="k8s" size="small" class="text-none"><v-icon start size="small">mdi-kubernetes</v-icon> K8s RBAC</v-tab>
              <v-tab value="web" size="small" class="text-none"><v-icon start size="small">mdi-web</v-icon> Web Proxy</v-tab>
              <v-tab value="sessions" size="small" class="text-none"><v-icon start size="small">mdi-clock-check</v-icon> Sessions</v-tab>
            </v-tabs>

            <v-window v-model="activeTab" :touch="false">
              <!-- Kubernetes RBAC Tab -->
              <v-window-item value="k8s">
                <v-select
                  v-model="form.namespace"
                  density="compact"
                  label="Target Namespace"
                  variant="outlined"
                  :items="k8sNamespaces"
                  :loading="isLoadingNamespaces"
                  prepend-inner-icon="mdi-google-cloud"
                  hide-details="auto"
                  class="mb-4 mt-2"
                  no-data-text="No namespaces found"
                ></v-select>
                
                <v-select 
                  v-model="form.role"
                  density="compact" 
                  label="Requested Kubernetes Role" 
                  :items="roles" 
                  variant="outlined"
                  prepend-inner-icon="mdi-shield-account-variant"
                  hide-details="auto"
                  class="mb-4"
                ></v-select>
                
                <div class="px-2 mt-6">
                  <div class="text-caption text-secondary mb-1">Duration: {{ form.duration }} minutes <span class="text-error text-caption">(min 10 min — K8s TokenRequest limit)</span></div>
                  <v-slider
                    v-model="form.duration"
                    color="primary"
                    min="10"
                    max="120"
                    step="10"
                    thumb-label
                    hide-details
                  ></v-slider>
                </div>

                <v-textarea
                  v-model="form.reason"
                  label="Justification (SecOps audit log)"
                  variant="outlined"
                  density="compact"
                  rows="2"
                  class="mt-4"
                  hide-details="auto"
                  prepend-inner-icon="mdi-text-box-edit-outline"
                ></v-textarea>
                
                <v-btn
                  :loading="isSubmitting"
                  :disabled="!canRequest"
                  @click="submitRequest"
                  color="primary"
                  block
                  variant="flat"
                  elevation="0"
                  class="mt-6 text-none font-weight-medium"
                  prepend-icon="mdi-shield-key-outline"
                >
                  {{ canRequest ? 'Request K8S Access' : 'Requires developer / sre / platform-engineer role' }}
                </v-btn>
              </v-window-item>

              <!-- Web App Tab -->
              <v-window-item value="web">
                <v-select 
                  v-model="webForm.appName"
                  density="compact" 
                  label="Target Web Application" 
                  :items="webApps.map(a => a.name)" 
                  variant="outlined"
                  prepend-inner-icon="mdi-application-brackets-outline"
                  hide-details="auto"
                  class="mb-4 mt-2"
                  :loading="isLoadingWebApps"
                ></v-select>

                <div class="px-2 mt-6">
                  <div class="text-caption text-secondary mb-1">Duration: {{ webForm.duration }} minutes</div>
                  <v-slider 
                    v-model="webForm.duration"
                    color="primary" 
                    min="5" 
                    max="480" 
                    step="15" 
                    thumb-label
                    hide-details
                  ></v-slider>
                </div>

                <v-textarea
                  v-model="webForm.reason"
                  label="Justification (SecOps audit log)"
                  variant="outlined"
                  density="compact"
                  rows="2"
                  class="mt-4"
                  hide-details="auto"
                  prepend-inner-icon="mdi-text-box-edit-outline"
                ></v-textarea>

                <v-btn
                  :loading="isSubmitting"
                  @click="submitWebRequest"
                  color="primary"
                  block
                  variant="flat"
                  elevation="0"
                  class="mt-6 text-none font-weight-medium"
                  prepend-icon="mdi-web-check"
                  :disabled="!webForm.appName || !canRequest"
                >
                  {{ canRequest ? 'Request Ingress Access' : 'Requires developer / sre / platform-engineer role' }}
                </v-btn>
              </v-window-item>

              <!-- Sessions State Tab -->
              <v-window-item value="sessions">
                <div class="mt-4">
                  <div class="d-flex justify-space-between align-center mb-3">
                    <h3 class="text-subtitle-2 font-weight-medium">
                      Active Sessions
                    </h3>
                    <v-btn size="small" variant="text" color="primary" prepend-icon="mdi-refresh" @click="fetchJitSessions" :loading="isLoadingSessions">
                      Refresh
                    </v-btn>
                  </div>

                  <!-- Stat cards double as quick filters -->
                  <div v-if="jitSessionStats" class="d-grid gap-2 mb-3" style="grid-template-columns: repeat(auto-fit, minmax(110px, 1fr))">
                    <v-card
                      v-for="opt in [
                        { key: 'all', label: 'Total', value: jitSessionStats.total_sessions, color: 'primary' },
                        { key: 'pending', label: 'Pending', value: jitSessionStats.pending, color: 'warning' },
                        { key: 'active', label: 'Active', value: jitSessionStats.active, color: 'success' },
                        { key: 'expired', label: 'Ended', value: jitSessionStats.expired, color: 'error' },
                      ]"
                      :key="opt.key"
                      variant="outlined"
                      class="pa-3 text-center stat-card"
                      :class="{ 'stat-card--active': sessionFilter === opt.key }"
                      @click="sessionFilter = (opt.key as SessionFilter)"
                      style="cursor: pointer;"
                    >
                      <div class="text-h6 font-weight-bold" :class="`text-${opt.color}`">{{ opt.value }}</div>
                      <div class="text-caption text-secondary">{{ opt.label }}</div>
                    </v-card>
                  </div>

                  <v-skeleton-loader v-if="isLoadingSessions && visibleSessions.length === 0" type="table"></v-skeleton-loader>

                  <div v-else-if="visibleSessions.length > 0" class="d-flex flex-column" style="gap: 8px;">
                    <v-card
                      v-for="sess in visibleSessions"
                      :key="sess.id"
                      variant="outlined"
                      class="pa-3 session-card"
                      :class="{ 'session-card--selected': selectedSessionId === sess.id }"
                      @click="selectSession(sess.id)"
                    >
                      <div class="d-flex justify-space-between align-start" style="gap: 12px;">
                        <div class="flex-grow-1" style="min-width: 0;">
                          <div class="d-flex align-center ga-2 mb-1">
                            <v-avatar size="22" color="primary" class="text-caption font-weight-bold">{{ sess.user.substring(0,2).toUpperCase() }}</v-avatar>
                            <span class="text-body-2 font-weight-medium text-truncate">{{ sess.user }}</span>
                          </div>
                          <div class="text-caption text-secondary d-flex flex-wrap ga-2 align-center">
                            <span class="d-inline-flex align-center"><v-icon size="x-small" start>mdi-kubernetes</v-icon>{{ sess.namespace }}</span>
                            <span class="d-inline-flex align-center"><v-icon size="x-small" start>mdi-shield-account-variant</v-icon>{{ sess.role }}</span>
                            <span v-if="sess.duration" class="d-inline-flex align-center"><v-icon size="x-small" start>mdi-timer-outline</v-icon>{{ sess.duration }}m</span>
                          </div>
                          <div class="text-caption mt-1">
                            <template v-if="isTokenUsable(sess)">
                              <span class="text-success font-weight-medium">
                                <v-icon size="x-small" start>mdi-clock-outline</v-icon>
                                {{ liveTimeLeft(sess.expiresAt) }} left
                              </span>
                            </template>
                            <template v-else-if="sess.status === 'PENDING_APPROVAL' || sess.status === 'PENDING'">
                              <span class="text-warning">Awaiting platform approval</span>
                            </template>
                            <template v-else-if="sess.status === 'EXPIRED'">
                              <span class="text-secondary"><v-icon size="x-small" start>mdi-history</v-icon>Session expired</span>
                            </template>
                            <template v-else-if="sess.status === 'REVOKED' || sess.status === 'TAMPERED'">
                              <span class="text-error"><v-icon size="x-small" start>mdi-cancel</v-icon>{{ sess.status === 'TAMPERED' ? 'Tampered — auto-revoked' : 'Manually revoked' }}</span>
                            </template>
                            <template v-else-if="sess.status.startsWith('DENIED')">
                              <span class="text-error"><v-icon size="x-small" start>mdi-alert</v-icon>{{ sess.message || 'Denied by anti-abuse engine' }}</span>
                            </template>
                          </div>
                        </div>
                        <div class="text-right d-flex flex-column align-end" style="gap: 6px;" @click.stop>
                          <v-chip :color="getStatusColor(sess.status)" size="small" variant="flat">
                            <v-icon start size="x-small">{{ getStatusIcon(sess.status) }}</v-icon>
                            {{ sess.status }}
                          </v-chip>
                          <div class="d-flex gap-1 flex-wrap justify-end">
                            <v-btn
                              v-if="(sess.status === 'PENDING_APPROVAL' || sess.status === 'PENDING') && canApprove"
                              size="x-small" variant="flat" color="success" prepend-icon="mdi-check-bold"
                              @click="approveSession({ session_id: sess.id, namespace: sess.namespace })"
                            >Approve</v-btn>
                            <v-btn
                              v-if="isTokenUsable(sess)"
                              size="x-small" variant="tonal" color="success" prepend-icon="mdi-content-copy"
                              @click="copyTokenCommand(sess); selectSession(sess.id)"
                            >Copy token</v-btn>
                            <v-btn
                              v-if="canRevoke && (sess.status === 'ACTIVE' || sess.status === 'APPROVED' || sess.status === 'PENDING_APPROVAL' || sess.status === 'PENDING')"
                              size="x-small" variant="flat" color="error"
                              @click="jitStore.revokeSession(sess.namespace, sess.id)"
                            >{{ (sess.status === 'PENDING_APPROVAL' || sess.status === 'PENDING') ? 'Cancel' : 'Revoke' }}</v-btn>
                            <v-btn
                              v-if="sess.status === 'EXPIRED' || sess.status === 'REVOKED' || sess.status === 'TAMPERED' || sess.status.startsWith('DENIED')"
                              size="x-small" variant="text" color="secondary" prepend-icon="mdi-trash-can-outline"
                              @click="dismissSession({ session_id: sess.id, namespace: sess.namespace })"
                              title="Dismiss from list"
                            >Dismiss</v-btn>
                          </div>
                        </div>
                      </div>
                    </v-card>
                  </div>

                  <div v-else class="text-center text-secondary py-6">
                    <v-icon size="32" class="mb-2">mdi-inbox-outline</v-icon>
                    <div class="text-body-2">
                      <template v-if="sessionFilter === 'all'">No JIT sessions yet — request access above.</template>
                      <template v-else-if="sessionFilter === 'pending'">No requests waiting for approval.</template>
                      <template v-else-if="sessionFilter === 'active'">No active sessions right now.</template>
                      <template v-else>No expired or revoked sessions.</template>
                    </div>
                  </div>
                </div>
              </v-window-item>
            </v-window>

            <v-expand-transition>
              <div v-if="tokenPanel" class="mt-4 token-panel" :data-kind="tokenPanel.kind">
                <div class="token-panel__header d-flex align-center justify-space-between mb-1">
                  <div class="d-flex align-center ga-2">
                    <v-icon
                      size="small"
                      :color="tokenPanel.kind === 'ready' ? 'success'
                        : tokenPanel.kind === 'pending' ? 'warning'
                        : tokenPanel.kind === 'provisioning' ? 'info'
                        : tokenPanel.kind === 'gone' ? 'secondary'
                        : tokenPanel.kind === 'denied' ? 'error' : 'secondary'"
                    >
                      {{ tokenPanel.kind === 'ready' ? 'mdi-key-variant'
                        : tokenPanel.kind === 'pending' ? 'mdi-account-clock'
                        : tokenPanel.kind === 'provisioning' ? 'mdi-progress-clock'
                        : tokenPanel.kind === 'gone' ? 'mdi-history'
                        : tokenPanel.kind === 'denied' ? 'mdi-cancel' : 'mdi-information-outline' }}
                    </v-icon>
                    <span class="text-caption font-weight-medium">
                      {{ tokenPanel.kind === 'ready' ? 'kubectl token ready'
                        : tokenPanel.kind === 'pending' ? 'Awaiting approval'
                        : tokenPanel.kind === 'provisioning' ? 'Provisioning'
                        : tokenPanel.kind === 'gone' ? 'Session ended'
                        : tokenPanel.kind === 'denied' ? 'Request rejected'
                        : 'Token preview' }}
                    </span>
                    <v-chip v-if="selectedSession" size="x-small" variant="tonal" class="font-mono">
                      {{ selectedSession.id }}
                    </v-chip>
                  </div>
                  <v-btn
                    v-if="tokenPanel.kind === 'ready'"
                    size="x-small"
                    variant="text"
                    :color="copySuccess ? 'success' : 'primary'"
                    :prepend-icon="copySuccess ? 'mdi-check' : 'mdi-content-copy'"
                    @click="copyCommand"
                  >
                    {{ copySuccess ? 'Copied' : 'Copy' }}
                  </v-btn>
                </div>
                <pre
                  class="token-panel__body font-mono text-caption ma-0 pa-3 rounded"
                  :class="{
                    'token-panel__body--ready': tokenPanel.kind === 'ready',
                    'token-panel__body--muted': tokenPanel.kind !== 'ready',
                  }"
                  style="white-space: pre-wrap; word-break: break-all;"
                >{{ tokenPanel.body }}</pre>
              </div>
            </v-expand-transition>

          </v-card-text>
        </v-card>
      </v-col>
      
      <v-col cols="12" md="7" lg="8">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-error">
            <v-icon start color="error" class="mr-2">mdi-google-cloud</v-icon>
            IAM & Service Accounts Admin
          </v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary mb-4">Monitor active, pending, denied or revoked sessions and inspect the full operator reasoning.</p>
            
            <v-table density="comfortable" class="border rounded" hover>
              <thead>
                <tr class="bg-surface-variant">
                  <th class="text-left font-weight-medium">Identity (User)</th>
                  <th class="text-left font-weight-medium">Namespace</th>
                  <th class="text-left font-weight-medium">Role</th>
                  <th class="text-center font-weight-medium">Status</th>
                  <th class="text-center font-weight-medium" style="width: 150px">TTL</th>
                  <th class="text-left font-weight-medium">Visibility</th>
                  <th class="text-right font-weight-medium">Actions</th>
                </tr>
              </thead>
              <tbody v-if="isLoading">
                <tr v-for="i in 3" :key="i">
                  <td colspan="7">
                    <v-skeleton-loader type="table-row" height="40"></v-skeleton-loader>
                  </td>
                </tr>
              </tbody>
              <tbody v-else>
                <tr v-for="session in sessions" :key="session.id" class="cursor-pointer hover:bg-surface-variant transition-colors" :class="{ 'bg-surface-variant': selectedSessionId === session.id }" @click="selectSession(session.id)">
                  <td class="text-body-2 font-weight-medium d-flex align-center">
                    <v-avatar size="24" color="primary" class="mr-2 text-caption font-weight-bold">{{ session.user.substring(0,2).toUpperCase() }}</v-avatar>
                    {{ session.user }}
                  </td>
                  <td class="font-mono text-caption text-secondary">{{ session.namespace }}</td>
                  <td class="font-mono text-caption text-secondary">{{ session.role }}</td>
                  <td class="text-center">
                    <v-chip 
                      :color="getStatusColor(session.status)" 
                      size="small" 
                      variant="flat" 
                      class="font-weight-bold text-caption px-3"
                    >
                      <v-icon start size="x-small">{{ getStatusIcon(session.status) }}</v-icon>
                      {{ session.status }}
                    </v-chip>
                  </td>
                  <td class="text-center font-mono text-caption">
                    <template v-if="(session.status === 'ACTIVE' || session.status === 'APPROVED') && session.expiresAt">
                      <div class="d-flex flex-column align-center w-100">
                        <span class="mb-1" :class="getTTLColorClass(session.expiresAt)">{{ formatTimeLeft(session.expiresAt) }}</span>
                        <v-progress-linear
                          :model-value="getTTLPercentage(session.expiresAt, session.duration)"
                          :color="getTTLColor(session.expiresAt)"
                          height="4"
                          rounded="pill"
                          class="w-100"
                        ></v-progress-linear>
                      </div>
                    </template>
                    <template v-else-if="session.status === 'PENDING_APPROVAL'">
                      <span class="text-warning">awaiting approval</span>
                      <v-progress-linear indeterminate color="warning" height="4" rounded="pill" class="w-100 mt-1"></v-progress-linear>
                    </template>
                    <template v-else>
                      <span class="text-secondary">00:00:00</span>
                      <v-progress-linear model-value="0" color="secondary" height="4" rounded="pill" class="w-100 mt-1"></v-progress-linear>
                    </template>
                  </td>
                  <td class="text-caption text-secondary" style="max-width: 220px;">{{ session.message || 'No operator message available.' }}</td>
                  <td class="text-right" @click.stop>
                    <v-btn
                      v-if="(session.status === 'PENDING_APPROVAL' || session.status === 'PENDING') && canApprove"
                      @click="approveSession({ session_id: session.id, namespace: session.namespace })"
                      color="success"
                      size="small"
                      variant="flat"
                      prepend-icon="mdi-check-bold"
                      class="mr-1"
                    >Approve</v-btn>
                    <v-btn
                      v-if="session.status === 'ACTIVE' || session.status === 'APPROVED' || session.status === 'PENDING' || session.status === 'PENDING_APPROVAL'"
                      @click="promptRevoke(session)"
                      color="error"
                      size="small"
                      variant="text"
                      icon="mdi-lock-reset"
                      title="Kill Switch (Revoke)"
                    ></v-btn>
                    <v-btn
                      v-if="session.status === 'EXPIRED' || session.status === 'REVOKED' || session.status === 'TAMPERED' || session.status.startsWith('DENIED')"
                      @click="dismissSession({ session_id: session.id, namespace: session.namespace })"
                      color="secondary"
                      size="small"
                      variant="text"
                      icon="mdi-trash-can-outline"
                      title="Dismiss from list"
                    ></v-btn>
                    
                    <v-menu location="start">
                      <template v-slot:activator="{ props }">
                        <v-btn icon="mdi-dots-vertical" variant="text" size="small" v-bind="props" color="secondary"></v-btn>
                      </template>
                      <v-list density="compact" class="gc-border" elevation="2">
                        <v-list-item
                          v-if="isTokenUsable(session) && session.commandToUse"
                          @click="copyTokenCommand(session)"
                          prepend-icon="mdi-key-variant"
                        >
                          <v-list-item-title class="text-caption text-success font-weight-medium">Copy kubectl Token</v-list-item-title>
                        </v-list-item>
                        <v-list-item
                          v-if="isTokenUsable(session)"
                          @click="copyKubeconfig(session.sessionId || session.id)"
                          prepend-icon="mdi-code-json"
                        >
                          <v-list-item-title class="text-caption">Copy Kubeconfig</v-list-item-title>
                        </v-list-item>
                        <v-list-item v-else prepend-icon="mdi-key-off-outline" disabled>
                          <v-list-item-title class="text-caption text-secondary font-italic">Token unavailable for {{ session.status }} sessions</v-list-item-title>
                        </v-list-item>
                        <v-divider class="my-1"></v-divider>
                        <v-list-item prepend-icon="mdi-information-outline">
                          <v-list-item-title class="text-caption">{{ session.message || 'No details' }}</v-list-item-title>
                        </v-list-item>
                      </v-list>
                    </v-menu>
                  </td>
                </tr>
              </tbody>
            </v-table>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row v-if="canReadAll" class="mt-2">
      <v-col cols="12" lg="5">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Anti-Abuse Policy Editor</v-card-title>
          <v-card-text>
            <div class="text-caption text-secondary mb-4">Edits the <code>jit-security-policies</code> ConfigMap in the cluster directly.</div>
            <v-skeleton-loader v-if="isLoadingPolicies" type="article"></v-skeleton-loader>
            <template v-else>
              <v-autocomplete
                v-model="policyForm.blockedUsers"
                :items="iamUserOptions"
                item-title="title"
                item-value="value"
                label="Blocked Users"
                placeholder="Select one or more users to block"
                variant="outlined"
                density="compact"
                chips
                closable-chips
                multiple
                clearable
                :loading="isLoadingIamUsers"
                :menu-props="{ maxHeight: 320 }"
                hint="Searches by display name or identity. Selections take effect after Apply Cluster Policy."
                persistent-hint
                class="mb-4"
              >
                <template #item="{ props, item }">
                  <v-list-item v-bind="props" :title="item.raw.title" :subtitle="item.raw.subtitle" />
                </template>
                <template #chip="{ props, item }">
                  <v-chip v-bind="props" size="small" color="error" variant="tonal" prepend-icon="mdi-account-cancel-outline">
                    {{ item.raw.title || item.raw.value }}
                  </v-chip>
                </template>
                <template #no-data>
                  <v-list-item title="No matching users — type to add a manual identity" />
                </template>
              </v-autocomplete>
              <div class="d-flex align-center text-caption text-secondary mb-4">
                <v-icon size="x-small" start>mdi-shield-account-outline</v-icon>
                {{ policyForm.blockedUsers.length }} user{{ policyForm.blockedUsers.length === 1 ? '' : 's' }} currently blocked
              </div>
              <v-row>
                <v-col cols="12" md="6">
                  <v-text-field v-model.number="policyForm.maxActiveSessions" type="number" label="Max Active Sessions" variant="outlined" density="compact" hide-details></v-text-field>
                </v-col>
                <v-col cols="12" md="6">
                  <v-text-field v-model.number="policyForm.cooldownMinutes" type="number" label="Cooldown Minutes" variant="outlined" density="compact" hide-details></v-text-field>
                </v-col>
                <v-col cols="12" md="6">
                  <v-text-field v-model.number="policyForm.maxRequestsPerDay" type="number" label="Max Requests / Day" variant="outlined" density="compact" hide-details></v-text-field>
                </v-col>
                <v-col cols="12" md="6">
                  <v-text-field v-model.number="policyForm.maxDurationMinutes" type="number" label="Max Duration Minutes" variant="outlined" density="compact" hide-details></v-text-field>
                </v-col>
              </v-row>
              <v-btn color="primary" variant="flat" :loading="isSavingPolicies" :disabled="!canWritePolicy" @click="savePolicies" class="mt-4">
                {{ canWritePolicy ? 'Apply Cluster Policy' : 'Requires platform-engineer role' }}
              </v-btn>
            </template>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" lg="7">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Anti-Abuse Analytics</v-card-title>
          <v-card-text>
            <div class="d-flex flex-wrap ga-2 mb-4">
              <v-chip color="primary" variant="tonal">Active {{ jitAnalytics?.activeSessions || 0 }}</v-chip>
              <v-chip color="error" variant="tonal">Blocked {{ (jitAnalytics?.blockedUsers || []).length }}</v-chip>
              <v-chip color="warning" variant="tonal">Tracked identities {{ (jitAnalytics?.topIdentities || []).length }}</v-chip>
            </div>
            <div class="text-caption text-secondary mb-2">Denied by type</div>
            <div class="d-flex flex-wrap ga-2 mb-4">
              <v-chip v-for="(count, key) in (jitAnalytics?.deniedByType || {})" :key="key" color="warning" variant="outlined">
                {{ key }}: {{ count }}
              </v-chip>
            </div>
            <v-table density="compact" class="border rounded">
              <thead>
                <tr>
                  <th class="text-left">Identity</th>
                  <th class="text-left">Requests</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="identity in (jitAnalytics?.topIdentities || [])" :key="identity.identity">
                  <td>{{ identity.identity }}</td>
                  <td>{{ identity.requests }}</td>
                </tr>
              </tbody>
            </v-table>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-dialog v-model="isConfirmRevokeOpen" max-width="400" persistent>
      <v-card class="gc-border" flat>
        <v-card-title class="text-error font-weight-medium pt-4 bg-error-lighten-5">
          <v-icon color="error" class="mr-2">mdi-alert-decagram</v-icon> Confirm Revoke IAM
        </v-card-title>
        <v-card-text class="pt-4">
          You are about to revoke this critical session:
          <div class="mt-3 pa-3 bg-surface-variant rounded border gc-border font-mono text-caption">
            <strong>ID:</strong> {{ sessionToRevoke?.id }}<br>
            <strong>User:</strong> {{ sessionToRevoke?.user }}<br>
            <strong>Namespace:</strong> {{ sessionToRevoke?.namespace }}<br>
            <strong>Role:</strong> {{ sessionToRevoke?.role }}<br>
            <strong>Message:</strong> {{ sessionToRevoke?.message || 'No backend message' }}
          </div>
          <p class="mt-4 text-body-2 font-weight-medium text-error">This will immediately delete the RoleBinding in the selected cluster. Continue?</p>
        </v-card-text>
        <v-card-actions class="px-4 pb-4">
          <v-spacer></v-spacer>
          <v-btn color="secondary" variant="text" :disabled="isRevoking" @click="isConfirmRevokeOpen = false">Cancel</v-btn>
          <v-btn color="error" variant="flat" elevation="0" :loading="isRevoking" @click="confirmRevoke">Revoke Access Now</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<style scoped>
.v-table th { white-space: nowrap; }
.bg-error-lighten-5 { background-color: rgba(var(--v-theme-error), 0.05); }

.session-card {
  cursor: pointer;
  transition: border-color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
}
.session-card:hover {
  border-color: rgba(var(--v-theme-primary), 0.4);
  background: rgba(var(--v-theme-primary), 0.03);
}

.stat-card {
  transition: border-color 0.15s ease, background 0.15s ease;
}
.stat-card:hover {
  border-color: rgba(var(--v-theme-primary), 0.35);
}
.stat-card--active {
  border-color: rgb(var(--v-theme-primary)) !important;
  background: rgba(var(--v-theme-primary), 0.07);
  box-shadow: 0 0 0 1px rgb(var(--v-theme-primary)) inset;
}
.session-card--selected {
  border-color: rgb(var(--v-theme-primary)) !important;
  background: rgba(var(--v-theme-primary), 0.08);
  box-shadow: inset 3px 0 0 0 rgb(var(--v-theme-primary));
}

.token-panel__body {
  background: rgba(var(--v-theme-on-surface), 0.04);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
  line-height: 1.45;
}
.token-panel__body--ready {
  background: rgba(var(--v-theme-success), 0.08);
  border-color: rgba(var(--v-theme-success), 0.35);
  color: rgb(var(--v-theme-on-surface));
}
.token-panel__body--muted {
  color: rgba(var(--v-theme-on-surface), 0.65);
  font-style: italic;
}
</style>
