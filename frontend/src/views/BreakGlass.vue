<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'
import { useAuthStore } from '../store/auth'

const notifyStore = useNotificationStore()
const auth = useAuthStore()
const canIssue = computed(() => auth.can('breakglass:issue'))
const canRevokeBg = computed(() => auth.can('breakglass:revoke'))

interface Session {
  jti: string
  node: string
  requester: string
  approver: string
  reason: string
  ttl_seconds: number
  issued_at: string
  expires_at: string
  state: 'ISSUED' | 'EXPIRED' | 'REVOKED'
  revoked_at?: string | null
  revoked_by?: string | null
  token?: string
}

interface AuthorizedPID {
  pid: number
  expires_at: string
}

interface NodeStatus {
  node: string
  version: string
  started_at: string
  mode: string
  protected_paths: string[]
  authorized_pids: AuthorizedPID[]
  mounted_honeypots: string[]
  policies_loaded: number
  audit_forwarder?: Record<string, any> | null
  received_at: string
  age_seconds: number
  healthy: boolean
}

interface AuditEvent {
  ts_ns?: number
  pid?: number
  tgid?: number
  ppid?: number
  uid?: number
  gid?: number
  action?: string
  dev?: number
  ino?: number
  path?: string
  comm?: string
  pcomm?: string
  node?: string
  received_at?: string
}

interface Analytics {
  sessions: { active: number; revoked: number; expired: number; total: number }
  audit: { denied: number; allowed: number; total: number; denied_per_node: Record<string, number> }
  agents: { total: number; healthy: number }
}

const activeTab = ref<'overview' | 'issue' | 'sessions' | 'nodes' | 'audit' | 'policies'>('overview')

const sessions = ref<Session[]>([])
const nodes = ref<NodeStatus[]>([])
const auditEvents = ref<AuditEvent[]>([])
const policies = ref<any[]>([])
const analytics = ref<Analytics | null>(null)

const loadingSessions = ref(false)
const loadingNodes = ref(false)
const loadingAudit = ref(false)
const loadingAnalytics = ref(false)
const loadingPolicies = ref(false)
const issuing = ref(false)
const revokingJti = ref<string | null>(null)

const auditFilters = ref({ node: '', action: '', limit: 200 })
const issuedTokenDialog = ref<{ open: boolean; session?: Session }>({ open: false })

const issueForm = ref({
  node: '',
  reason: '',
  ttl_minutes: 5,
})

const liveRefresh = ref(true)
let refreshTimer: ReturnType<typeof setInterval> | null = null

const sessionsHeaders = [
  { title: 'State', key: 'state' },
  { title: 'Node', key: 'node' },
  { title: 'Requester', key: 'requester' },
  { title: 'Approver', key: 'approver' },
  { title: 'TTL', key: 'ttl_seconds' },
  { title: 'Issued', key: 'issued_at' },
  { title: 'Expires', key: 'expires_at' },
  { title: 'Reason', key: 'reason' },
  { title: 'Actions', key: 'actions', sortable: false },
]

const nodesHeaders = [
  { title: 'Health', key: 'healthy' },
  { title: 'Node', key: 'node' },
  { title: 'Mode', key: 'mode' },
  { title: 'Protected paths', key: 'protected_paths' },
  { title: 'Authorized PIDs', key: 'authorized_pids' },
  { title: 'Honeypots mounted', key: 'mounted_honeypots' },
  { title: 'Policies', key: 'policies_loaded' },
  { title: 'Last heartbeat', key: 'received_at' },
  { title: 'Version', key: 'version' },
]

const auditHeaders = [
  { title: 'Action', key: 'action' },
  { title: 'When', key: 'received_at' },
  { title: 'Node', key: 'node' },
  { title: 'PID', key: 'pid' },
  { title: 'Process', key: 'comm' },
  { title: 'Path', key: 'path' },
  { title: 'UID', key: 'uid' },
]

const policiesHeaders = [
  { title: 'Name', key: 'name' },
  { title: 'Node Selector', key: 'nodeSelector' },
  { title: 'Protected Paths', key: 'protectedPaths' },
  { title: 'Mode', key: 'mode' },
  { title: 'Max TTL', key: 'maxTtl' },
]

const filteredAudit = computed(() => auditEvents.value)

const knownNodes = computed(() => {
  const set = new Set<string>()
  nodes.value.forEach((n) => set.add(n.node))
  sessions.value.forEach((s) => set.add(s.node))
  return Array.from(set).sort()
})

const maxDeniedPerNode = computed(() => {
  if (!analytics.value?.audit.denied_per_node) return 0
  const values = Object.values(analytics.value.audit.denied_per_node) as number[]
  return values.length > 0 ? Math.max(...values) : 0
})

function reportFetchError(path: string, err: any) {
  const status = err?.response?.status ?? 'NET'
  const detail = err?.response?.data?.detail ?? err?.response?.data?.message ?? err?.message ?? 'unknown'
  notifyStore.addAlert({
    error_code: `BREAKGLASS_FETCH_FAILED_${status}`,
    message: `Nu am putut citi ${path} (${status})`,
    technical_details: typeof detail === 'string' ? detail : JSON.stringify(detail),
    component: 'BREAKGLASS_UI',
    trace_id: err?.response?.headers?.['x-request-id'] ?? 'CLIENT',
    action_required:
      status === 403
        ? 'Cere unui platform-engineer/sre-oncall/security-auditor să-ți adauge grupul în Keycloak.'
        : status === 401
        ? 'Sesiunea a expirat — reautentifică-te.'
        : 'Verifică logs backend zero-trust-dashboard-backend și conectivitatea agenți → /breakglass/heartbeat.',
    request_method: 'GET',
    request_path: path,
    timestamp: new Date().toISOString(),
    source: 'backend',
    type: 'error',
  })
}

async function fetchAnalytics() {
  loadingAnalytics.value = true
  try {
    const res = await api.get('/breakglass/analytics')
    analytics.value = res.data.analytics
  } catch (err) {
    analytics.value = null
    reportFetchError('/breakglass/analytics', err)
  } finally {
    loadingAnalytics.value = false
  }
}

async function fetchSessions() {
  loadingSessions.value = true
  try {
    const res = await api.get('/breakglass/sessions')
    sessions.value = res.data.sessions || []
  } catch (err) {
    sessions.value = []
    reportFetchError('/breakglass/sessions', err)
  } finally {
    loadingSessions.value = false
  }
}

async function fetchNodes() {
  loadingNodes.value = true
  try {
    const res = await api.get('/breakglass/nodes')
    nodes.value = res.data.nodes || []
  } catch (err) {
    nodes.value = []
    reportFetchError('/breakglass/nodes', err)
  } finally {
    loadingNodes.value = false
  }
}

async function fetchAudit() {
  loadingAudit.value = true
  try {
    const params: Record<string, any> = { limit: auditFilters.value.limit }
    if (auditFilters.value.node) params.node = auditFilters.value.node
    if (auditFilters.value.action) params.action = auditFilters.value.action
    const res = await api.get('/breakglass/audit', { params })
    auditEvents.value = res.data.events || []
  } catch (err) {
    auditEvents.value = []
    reportFetchError('/breakglass/audit', err)
  } finally {
    loadingAudit.value = false
  }
}

async function fetchPolicies() {
  loadingPolicies.value = true
  try {
    const res = await api.get('/breakglass/policies')
    policies.value = res.data.policies || []
  } catch (err) {
    policies.value = []
    reportFetchError('/breakglass/policies', err)
  } finally {
    loadingPolicies.value = false
  }
}

async function refreshAll() {
  await Promise.all([fetchAnalytics(), fetchSessions(), fetchNodes(), fetchAudit(), fetchPolicies()])
}

async function issueToken() {
  if (!issueForm.value.node) {
    notifyStore.addAlert({
      error_code: 'VALIDATION_ERROR',
      message: 'Selectează un nod înainte de a emite token-ul.',
      technical_details: 'node is required',
      component: 'BREAKGLASS_UI',
      trace_id: 'CLIENT',
      action_required: 'Selectează un nod activ',
      request_method: 'POST',
      request_path: '/breakglass/sessions',
      timestamp: new Date().toISOString(),
      source: 'frontend',
      type: 'warning',
    })
    return
  }
  issuing.value = true
  try {
    const res = await api.post('/breakglass/sessions', {
      node: issueForm.value.node,
      reason: issueForm.value.reason,
      ttl_seconds: issueForm.value.ttl_minutes * 60,
    })
    issuedTokenDialog.value = { open: true, session: res.data }
    notifyStore.addAlert({
      error_code: 'BREAKGLASS_TOKEN_CREATED',
      message: `Token break-glass emis pentru ${issueForm.value.node}`,
      technical_details: `jti=${res.data.jti}`,
      component: 'BREAKGLASS_UI',
      trace_id: 'CLIENT',
      action_required: 'Copiază token-ul ACUM. Nu va mai fi afișat.',
      request_method: 'POST',
      request_path: '/breakglass/sessions',
      timestamp: new Date().toISOString(),
      source: 'backend',
      type: 'warning',
    })
    issueForm.value.reason = ''
    fetchSessions()
    fetchAnalytics()
  } catch {
    // axios interceptor handles the alert
  } finally {
    issuing.value = false
  }
}

async function revokeSession(s: Session) {
  if (!confirm(`Revoci sesiunea ${s.jti.slice(0, 8)}… pe ${s.node}?`)) return
  revokingJti.value = s.jti
  try {
    await api.delete(`/breakglass/sessions/${s.jti}`)
    notifyStore.addAlert({
      error_code: 'BREAKGLASS_SESSION_REVOKED',
      message: `Sesiunea ${s.jti.slice(0, 8)}… a fost revocată`,
      technical_details: 'token rămâne neutilizabil pe agent (jti blacklisted prin replay-cache)',
      component: 'BREAKGLASS_UI',
      trace_id: 'CLIENT',
      action_required: '',
      request_method: 'DELETE',
      request_path: `/breakglass/sessions/${s.jti}`,
      timestamp: new Date().toISOString(),
      source: 'backend',
      type: 'warning',
    })
    fetchSessions()
    fetchAnalytics()
  } catch {
    // interceptor
  } finally {
    revokingJti.value = null
  }
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(() => {
    notifyStore.addAlert({
      error_code: 'COPIED_OK',
      message: 'Copiat în clipboard',
      technical_details: '',
      component: 'BREAKGLASS_UI',
      trace_id: 'CLIENT',
      action_required: '',
      request_method: 'COPY',
      request_path: 'clipboard',
      timestamp: new Date().toISOString(),
      source: 'frontend',
      type: 'warning',
    })
  })
}

function copyKnockCommand(s: Session) {
  if (!s.token) return
  const cmd = `# Pe nodul ${s.node}\nexport ZTA_TOKEN='${s.token}'\nzta-cli unlock --ttl ${s.ttl_seconds}s`
  copyToClipboard(cmd)
}

function stateColor(state: string) {
  switch (state) {
    case 'ISSUED':
      return 'success'
    case 'EXPIRED':
      return 'grey'
    case 'REVOKED':
      return 'error'
    default:
      return 'primary'
  }
}

function actionColor(action?: string) {
  switch (action) {
    case 'denied':
      return 'error'
    case 'allowed':
      return 'success'
    default:
      return 'primary'
  }
}

function formatTime(value?: string) {
  if (!value) return '—'
  try {
    return new Date(value).toLocaleString()
  } catch {
    return value
  }
}

function formatDuration(seconds: number) {
  if (!seconds) return '—'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${(seconds / 3600).toFixed(1)}h`
}

onMounted(() => {
  refreshAll()
  refreshTimer = setInterval(() => {
    if (liveRefresh.value) refreshAll()
  }, 5000)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<template>
  <div>
    <!-- Header -->
    <v-row class="mb-2">
      <v-col cols="12">
        <div class="d-flex align-center justify-space-between">
          <div>
            <div class="text-h5 font-weight-medium">
              <v-icon class="mr-2" color="error">mdi-shield-key-outline</v-icon>
              Break-Glass &middot; Zero-Trust Node Protection (eBPF)
            </div>
            <div class="text-caption text-secondary">
              Acces de urgență pe noduri Kubernetes via agent eBPF + LSM hooks. Toate
              acțiunile sunt auditate kernel-side.
            </div>
          </div>
          <div class="d-flex align-center ga-3">
            <v-switch
              v-model="liveRefresh"
              color="primary"
              hide-details
              density="compact"
              label="Live (5s)"
            />
            <v-btn
              size="small"
              prepend-icon="mdi-refresh"
              variant="outlined"
              color="primary"
              @click="refreshAll"
            >
              Refresh
            </v-btn>
          </div>
        </div>
      </v-col>
    </v-row>

    <!-- KPI cards -->
    <v-row class="mb-2">
      <v-col cols="12" md="3">
        <v-card flat class="gc-border pa-4">
          <div class="text-caption text-secondary">Sesiuni active</div>
          <div class="text-h4 font-weight-bold text-success">
            {{ analytics?.sessions.active ?? 0 }}
          </div>
          <div class="text-caption text-secondary">
            {{ analytics?.sessions.revoked ?? 0 }} revocate · {{ analytics?.sessions.expired ?? 0 }} expirate
          </div>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card flat class="gc-border pa-4">
          <div class="text-caption text-secondary">Agenți eBPF</div>
          <div class="text-h4 font-weight-bold text-primary">
            {{ analytics?.agents.healthy ?? 0 }} / {{ analytics?.agents.total ?? 0 }}
          </div>
          <div class="text-caption text-secondary">healthy / înregistrați</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card flat class="gc-border pa-4">
          <div class="text-caption text-secondary">Accesuri blocate</div>
          <div class="text-h4 font-weight-bold text-error">
            {{ analytics?.audit.denied ?? 0 }}
          </div>
          <div class="text-caption text-secondary">{{ analytics?.audit.allowed ?? 0 }} permise</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card flat class="gc-border pa-4">
          <div class="text-caption text-secondary">Evenimente de audit</div>
          <div class="text-h4 font-weight-bold">
            {{ analytics?.audit.total ?? 0 }}
          </div>
          <div class="text-caption text-secondary">cumulat per backend</div>
        </v-card>
      </v-col>
    </v-row>

    <v-tabs v-model="activeTab" color="primary" align-tabs="start" density="compact" class="mb-3">
      <v-tab value="overview">
        <v-icon start size="small">mdi-view-dashboard-outline</v-icon>Overview
      </v-tab>
      <v-tab value="issue">
        <v-icon start size="small">mdi-key-plus</v-icon>Emite token
      </v-tab>
      <v-tab value="sessions">
        <v-icon start size="small">mdi-account-key</v-icon>Sesiuni ({{ sessions.length }})
      </v-tab>
      <v-tab value="nodes">
        <v-icon start size="small">mdi-server-network</v-icon>Agenți ({{ nodes.length }})
      </v-tab>
      <v-tab value="audit">
        <v-icon start size="small">mdi-file-search-outline</v-icon>Audit
      </v-tab>
      <v-tab value="policies">
        <v-icon start size="small">mdi-shield-account-outline</v-icon>Politici
      </v-tab>
    </v-tabs>

    <v-window v-model="activeTab">
      <!-- Overview -->
      <v-window-item value="overview">
        <v-row>
          <v-col cols="12" md="6">
            <v-card flat class="gc-border">
              <v-card-title class="text-subtitle-1">Cele mai noi 10 evenimente kernel</v-card-title>
              <v-divider />
              <v-list density="compact">
                <v-list-item v-for="(ev, i) in auditEvents.slice(0, 10)" :key="i">
                  <template #prepend>
                    <v-chip size="x-small" :color="actionColor(ev.action)" variant="tonal" class="mr-2">
                      {{ ev.action || '—' }}
                    </v-chip>
                  </template>
                  <v-list-item-title class="text-body-2 font-mono">
                    {{ ev.path || '(unresolved)' }}
                  </v-list-item-title>
                  <v-list-item-subtitle class="text-caption">
                    {{ ev.node }} · pid={{ ev.pid }} · {{ ev.comm }} · {{ formatTime(ev.received_at) }}
                  </v-list-item-subtitle>
                </v-list-item>
                <v-list-item v-if="!auditEvents.length">
                  <v-list-item-title class="text-caption text-secondary">
                    Nu sunt evenimente. Verifică agenții și endpoint-ul de audit.
                  </v-list-item-title>
                </v-list-item>
              </v-list>
            </v-card>
          </v-col>
          <v-col cols="12" md="6">
            <v-card flat class="gc-border">
              <v-card-title class="text-subtitle-1">Blocări per nod</v-card-title>
              <v-divider />
              <v-card-text v-if="!analytics?.audit.denied_per_node || Object.keys(analytics.audit.denied_per_node).length === 0">
                <v-chip color="success" variant="tonal" label size="small">Nicio blocare detectată</v-chip>
              </v-card-text>
              <v-card-text v-else class="pt-4">
                <div v-for="(count, node) in analytics.audit.denied_per_node" :key="node" class="mb-4">
                  <div class="d-flex align-center justify-space-between mb-1">
                    <span class="text-body-2 font-mono">{{ node }}</span>
                    <span class="text-body-2 font-weight-medium text-error">{{ count }}</span>
                  </div>
                  <v-progress-linear
                    :value="maxDeniedPerNode > 0 ? (count / maxDeniedPerNode) * 100 : 0"
                    color="error"
                    height="6"
                    rounded
                  />
                </div>
              </v-card-text>
            </v-card>
          </v-col>
        </v-row>
      </v-window-item>

      <!-- Issue token -->
      <v-window-item value="issue">
        <v-card flat class="gc-border pa-6">
          <v-card-title class="text-subtitle-1 px-0">
            <v-icon class="mr-2" color="warning">mdi-shield-alert</v-icon>
            Emite un token de break-glass
          </v-card-title>
          <v-card-subtitle class="text-caption text-secondary px-0 mb-4">
            Token-ul este semnat Ed25519 de backend, validat offline de agentul eBPF de pe nodul țintă.
            Folosește-l cu <code>zta-cli unlock</code>.
          </v-card-subtitle>

          <v-row>
            <v-col cols="12" md="6">
              <v-select
                v-model="issueForm.node"
                :items="knownNodes"
                label="Nod țintă (audience)"
                variant="outlined"
                density="comfortable"
                prepend-inner-icon="mdi-server"
                clearable
              >
                <template #append-inner>
                  <v-tooltip text="Reîncarcă lista">
                    <template #activator="{ props }">
                      <v-btn v-bind="props" icon="mdi-refresh" size="x-small" variant="text" @click="fetchNodes" />
                    </template>
                  </v-tooltip>
                </template>
              </v-select>
            </v-col>
            <v-col cols="12" md="3">
              <v-text-field
                v-model.number="issueForm.ttl_minutes"
                label="TTL (minute)"
                type="number"
                min="1"
                max="30"
                variant="outlined"
                density="comfortable"
                prepend-inner-icon="mdi-timer-outline"
              />
            </v-col>
            <v-col cols="12">
              <v-textarea
                v-model="issueForm.reason"
                label="Motiv (justificare audit)"
                variant="outlined"
                density="comfortable"
                rows="2"
                prepend-inner-icon="mdi-comment-text-outline"
              />
            </v-col>
            <v-col cols="12">
              <v-btn
                color="error"
                prepend-icon="mdi-key-plus"
                :loading="issuing"
                :disabled="!canIssue"
                @click="issueToken"
              >
                {{ canIssue ? 'Emite token Ed25519' : 'Necesită platform-engineer / sre-oncall' }}
              </v-btn>
            </v-col>
          </v-row>
        </v-card>
      </v-window-item>

      <!-- Sessions -->
      <v-window-item value="sessions">
        <v-card flat class="gc-border">
          <v-data-table
            :items="sessions"
            :headers="sessionsHeaders"
            :loading="loadingSessions"
            density="compact"
            items-per-page="25"
          >
            <template #item.state="{ item }">
              <v-chip size="small" :color="stateColor(item.state)" variant="tonal">{{ item.state }}</v-chip>
            </template>
            <template #item.ttl_seconds="{ item }">
              {{ formatDuration(item.ttl_seconds) }}
            </template>
            <template #item.issued_at="{ item }">
              <span class="font-mono text-caption">{{ formatTime(item.issued_at) }}</span>
            </template>
            <template #item.expires_at="{ item }">
              <span class="font-mono text-caption">{{ formatTime(item.expires_at) }}</span>
            </template>
            <template #item.actions="{ item }">
              <v-btn
                v-if="item.state === 'ISSUED' && canRevokeBg"
                size="x-small"
                color="error"
                variant="tonal"
                :loading="revokingJti === item.jti"
                @click="revokeSession(item)"
              >
                Revocă
              </v-btn>
              <v-tooltip v-else-if="item.state === 'ISSUED'" text="Necesită platform-engineer / sre-oncall." location="left">
                <template v-slot:activator="{ props: tProps }">
                  <span v-bind="tProps" class="text-caption text-secondary">—</span>
                </template>
              </v-tooltip>
              <span v-else class="text-caption text-secondary">—</span>
            </template>
          </v-data-table>
        </v-card>
      </v-window-item>

      <!-- Node agents -->
      <v-window-item value="nodes">
        <v-card flat class="gc-border">
          <v-data-table
            :items="nodes"
            :headers="nodesHeaders"
            :loading="loadingNodes"
            density="compact"
            items-per-page="25"
          >
            <template #item.healthy="{ item }">
              <v-chip
                size="x-small"
                :color="item.healthy ? 'success' : 'error'"
                variant="tonal"
              >
                {{ item.healthy ? 'OK' : 'STALE' }}
              </v-chip>
            </template>
            <template #item.mode="{ item }">
              <v-chip size="x-small" :color="item.mode === 'deception' ? 'warning' : 'primary'" variant="tonal">
                {{ item.mode || '—' }}
              </v-chip>
            </template>
            <template #item.protected_paths="{ item }">
              <span class="text-caption">{{ item.protected_paths?.length || 0 }}</span>
              <v-tooltip v-if="item.protected_paths?.length" location="bottom">
                <template #activator="{ props }">
                  <v-icon v-bind="props" size="x-small" class="ml-1">mdi-information-outline</v-icon>
                </template>
                <pre class="font-mono text-caption">{{ item.protected_paths.join('\n') }}</pre>
              </v-tooltip>
            </template>
            <template #item.authorized_pids="{ item }">
              <v-chip
                size="x-small"
                :color="item.authorized_pids?.length ? 'warning' : 'default'"
                variant="tonal"
              >
                {{ item.authorized_pids?.length || 0 }}
              </v-chip>
              <v-tooltip v-if="item.authorized_pids?.length" location="bottom">
                <template #activator="{ props }">
                  <v-icon v-bind="props" size="x-small" class="ml-1">mdi-account-key</v-icon>
                </template>
                <pre class="font-mono text-caption">{{
                  item.authorized_pids.map((p: AuthorizedPID) => `pid=${p.pid} until ${formatTime(p.expires_at)}`).join('\n')
                }}</pre>
              </v-tooltip>
            </template>
            <template #item.mounted_honeypots="{ item }">
              <v-chip size="x-small" :color="item.mounted_honeypots?.length ? 'warning' : 'default'" variant="tonal">
                {{ item.mounted_honeypots?.length || 0 }}
              </v-chip>
            </template>
            <template #item.received_at="{ item }">
              <span class="font-mono text-caption">{{ formatTime(item.received_at) }}</span>
              <span class="text-caption text-secondary ml-2">({{ Math.round(item.age_seconds || 0) }}s)</span>
            </template>
            <template #item.version="{ item }">
              <code class="text-caption">{{ item.version || '—' }}</code>
            </template>
          </v-data-table>
        </v-card>
      </v-window-item>

      <!-- Audit feed -->
      <v-window-item value="audit">
        <v-card flat class="gc-border">
          <v-card-title class="d-flex align-center ga-3">
            <span class="text-subtitle-1">Audit feed (kernel ringbuf → backend)</span>
            <v-spacer />
            <v-select
              v-model="auditFilters.node"
              :items="['', ...knownNodes]"
              label="Filtru nod"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 240px"
              clearable
              @update:model-value="fetchAudit"
            />
            <v-select
              v-model="auditFilters.action"
              :items="['', 'denied', 'allowed']"
              label="Filtru acțiune"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 200px"
              clearable
              @update:model-value="fetchAudit"
            />
            <v-btn icon="mdi-refresh" size="small" variant="text" :loading="loadingAudit" @click="fetchAudit" />
          </v-card-title>
          <v-divider />
          <v-data-table
            :items="filteredAudit"
            :headers="auditHeaders"
            :loading="loadingAudit"
            density="compact"
            items-per-page="50"
          >
            <template #item.action="{ item }">
              <v-chip size="x-small" :color="actionColor(item.action)" variant="tonal">
                {{ item.action || '—' }}
              </v-chip>
            </template>
            <template #item.received_at="{ item }">
              <span class="font-mono text-caption">{{ formatTime(item.received_at) }}</span>
            </template>
            <template #item.path="{ item }">
              <code class="text-caption">{{ item.path || '(unresolved)' }}</code>
            </template>
            <template #item.comm="{ item }">
              <code class="text-caption">{{ item.comm || '—' }}</code>
              <span v-if="item.pcomm" class="text-caption text-secondary"> ← {{ item.pcomm }}</span>
            </template>
          </v-data-table>
        </v-card>
      </v-window-item>

      <!-- Policies -->
      <v-window-item value="policies">
        <v-card flat class="gc-border pa-6">
          <v-card-title class="px-0 text-subtitle-1">
            <v-icon class="mr-2" color="info">mdi-shield-account-outline</v-icon>
            NodeProtectionPolicy CRD Resources
          </v-card-title>
          <v-card-subtitle class="px-0 mb-4 text-caption text-secondary">
            Politici de protecție a nodurilor Kubernetes (cluster-scoped). Definesc căile protejate și modul de operare.
          </v-card-subtitle>

          <v-data-table
            :headers="policiesHeaders"
            :items="policies"
            :loading="loadingPolicies"
            density="compact"
            class="gc-border"
            flat
          >
            <template #no-data>
              <div class="text-center pa-4 text-caption text-secondary">
                {{ loadingPolicies ? 'Se încarcă politici...' : 'Nicio politică NodeProtectionPolicy configurată.' }}
              </div>
            </template>
            <template #item.name="{ item }">
              <code class="text-caption">{{ item.metadata?.name || '—' }}</code>
            </template>
            <template #item.nodeSelector="{ item }">
              <span class="text-caption">
                {{ Object.keys(item.spec?.nodeSelector || {}).length > 0 ? Object.entries(item.spec.nodeSelector).map(([k, v]: [string, any]) => `${k}=${v}`).join(', ') : '(all nodes)' }}
              </span>
            </template>
            <template #item.protectedPaths="{ item }">
              <v-tooltip :text="(item.spec?.protectedPaths || []).join(', ')">
                <template #activator="{ props }">
                  <v-chip v-bind="props" size="small" variant="tonal">
                    {{ (item.spec?.protectedPaths || []).length }} căi
                  </v-chip>
                </template>
              </v-tooltip>
            </template>
            <template #item.mode="{ item }">
              <v-chip :color="item.spec?.mode === 'deception' ? 'warning' : 'info'" size="small" variant="tonal" label>
                {{ item.spec?.mode || 'deny' }}
              </v-chip>
            </template>
            <template #item.maxTtl="{ item }">
              <span class="text-caption font-mono">{{ item.spec?.breakGlass?.maxTTLSeconds || '—' }}s</span>
            </template>
          </v-data-table>
        </v-card>
      </v-window-item>
    </v-window>

    <!-- Issued token dialog (one-time view) -->
    <v-dialog v-model="issuedTokenDialog.open" max-width="900">
      <v-card class="gc-border" flat>
        <v-card-title class="text-subtitle-1">
          <v-icon class="mr-2" color="warning">mdi-key-variant</v-icon>
          Token emis · {{ issuedTokenDialog.session?.node }}
        </v-card-title>
        <v-card-subtitle class="text-caption text-secondary">
          Token-ul nu va mai fi vizibil după închidere. Copiază-l ACUM.
        </v-card-subtitle>
        <v-card-text>
          <div class="text-caption mb-1">jti</div>
          <div class="font-mono mb-3">{{ issuedTokenDialog.session?.jti }}</div>
          <div class="text-caption mb-1">JWT (EdDSA)</div>
          <v-textarea
            :model-value="issuedTokenDialog.session?.token"
            readonly
            variant="outlined"
            density="compact"
            rows="4"
            class="font-mono"
          />
          <div class="d-flex ga-2 mt-3">
            <v-btn
              prepend-icon="mdi-content-copy"
              color="primary"
              @click="issuedTokenDialog.session && copyToClipboard(issuedTokenDialog.session.token!)"
            >
              Copy JWT
            </v-btn>
            <v-btn
              prepend-icon="mdi-console"
              color="secondary"
              variant="outlined"
              @click="issuedTokenDialog.session && copyKnockCommand(issuedTokenDialog.session)"
            >
              Copy zta-cli command
            </v-btn>
            <v-spacer />
            <v-btn variant="text" @click="issuedTokenDialog.open = false">Închide</v-btn>
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>
  </div>
</template>

<style scoped>
.font-mono {
  font-family: 'Roboto Mono', monospace;
}
.gc-border {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important;
  border-radius: 12px;
}
</style>
