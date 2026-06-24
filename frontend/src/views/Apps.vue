<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, onUnmounted, ref, watch } from 'vue'
import type { AxiosError, AxiosResponse } from 'axios'
import { useTheme } from 'vuetify'
// Monaco is heavy (~MBs). Load it only when the builder reaches the "Review"
// step (v-stepper-window renders steps lazily), not on every /apps navigation.
const VueMonacoEditor = defineAsyncComponent(() =>
  import('@guolao/vue-monaco-editor').then((m) => m.VueMonacoEditor),
)
import { api } from '../api/axios'
import BuildLedgerGraph from '../components/BuildLedgerGraph.vue'
import ProvisioningPlan from '../components/ProvisioningPlan.vue'
import ReconcileFlow from '../components/ReconcileFlow.vue'
import EventsTimelinePanel from '../components/EventsTimelinePanel.vue'
import VerificationStatusTable from '../components/VerificationStatusTable.vue'
import CelEvaluationsTable from '../components/CelEvaluationsTable.vue'
import ErrorLogPanel from '../components/ErrorLogPanel.vue'
import SbomTree from '../components/SbomTree.vue'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'
import { useAuthStore } from '../store/auth'
import { useIntegrityStream, type KopfEvent, type IntegrityStreamError } from '../composables/useIntegrityStream'
import { WAF_MODES, WAF_PROFILES, ON_COMPROMISE_ACTIONS, ALLOWED_REGISTRY, FORBIDDEN_TAG, DEFAULT_NAMESPACE } from '../constants/zta'

const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()
const auth = useAuthStore()
const theme = useTheme()
const canWriteApps = computed(() => auth.can('apps:write'))
const isDarkTheme = computed(() => theme.global.current.value.dark)

const monacoOptions = {
  readOnly: true,
  minimap: { enabled: false },
  scrollBeyondLastLine: false,
  fontSize: 12,
  lineNumbers: 'on' as const,
  padding: { top: 8, bottom: 8 },
  automaticLayout: true,
  wordWrap: 'on' as const,
  folding: true,
  renderLineHighlight: 'none' as const,
  scrollbar: { verticalScrollbarSize: 6, horizontalScrollbarSize: 6 },
}

const namespaces = ref<string[]>([DEFAULT_NAMESPACE])
const isLoadingNamespaces = ref(false)

const step = ref(1)
const builderPanels = ref<number[]>([])
const showIntegrityLedger = ref(false)
const isSubmitting = ref(false)
const selectedApplication = ref('')
const integrityDetails = ref<any | null>(null)
const isRevalidating = ref(false)
const isRetrying = ref(false)
const integrityPoller = ref<number | null>(null)
// Tracks when the current polling session started so we can ramp the
// interval (2s → 4s → 8s) — fast feedback right after submit, then back off.
const pollingStartedAt = ref<number>(0)

const editingApp = ref<{ namespace: string; name: string } | null>(null)
const isEditingApp = computed(() => editingApp.value !== null)

function defaultIngress() {
  return {
    enabled: false,
    host: '',
    className: 'nginx',
    path: '/',
    pathType: 'Prefix',
    servicePort: 80,
    oauth2Enabled: true,
    authUrl: '',
    authSignin: '',
    authResponseHeaders: '',
    oauth2ServiceName: 'oauth2-proxy',
    oauth2ServiceNamespace: 'oauth2-proxy',
    oauth2ServicePort: 80,
    oauth2IngressPath: '/oauth2',
    groupsHeader: 'X-Forwarded-Groups',
    groupsHeaderFallback: 'X-Auth-Request-Groups',
  }
}

function defaultForm() {
  return {
    name: '',
    namespace: DEFAULT_NAMESPACE,
    image: '',
    replicas: 1,
    securityPolicyName: '',
    ingressAllowedFrom: [{ namespace: '' }] as Array<{ namespace: string }>,
    egressAllowedTo: [{ namespace: '', ports: '5432' }] as Array<{ namespace: string; ports: string }>,
    wafMode: 'Block',
    wafProfile: 'REST-API',
    allowedPaths: '/tmp/app-data',
    onCompromise: 'Isolate',
    ingress: defaultIngress(),
  }
}

const form = ref(defaultForm())

function parsePorts(s: string): number[] {
  return String(s || '')
    .split(',')
    .map((x) => Number.parseInt(x.trim(), 10))
    .filter(Number.isFinite)
}

function addIngressRule() { form.value.ingressAllowedFrom.push({ namespace: '' }) }
function removeIngressRule(i: number) {
  if (form.value.ingressAllowedFrom.length > 1) form.value.ingressAllowedFrom.splice(i, 1)
}
function addEgressRule() { form.value.egressAllowedTo.push({ namespace: '', ports: '' }) }
function removeEgressRule(i: number) {
  if (form.value.egressAllowedTo.length > 1) form.value.egressAllowedTo.splice(i, 1)
}

function buildNetworkZeroTrust() {
  return {
    ingressAllowedFrom: form.value.ingressAllowedFrom
      .filter((r) => r.namespace && r.namespace.trim())
      .map((r) => ({ namespace: r.namespace.trim() })),
    egressAllowedTo: form.value.egressAllowedTo
      .filter((r) => r.namespace && r.namespace.trim())
      .map((r) => ({ namespace: r.namespace.trim(), ports: parsePorts(r.ports) })),
  }
}

function buildIngress() {
  const ing = form.value.ingress
  if (!ing.enabled) return { enabled: false }
  return {
    enabled: true,
    host: ing.host,
    className: ing.className,
    path: ing.path,
    pathType: ing.pathType,
    servicePort: Number(ing.servicePort) || 80,
    oauth2Enabled: ing.oauth2Enabled,
    authUrl: ing.authUrl,
    authSignin: ing.authSignin,
    authResponseHeaders: ing.authResponseHeaders,
    oauth2ServiceName: ing.oauth2ServiceName,
    oauth2ServiceNamespace: ing.oauth2ServiceNamespace,
    oauth2ServicePort: Number(ing.oauth2ServicePort) || 80,
    oauth2IngressPath: ing.oauth2IngressPath,
    groupsHeader: ing.groupsHeader,
    groupsHeaderFallback: ing.groupsHeaderFallback,
  }
}

function resetBuilder() {
  form.value = defaultForm()
  editingApp.value = null
  step.value = 1
}
function cancelEditApp() { resetBuilder() }

function startEditApp() {
  const sel = selectedApplication.value
  if (!sel) return
  const [ns, nm] = sel.split('/')
  const app = applications.value.find((a: any) => a.metadata?.namespace === ns && a.metadata?.name === nm)
  if (!app) return
  const spec = app.spec || {}
  const nzt = spec.networkZeroTrust || {}
  const ingFrom = (nzt.ingressAllowedFrom || []).map((r: any) => ({ namespace: r.namespace || '' }))
  const egTo = (nzt.egressAllowedTo || []).map((r: any) => ({ namespace: r.namespace || '', ports: (r.ports || []).join(', ') }))
  form.value = {
    name: app.metadata.name,
    namespace: app.metadata.namespace,
    image: spec.image || '',
    replicas: spec.replicas || 1,
    securityPolicyName: spec.securityPolicyRef?.name || '',
    ingressAllowedFrom: ingFrom.length ? ingFrom : [{ namespace: '' }],
    egressAllowedTo: egTo.length ? egTo : [{ namespace: '', ports: '' }],
    wafMode: spec.wafConfig?.mode || 'Block',
    wafProfile: spec.wafConfig?.appProfile || 'REST-API',
    allowedPaths: (spec.runtimeSecurity?.allowedPaths || []).join(', '),
    onCompromise: spec.runtimeSecurity?.onCompromise || 'Isolate',
    ingress: { ...defaultIngress(), ...(spec.ingress || {}) },
  }
  editingApp.value = { namespace: ns, name: nm }
  builderPanels.value = [0]
  step.value = 1
  if (typeof window !== 'undefined') window.scrollTo({ top: 0, behavior: 'smooth' })
}

const wafProfiles = WAF_PROFILES
const applications = computed(() => dashboardStore.applications)
const applicationOptions = computed(() => dashboardStore.applicationOptions)

// Rich items for the autocomplete: each row carries the value (key used by
// the watcher to split on '/'), the searchable title, and the original app
// payload accessed in the custom item slot as `item.raw.app`.
const applicationItems = computed(() =>
  applications.value.map((app: any) => ({
    value: `${app.metadata.namespace}/${app.metadata.name}`,
    title: app.metadata.name,
    app,
  }))
)
const isLoadingApplications = computed(() => dashboardStore.loadingApplications)
const isLoadingIntegrity = computed(() => dashboardStore.loadingIntegrity)
// SCA dropdown: replaces free-text input so the user cannot reference a
// policy that does not exist in the cluster.
const policyOptions = computed(() => dashboardStore.policyOptions)
const isLoadingPolicies = computed(() => dashboardStore.loadingPolicies)

// Factual cause of an audit-mode (Alert) state, derived from the real signals
// (not hardcoded): the triggering violation + the actual manifest-hash state.
// The alert may come from a Trivy vulnerability policy (onVulnerabilityFound:
// Alert), a CEL Alert rule, or a strict-manifest-hash drift in Alert mode.
function auditAlertCause(summary: any): string {
  const s = summary || {}
  const violations: string[] = Array.isArray(s.violations) ? s.violations.map(String) : []
  if (s.hasHashMismatch || violations.find((v) => /hash|infra|drift/i.test(v))) {
    return 'manifest hash drift'
  }
  if (violations.find((v) => /vulnerab|trivy/i.test(v))) return 'vulnerability policy (Trivy)'
  if (violations.length) {
    return violations[0] + (violations.length > 1 ? ` (+${violations.length - 1} more)` : '')
  }
  return 'non-blocking policy alert'
}

// Exact manifest-hash state for this app (matched / drifted / not enforced).
function manifestHashState(summary: any): string {
  const s = summary || {}
  if (s.hasHashMismatch) return 'drifted (expected ≠ computed)'
  if (s.expectedInfraHash) return 'matches attested hash'
  return 'not enforced'
}

function applicationSeverity(app: any) {
  const summary = app?.summary || {}
  // Audit-mode (enforcementAction: Alert) — the operator created the
  // Deployment but flagged a non-blocking violation. Render orange to
  // distinguish from both hard failures (red) and clean state (green).
  if (summary.isAuditAlert || (summary.securityState || '').toLowerCase() === 'alert') return 'warning'
  if (summary.hasErrors || summary.hasHashMismatch) return 'error'
  if (summary.hasViolations || !['Compliant', 'PendingProvenance'].includes(summary.securityState || '')) return 'error'
  if (summary.trustLevel === 'Verified') return 'success'
  return 'warning'
}

function applicationIcon(app: any) {
  const summary = app?.summary || {}
  if (summary.isAuditAlert || (summary.securityState || '').toLowerCase() === 'alert') return 'mdi-shield-alert-outline'
  if (summary.hasHashMismatch) return 'mdi-file-document-alert'
  if (summary.hasErrors) return 'mdi-alert-octagon'
  if (summary.hasViolations || !['Compliant', 'PendingProvenance'].includes(summary.securityState || '')) return 'mdi-shield-alert'
  if (summary.trustLevel === 'Verified') return 'mdi-shield-check'
  return 'mdi-progress-clock'
}

function applicationBadge(app: any) {
  const summary = app?.summary || {}
  if (summary.isAuditAlert || (summary.securityState || '').toLowerCase() === 'alert') return 'Audit Mode'
  if (summary.hasHashMismatch) return 'Manifest Mismatch'
  if (summary.hasErrors) return 'Verification Failed'
  if (summary.hasViolations) return 'Compliance Failed'
  if (summary.trustLevel === 'Verified') return 'Verified'
  return 'Pending'
}

function guacIngestionSeverity(app: any): 'success' | 'info' | 'warning' | 'error' | null {
  const s = (app?.summary?.guacIngestion?.status || '').toLowerCase()
  if (s === 'completed') return 'success'
  if (s === 'inprogress') return 'info'
  if (s === 'failed') return 'error'
  if (s === 'disabled' || s === '') return null
  return 'warning'
}

function guacIngestionLabel(app: any): string {
  const s = (app?.summary?.guacIngestion?.status || '').toLowerCase()
  if (s === 'completed') return 'Threat Intel ✓'
  if (s === 'inprogress') return 'Fetching Intel…'
  if (s === 'failed') return 'Intel Failed'
  if (s === 'disabled') return 'Intel Off'
  return ''
}

function ledgerColor(status: string) {
  if (status === 'error' || status === 'blocked') return 'error'
  if (status === 'verified') return 'success'
  return 'warning'
}

function ledgerIcon(status: string, itemId: string) {
  if (itemId === 'manifest-hash' && status !== 'verified') return 'mdi-file-document-alert'
  if (itemId === 'operator-error') return 'mdi-alert-octagon'
  if (status === 'error') return 'mdi-alert-circle'
  if (status === 'blocked') return 'mdi-close-circle'
  if (status === 'verified') return 'mdi-check-circle'
  return 'mdi-progress-clock'
}

function formatLedgerDetails(details: unknown) {
  if (typeof details === 'string') return details
  if (details && typeof details === 'object') {
    return JSON.stringify(details, null, 2)
  }
  return String(details ?? '')
}

function prettifyKey(key: string) {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/^./, (char) => char.toUpperCase())
}

function ledgerDetailsEntries(details: unknown) {
  if (!details || typeof details !== 'object') {
    const value = formatLedgerDetails(details)
    return value ? [{ key: 'Details', value }] : []
  }

  return Object.entries(details as Record<string, unknown>).map(([key, value]) => {
    if (Array.isArray(value)) {
      return {
        key: prettifyKey(key),
        value: value
          .map((item) => (typeof item === 'object' ? JSON.stringify(item) : String(item)))
          .join(', '),
      }
    }
    if (value && typeof value === 'object') {
      return { key: prettifyKey(key), value: JSON.stringify(value) }
    }
    return { key: prettifyKey(key), value: String(value ?? '') }
  })
}

async function copyToClipboard(value: string) {
  if (!value) return
  await navigator.clipboard.writeText(value)
}

let pollingInFlight = false

// Adaptive polling cadence: the operator transitions through Validating →
// Provisioning quickly at the start, then sits in a long Cosign/Trivy scan.
// Polling fast at the beginning gives instant UI feedback, then backs off
// to avoid hammering the backend during the long-running phases.
function _nextPollDelayMs(): number {
  const elapsed = Date.now() - pollingStartedAt.value
  if (elapsed < 10_000) return 2000   // first 10s after submit: 2s cadence
  if (elapsed < 40_000) return 4000   // next 30s: 4s cadence
  return 8000                          // after 40s: relaxed 8s cadence
}

async function _pollOnce() {
  if (pollingInFlight) {
    _schedulePoll()
    return
  }
  const currentApp = selectedApplication.value
  if (!currentApp) return
  const [namespace, name] = currentApp.split('/')
  if (!namespace || !name) return
  pollingInFlight = true
  try {
    const payload = await dashboardStore.fetchIntegrity(namespace, name, true)
    if (selectedApplication.value !== currentApp) return
    integrityDetails.value = payload
    if (isIntegrityFlowStable(payload)) {
      stopIntegrityPolling()
      return
    }
  } catch (exc: any) {
    // ZTA disappeared (deleted while polling). Stop, clear, notify the
    // user once. Avoids the "404 spam" loop where polling kept hitting
    // a deleted resource.
    const status = exc?.response?.status
    if (status === 404 && selectedApplication.value === currentApp) {
      stopIntegrityPolling()
      selectedApplication.value = ''
      integrityDetails.value = null
      kopfEvents.value = []
      notifyStore.addAlert({
        error_code: 'ZTA_DELETED',
        message: `Aplicația ${currentApp} a fost ștearsă din cluster. Vizualizarea s-a închis automat.`,
        technical_details: String(exc?.message || ''),
        component: 'INTEGRITY_POLLING',
        trace_id: `DEL-${Math.random().toString(36).substring(2)}`,
        action_required: 'Selectați altă aplicație din listă sau aplicați un manifest nou.',
        type: 'warning',
      })
      return
    }
    // Other errors: let them bubble up to the global axios interceptor.
    throw exc
  } finally {
    pollingInFlight = false
  }
  _schedulePoll()
}

function _schedulePoll() {
  integrityPoller.value = window.setTimeout(_pollOnce, _nextPollDelayMs())
}

function startIntegrityPolling() {
  stopIntegrityPolling()
  if (!selectedApplication.value) return
  pollingInFlight = false
  pollingStartedAt.value = Date.now()
  _schedulePoll()
}

function stopIntegrityPolling() {
  if (integrityPoller.value !== null) {
    window.clearTimeout(integrityPoller.value)
    integrityPoller.value = null
  }
}

// Real-time SSE subscription: replaces polling when the backend stream
// is healthy. Falls back to polling after repeated connection errors.
const kopfEvents = ref<KopfEvent[]>([])
const streamConnected = ref(false)
const streamError = ref<IntegrityStreamError | null>(null)
const stream = useIntegrityStream({
  onSnapshot: (payload) => {
    if (!selectedApplication.value) return
    const [ns, nm] = selectedApplication.value.split('/')
    if (!ns || !nm) return
    integrityDetails.value = payload
    dashboardStore.setIntegrity(ns, nm, payload)
    streamConnected.value = true
    // Successful snapshot clears any transient error displayed in the banner.
    if (streamError.value?.recoverable) streamError.value = null
  },
  onEvents: (events) => {
    // Append + dedupe by uid; keep at most last 200.
    const seen = new Set(kopfEvents.value.map((e) => e.uid))
    for (const evt of events) {
      if (!seen.has(evt.uid)) kopfEvents.value.push(evt)
    }
    if (kopfEvents.value.length > 200) {
      kopfEvents.value = kopfEvents.value.slice(-200)
    }
  },
  onError: (err) => {
    streamError.value = err
    streamConnected.value = false
    // Special handling: ZTA was deleted while the user was watching it.
    // Close the view, clear all related state, and surface an informational
    // banner. Polling fallback would just keep hitting a 404 endpoint.
    if (err.code === 'zta-not-found') {
      const deletedApp = selectedApplication.value
      selectedApplication.value = ''
      integrityDetails.value = null
      kopfEvents.value = []
      stopIntegrityPolling()
      notifyStore.addAlert({
        error_code: 'ZTA_DELETED',
        message: `Aplicația ${deletedApp} a fost ștearsă din cluster. Vizualizarea s-a închis automat.`,
        technical_details: err.message,
        component: 'INTEGRITY_STREAM',
        trace_id: `DEL-${Math.random().toString(36).substring(2)}`,
        action_required: 'Selectați altă aplicație din listă sau aplicați un manifest nou.',
        type: 'warning',
      })
      return
    }
    // Other non-recoverable conditions still surface in the global
    // notification bar; the inline ErrorLogPanel banner stays for context.
    if (!err.recoverable) {
      notifyStore.addAlert({
        error_code: `STREAM_${err.code.toUpperCase().replace(/-/g, '_')}`,
        message: err.message,
        technical_details: JSON.stringify(err.details || {}, null, 2),
        component: 'INTEGRITY_STREAM',
        trace_id: `STR-${Math.random().toString(36).substring(2)}`,
        action_required: 'Stream-ul SSE s-a închis.',
        type: 'error',
      })
    }
  },
  onFallback: () => {
    streamConnected.value = false
    startIntegrityPolling()
  },
})

async function startIntegrityRealtime() {
  if (!selectedApplication.value) return
  const [ns, nm] = selectedApplication.value.split('/')
  if (!ns || !nm) return
  kopfEvents.value = []
  // Initial backfill of the events timeline before the stream kicks in.
  try {
    const resp = await api.get(`/integrity/applications/${ns}/${nm}/events`)
    if (Array.isArray(resp.data)) kopfEvents.value = resp.data as KopfEvent[]
  } catch { /* non-fatal */ }
  await stream.start(ns, nm)
}

function stopIntegrityRealtime() {
  stream.stop()
  stopIntegrityPolling()
}

async function handleRetryReconcile() {
  if (!selectedApplication.value || isRetrying.value) return
  const [namespace, name] = selectedApplication.value.split('/')
  if (!namespace || !name) return
  isRetrying.value = true
  try {
    await dashboardStore.triggerZtaReconcile(namespace, name)
    notifyStore.addAlert({
      error_code: 'ZTA_RECONCILE_TRIGGERED',
      message: `Re-evaluation pornită pentru ${name}. Operatorul reia analiza...`,
      technical_details: 'Annotation zta.devsecops/reconciled-at patched on the CRD',
      component: 'ZTA_OPERATOR',
      trace_id: `RTR-${Math.random().toString(36).substring(2)}`,
      action_required: 'Aşteptaţi câteva secunde pentru actualizarea stagiilor.',
      type: 'warning',
    })
    // Re-arm the realtime stream so the user sees the new state immediately.
    await startIntegrityRealtime()
  } finally {
    isRetrying.value = false
  }
}

function sanctionDotColor(event: any) {
  const severity = String(event?.severity || '').toLowerCase()
  if (severity === 'success') return 'success'
  if (severity === 'warning') return 'warning'
  if (severity === 'error') return 'error'

  const action = String(event?.action || '').toLowerCase()
  if (action.includes('verified')) return 'success'
  if (action.includes('alert')) return 'error'
  if (action.includes('kill') || action.includes('isolate') || action.includes('blocked') || action.includes('noncompliant')) return 'error'
  return 'warning'
}

function isIntegrityFlowStable(payload: any): boolean {
  if (!payload) return false
  const phase = String(payload?.application?.summary?.phase || payload?.reconcileFlow?.phase || '')
  if (phase === 'Degraded' || phase === 'Failed_SupplyChain') return true
  if (phase === 'Running') {
    const stages = payload?.reconcileFlow?.stages || []
    return !stages.some((s: any) => s?.status === 'running')
  }
  return false
}

const selectedAppSummary = computed(() => integrityDetails.value?.application?.summary || {})

const integrityCriticalIssues = computed(() => {
  const details = integrityDetails.value
  if (!details) return []

  const application = details.application || {}
  const summary = application.summary || {}
  const issues = []

  if (summary.lastError) {
    issues.push({
      title: summary.errorCategory || (summary.hasHashMismatch ? 'Manifest Hash Mismatch' : 'Verification Failure'),
      message: summary.lastErrorSummary || summary.lastError,
      icon: summary.hasHashMismatch ? 'mdi-file-document-alert' : 'mdi-alert-octagon',
    })
  }

  if (summary.hasHashMismatch) {
    issues.push({
      title: 'Expected Hash Does Not Match Applied Spec',
      message: `expected=${summary.expectedInfraHash || 'n/a'} computed=${summary.computedInfraHash || 'n/a'}`,
      icon: 'mdi-compare-remove',
    })
  }

  for (const violation of summary.violations || []) {
    issues.push({
      title: 'Compliance Violation',
      message: String(violation),
      icon: 'mdi-shield-alert',
    })
  }

  return issues
})

const imageError = computed(() => {
  if (!form.value.image) return ''
  if (!form.value.image.startsWith(ALLOWED_REGISTRY)) return 'Violation: Imaginea trebuie să fie din ghcr.io/'
  if (form.value.image.endsWith(FORBIDDEN_TAG)) return 'Violation: Tag-ul "latest" este strict interzis în producție.'
  return ''
})

const isStep1Valid = computed(() => {
  return form.value.name.length > 2 && form.value.image.length > 5 && !imageError.value && form.value.securityPolicyName.length > 1
})

const step1ValidationMessages = computed(() => {
  const msgs: string[] = []
  if (!form.value.name || form.value.name.length <= 2) msgs.push('App name must be at least 3 characters')
  if (!form.value.securityPolicyName) msgs.push('Security policy (SCA) must be selected')
  if (!form.value.image) msgs.push('Container image is required')
  else if (imageError.value) msgs.push(imageError.value)
  return msgs
})

function formatSanctionTimestamp(ts?: string): string {
  if (!ts) return 'timestamp unavailable'
  try {
    return new Date(ts).toLocaleString('en-GB', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    })
  } catch {
    return ts
  }
}

const yamlPreview = computed(() => {
  const allowedPaths = form.value.allowedPaths
    .split(',')
    .map(item => item.trim())
    .filter(Boolean)

  const nzt = buildNetworkZeroTrust()
  const ingressLines = nzt.ingressAllowedFrom.length
    ? nzt.ingressAllowedFrom.map(r => `      - namespace: ${r.namespace}`).join('\n')
    : '      []'
  const egressLines = nzt.egressAllowedTo.length
    ? nzt.egressAllowedTo.map(r => `      - namespace: ${r.namespace}\n        ports: [${r.ports.join(', ')}]`).join('\n')
    : '      []'

  const ing = buildIngress()
  let ingressBlock = `  ingress:\n    enabled: false`
  if (ing.enabled) {
    ingressBlock = `  ingress:
    enabled: true
    host: ${ing.host || ''}
    className: ${ing.className}
    path: ${ing.path}
    pathType: ${ing.pathType}
    servicePort: ${ing.servicePort}
    oauth2Enabled: ${ing.oauth2Enabled}`
  }

  return `apiVersion: devsecops.licenta.ro/v1
kind: ZeroTrustApplication
metadata:
  name: ${form.value.name || 'myapp'}
  namespace: ${form.value.namespace || 'default'}
spec:
  image: ${form.value.image || 'ghcr.io/org/app:v1'}
  replicas: ${form.value.replicas}
  securityPolicyRef:
    name: ${form.value.securityPolicyName || 'demo-app-security-policy'}
  networkZeroTrust:
    ingressAllowedFrom:
${ingressLines}
    egressAllowedTo:
${egressLines}
  wafConfig:
    mode: ${form.value.wafMode}
    appProfile: ${form.value.wafProfile}
  runtimeSecurity:
    allowedPaths:
${allowedPaths.map(path => `      - ${path}`).join('\n')}
    onCompromise: ${form.value.onCompromise}
${ingressBlock}`
})

onMounted(() => {
  dashboardStore.fetchApplications(true).catch(() => undefined)
  // Populate the SCA dropdown so the builder cannot reference a missing policy.
  dashboardStore.fetchPolicies(true).catch(() => undefined)
  // Fetch cluster namespaces for the target namespace and network policy dropdowns.
  isLoadingNamespaces.value = true
  api.get('/jit/namespaces')
    .then((res) => { namespaces.value = res.data.namespaces || ['default'] })
    .catch(() => undefined)
    .finally(() => { isLoadingNamespaces.value = false })
})

onUnmounted(() => {
  stopIntegrityRealtime()
})

watch(selectedApplication, async (value) => {
  stopIntegrityRealtime()
  if (!value) {
    integrityDetails.value = null
    kopfEvents.value = []
    return
  }

  const [namespace, name] = value.split('/')
  const payload = await dashboardStore.fetchIntegrity(namespace, name, true)
  integrityDetails.value = payload
  // Always subscribe to SSE — even for stable flows we want to catch
  // late events (GUAC async ingestion, runtime drift sanctions, etc.).
  await startIntegrityRealtime()
})

async function revalidateIntegrity() {
  if (!selectedApplication.value) return
  const [namespace, name] = selectedApplication.value.split('/')
  isRevalidating.value = true
  try {
    const response = await api.post(`/integrity/applications/${namespace}/${name}/revalidate`)
    integrityDetails.value = response.data
    dashboardStore.setIntegrity(namespace, name, response.data)
    if (!isIntegrityFlowStable(response.data)) {
      await startIntegrityRealtime()
    }
    notifyStore.addAlert({
      error_code: 'INTEGRITY_REVALIDATED',
      message: 'Revalidarea OCI a fost executată pentru aplicația selectată.',
      technical_details: JSON.stringify(response.data.revalidation, null, 2),
      component: 'INTEGRITY_ENGINE',
      trace_id: Math.random().toString(36).substring(2),
      action_required: 'Verifică statusul revalidation și grafurile VBBI.',
      type: 'warning'
    })
  } finally {
    isRevalidating.value = false
  }
}

function submitDeclaration() {
  isSubmitting.value = true

  const payload = {
    name: form.value.name || 'myapp',
    namespace: form.value.namespace || 'default',
    labels: { app: form.value.name },
    annotations: { 'dashboard.devsecops/source': 'frontend' },
    image: form.value.image,
    replicas: form.value.replicas,
    securityPolicyRef: {
      name: form.value.securityPolicyName,
    },
    networkZeroTrust: buildNetworkZeroTrust(),
    wafConfig: {
      mode: form.value.wafMode,
      appProfile: form.value.wafProfile,
    },
    runtimeSecurity: {
      allowedPaths: form.value.allowedPaths.split(',').map(item => item.trim()).filter(Boolean),
      onCompromise: form.value.onCompromise,
    },
    ingress: buildIngress(),
  }

  const editing = editingApp.value
  const request = editing
    ? api.put(`/zta/${editing.namespace}/${editing.name}`, payload)
    : api.post('/zta/', payload)

  request
    .then((response: AxiosResponse<any>) => {
      isSubmitting.value = false
      step.value = 1
      const wasEditing = !!editing
      editingApp.value = null
      const savedSelection = selectedApplication.value
      dashboardStore.fetchApplications(true)
        .then(() => {
          if (savedSelection && dashboardStore.applicationOptions.some(opt => opt.value === savedSelection)) {
            selectedApplication.value = savedSelection
          }
        })
        .catch(() => undefined)
      dashboardStore.fetchOverview().catch(() => undefined)
      notifyStore.addAlert({
        error_code: wasEditing ? 'ZTA_UPDATED_SUCCESS' : 'ZTA_CREATED_SUCCESS',
        message: `Aplicația ZTA ${response.data.metadata?.name || 'cu succes'} a fost ${wasEditing ? 'actualizată' : 'creată'}!`,
        technical_details: JSON.stringify(response.data, null, 2),
        component: 'ZTA_BUILDER',
        trace_id: response.data.metadata?.uid || `TRC-${Math.random().toString(36).substring(2)}`,
        action_required: 'Nu este necesară nicio altă acțiune. Operatorul cilium va prelua noile politici.',
        type: 'warning' // 'warning' in Pinia store is auto-dismissed (green auto-dismiss workaround)
      })
    })
    .catch((error: AxiosError<any>) => {
       isSubmitting.value = false
       // Axios interceptor deja plasează erorile 500/400 în store-ul notify.
       // Dar aici, dacã eroarea nu e complet formatată, ajutãm UI-ul
       if (!error.response) {
         notifyStore.addAlert({
           error_code: 'ZTA_BUILD_FAILURE',
           message: 'Crearea a esuat în pre-flight validation.',
           technical_details: error.message,
           component: 'ZTA_BUILDER',
           trace_id: `ERR-${Math.random().toString(36).substring(2)}`,
           action_required: 'Acțiune locală sau corectare parametri.',
           type: 'error'
         })
       }
    })
}
</script>

<template>
  <div>
    <h1 class="text-h5 font-weight-medium mb-2 text-primary">ZTA Resource Observatory</h1>
    <p class="text-body-2 text-secondary mb-4">Monitorizare, alertare și investigație pentru resursele ZeroTrustApplication. Builder-ul este disponibil mai jos, on-demand.</p>
    <v-row>
      <v-col cols="12" lg="4">
        <v-card class="gc-border mb-4" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary d-flex align-center justify-space-between">
            <span>Existing Applications</span>
            <v-chip size="x-small" variant="tonal" color="primary">
              {{ applications.length }}
            </v-chip>
          </v-card-title>
          <v-card-text>
            <v-autocomplete
              v-model="selectedApplication"
              :items="applicationItems"
              item-title="title"
              item-value="value"
              label="Select a ZTA application"
              placeholder="Type to filter…"
              variant="outlined"
              density="comfortable"
              :loading="isLoadingApplications"
              prepend-inner-icon="mdi-shield-search"
              menu-icon="mdi-chevron-down"
              clearable
              :menu-props="{ maxHeight: 480 }"
            >
              <template v-slot:item="{ props: itemProps, item }">
                <v-list-item
                  v-bind="itemProps"
                  class="zta-option py-2"
                  :title="undefined"
                  :subtitle="undefined"
                >
                  <template v-slot:prepend>
                    <v-avatar :color="applicationSeverity(item.raw.app)" size="34" class="me-1">
                      <v-icon size="18" color="white">{{ applicationIcon(item.raw.app) }}</v-icon>
                    </v-avatar>
                  </template>

                  <div class="d-flex align-center ga-2 flex-wrap zta-option__title">
                    <span class="font-weight-medium text-body-2">{{ item.raw.app.metadata.name }}</span>
                    <v-chip
                      :color="applicationSeverity(item.raw.app)"
                      size="x-small"
                      variant="tonal"
                      density="comfortable"
                    >
                      {{ applicationBadge(item.raw.app) }}
                    </v-chip>
                    <v-chip
                      v-if="guacIngestionSeverity(item.raw.app) && guacIngestionSeverity(item.raw.app) !== 'success'"
                      :color="guacIngestionSeverity(item.raw.app) || undefined"
                      size="x-small"
                      variant="tonal"
                      prepend-icon="mdi-graph-outline"
                    >
                      {{ guacIngestionLabel(item.raw.app) }}
                    </v-chip>
                    <v-chip
                      v-if="(item.raw.app.summary?.vex?.exemptedCount || 0) > 0"
                      color="success"
                      size="x-small"
                      variant="tonal"
                      prepend-icon="mdi-shield-check-outline"
                    >
                      VEX {{ item.raw.app.summary.vex.exemptedCount }}
                    </v-chip>
                    <v-chip
                      v-if="item.raw.app.summary?.merkle?.rfc6962"
                      color="primary"
                      size="x-small"
                      variant="tonal"
                      prepend-icon="mdi-merge"
                      title="Merkle tree uses RFC 6962 domain separation"
                    >
                      Merkle v{{ item.raw.app.summary.merkle.version }}
                    </v-chip>
                  </div>

                  <div class="text-caption text-secondary mt-1">
                    <span class="font-mono">{{ item.raw.app.summary.securityPolicyRef || 'no policy' }}</span>
                    <span class="mx-1">•</span>
                    <span>{{ item.raw.app.summary.securityState || 'Pending' }}</span>
                    <span class="ms-2 text-medium-emphasis font-mono">{{ item.raw.app.metadata.namespace }}</span>
                  </div>

                  <div
                    v-if="item.raw.app.summary.isAuditAlert"
                    class="text-caption text-medium-emphasis mt-1 d-flex align-center ga-1"
                    style="min-width: 0;"
                    :title="`Audit-mode alert — cause: ${auditAlertCause(item.raw.app.summary)} · manifest hash: ${manifestHashState(item.raw.app.summary)}`"
                  >
                    <v-icon size="x-small">mdi-information-outline</v-icon>
                    <span class="zta-option__msg">Audit-mode alert — {{ auditAlertCause(item.raw.app.summary) }}</span>
                  </div>
                  <div
                    v-else-if="item.raw.app.summary.lastError"
                    class="text-caption text-error mt-1 d-flex align-center ga-1"
                    style="min-width: 0;"
                    :title="item.raw.app.summary.lastError"
                  >
                    <v-icon size="x-small">mdi-alert-octagon-outline</v-icon>
                    <span class="zta-option__msg">{{ item.raw.app.summary.errorCategory || 'Verification failed' }}</span>
                  </div>
                </v-list-item>
              </template>

              <template v-slot:selection="{ item }">
                <span class="d-flex align-center ga-2" v-if="item.raw?.app">
                  <v-icon :color="applicationSeverity(item.raw.app)" size="18">
                    {{ applicationIcon(item.raw.app) }}
                  </v-icon>
                  <span class="font-weight-medium">{{ item.raw.app.metadata.name }}</span>
                  <v-chip :color="applicationSeverity(item.raw.app)" size="x-small" variant="tonal">
                    {{ applicationBadge(item.raw.app) }}
                  </v-chip>
                </span>
              </template>

              <template v-slot:no-data>
                <div class="px-4 py-3 text-caption text-secondary">
                  {{ isLoadingApplications ? 'Loading applications…' : 'No ZTA applications found.' }}
                </div>
              </template>
            </v-autocomplete>

            <div v-if="!selectedApplication" class="text-caption text-secondary mt-3 d-flex align-start ga-2">
              <v-icon size="small" color="primary">mdi-information-outline</v-icon>
              <span>Pick an application above to inspect its integrity ledger, reconcile flow, and supply-chain forensics.</span>
            </div>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12" lg="8">
        <v-card class="gc-border" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary d-flex align-center justify-space-between">
            <span>Integrity Ledger</span>
            <div class="d-flex ga-2">
              <v-btn
                size="small"
                variant="tonal"
                color="primary"
                :disabled="!selectedApplication"
                :append-icon="showIntegrityLedger ? 'mdi-chevron-up' : 'mdi-chevron-down'"
                @click="showIntegrityLedger = !showIntegrityLedger"
              >
                {{ showIntegrityLedger ? 'Hide Ledger' : 'Show Ledger' }}
              </v-btn>
              <v-btn size="small" variant="outlined" color="primary" :disabled="!selectedApplication" :loading="isRevalidating" @click="revalidateIntegrity">
                Revalidate OCI
              </v-btn>
              <v-btn size="small" variant="outlined" color="secondary" :disabled="!selectedApplication || !canWriteApps" prepend-icon="mdi-pencil" @click="startEditApp">
                Edit
              </v-btn>
            </div>
          </v-card-title>
          <v-card-text>
            <div v-if="isLoadingIntegrity && !integrityDetails" class="text-caption text-secondary">Loading integrity details...</div>
            <template v-else-if="integrityDetails">
              <v-alert
                v-for="(issue, index) in integrityCriticalIssues"
                :key="`${issue.title}-${index}`"
                type="error"
                variant="tonal"
                density="compact"
                class="mb-3"
              >
                <div class="d-flex align-start ga-2">
                  <v-icon color="error">{{ issue.icon }}</v-icon>
                  <div>
                    <div class="font-weight-bold">{{ issue.title }}</div>
                    <div class="text-caption">{{ issue.message }}</div>
                  </div>
                </div>
              </v-alert>

              <div v-if="!showIntegrityLedger" class="text-caption text-secondary">
                Ledger is hidden. Use "Show Ledger" to display all integrity stages.
              </div>

              <v-row v-else>
                <v-col cols="12" v-for="item in integrityDetails.integrityLedger || []" :key="item.id">
                  <v-card class="gc-border" flat style="border: 1px solid rgba(var(--v-theme-on-surface), 0.08)">
                    <v-card-text>
                      <div class="d-flex align-center justify-space-between w-100 ga-2 flex-wrap mb-2">
                        <div class="d-flex align-center ga-2">
                          <v-avatar :color="ledgerColor(item.status)" size="28">
                            <v-icon size="16">{{ ledgerIcon(item.status, item.id) }}</v-icon>
                          </v-avatar>
                          <div class="text-body-2 font-weight-medium">{{ item.title }}</div>
                        </div>
                        <v-chip :color="ledgerColor(item.status)" size="x-small" variant="tonal">{{ item.status }}</v-chip>
                      </div>
                      <v-row v-if="ledgerDetailsEntries(item.details).length">
                        <v-col cols="12" md="6" v-for="entry in ledgerDetailsEntries(item.details)" :key="`${item.id}-${entry.key}`">
                          <div class="text-caption text-secondary mb-1">{{ entry.key }}</div>
                          <div class="d-flex align-center ga-2">
                            <div class="text-body-2 text-medium-emphasis flex-grow-1" style="word-break: break-all;">{{ entry.value || 'n/a' }}</div>
                            <v-btn
                              v-if="entry.value"
                              icon="mdi-content-copy"
                              size="x-small"
                              variant="text"
                              color="primary"
                              @click="copyToClipboard(entry.value)"
                            ></v-btn>
                          </div>
                        </v-col>
                      </v-row>
                      <div v-else class="text-caption text-secondary">No details exposed for this stage.</div>
                    </v-card-text>
                  </v-card>
                </v-col>
              </v-row>
            </template>
            <div v-else class="text-caption text-secondary">Selectează o aplicație pentru a vedea detaliile VBBI și policy gate-ul.</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-2">
      <v-col cols="12">
        <v-expansion-panels v-model="builderPanels" variant="accordion">
          <v-expansion-panel>
            <v-expansion-panel-title>
              <div>
                <div class="text-subtitle-1 font-weight-medium text-primary">ZTA Application Builder</div>
                <div class="text-caption text-secondary">Deschide builder-ul doar când vrei să creezi sau modifici o declarație ZTA.</div>
              </div>
            </v-expansion-panel-title>
            <v-expansion-panel-text>
              <v-stepper v-model="step" elevation="0" bg-color="surface" hide-actions>
                <v-stepper-header class="gc-border-bottom">
                  <v-stepper-item :value="1" title="Core & Supply Chain" :complete="step > 1" value-icon="mdi-check" color="primary"></v-stepper-item>
                  <v-divider></v-divider>
                  <v-stepper-item :value="2" title="Network & WAF" :complete="step > 2" value-icon="mdi-check" color="primary"></v-stepper-item>
                  <v-divider></v-divider>
                  <v-stepper-item :value="3" title="Runtime Guardrails" :complete="step > 3" value-icon="mdi-check" color="primary"></v-stepper-item>
                  <v-divider></v-divider>
                  <v-stepper-item :value="4" title="Review & Commit" color="primary"></v-stepper-item>
                </v-stepper-header>

                <v-stepper-window>
                  <v-stepper-window-item :value="1">
                    <div class="pa-4">
                      <h3 class="text-subtitle-1 font-weight-medium mb-4">Application Fundamentals</h3>
                      <v-row>
                        <v-col cols="12" md="6">
                          <v-text-field v-model="form.name" label="App Name" variant="outlined" density="compact">
                            <template v-slot:append-inner>
                              <v-tooltip location="top" max-width="280">
                                <template v-slot:activator="{ props }">
                                  <v-icon v-bind="props" size="small" color="secondary" style="cursor:help;">mdi-help-circle-outline</v-icon>
                                </template>
                                <span>The Kubernetes resource name for this ZeroTrustApplication. Must be lowercase alphanumeric with hyphens only (e.g. my-app). This becomes the CRD name in your cluster.</span>
                              </v-tooltip>
                            </template>
                          </v-text-field>
                        </v-col>
                        <v-col cols="12" md="6">
                          <v-select
                            v-model="form.namespace"
                            :items="namespaces"
                            label="Target Namespace"
                            variant="outlined"
                            density="compact"
                            :loading="isLoadingNamespaces"
                            no-data-text="No namespaces found in cluster"
                          >
                            <template v-slot:append-inner>
                              <v-tooltip location="top" max-width="280">
                                <template v-slot:activator="{ props }">
                                  <v-icon v-bind="props" size="small" color="secondary" style="cursor:help;">mdi-help-circle-outline</v-icon>
                                </template>
                                <span>The Kubernetes namespace where this application will be deployed. Must already exist in the cluster. Defines policy scope and network segmentation boundary.</span>
                              </v-tooltip>
                            </template>
                          </v-select>
                        </v-col>
                        <v-col cols="12" md="6">
                          <v-select
                            v-model="form.securityPolicyName"
                            :items="policyOptions"
                            label="Security Policy (SCA)"
                            variant="outlined"
                            density="compact"
                            :loading="isLoadingPolicies"
                            :no-data-text="'Nicio politică SCA în cluster — creează una întâi în tabul Supply Chain.'"
                            hint="Doar politicile existente în cluster pot fi selectate"
                            persistent-hint
                          >
                            <template v-slot:append-inner>
                              <v-tooltip location="top" max-width="300">
                                <template v-slot:activator="{ props }">
                                  <v-icon v-bind="props" size="small" color="secondary" style="cursor:help;">mdi-help-circle-outline</v-icon>
                                </template>
                                <span>Reference to a SupplyChainAdmission policy this app must satisfy before deployment. The operator validates image provenance, Cosign signatures, and Trivy scan results against this policy.</span>
                              </v-tooltip>
                            </template>
                          </v-select>
                        </v-col>
                        <v-col cols="12">
                          <v-text-field
                            v-model="form.image"
                            label="Container Image"
                            variant="outlined"
                            density="compact"
                            hint="Must be hosted on GHCR and signed with Cosign"
                            persistent-hint
                            :error-messages="imageError ? [imageError] : []"
                          >
                            <template v-slot:prepend-inner>
                              <v-icon :color="imageError ? 'error' : 'default'">mdi-docker</v-icon>
                            </template>
                            <template v-slot:append-inner>
                              <v-tooltip location="top" max-width="300">
                                <template v-slot:activator="{ props }">
                                  <v-icon v-bind="props" size="small" color="secondary" style="cursor:help;">mdi-help-circle-outline</v-icon>
                                </template>
                                <span>The OCI container image to deploy. Must be hosted on GHCR (ghcr.io) and signed with Cosign. Tag 'latest' is blocked by Kyverno. Always use a pinned semver tag — e.g., ghcr.io/org/app:v1.2.3.</span>
                              </v-tooltip>
                            </template>
                          </v-text-field>
                          <v-alert v-if="imageError" type="error" variant="tonal" density="compact" class="mt-2 text-caption">
                            Politica Zero-Trust (Kyverno) va bloca acest deployment! Asigurați-vă că respectați regulile lanțului de aprovizionare.
                          </v-alert>
                        </v-col>
                      </v-row>
                      <div class="d-flex flex-column align-end mt-6">
                        <div v-if="step1ValidationMessages.length" class="text-right mb-2">
                          <div v-for="msg in step1ValidationMessages" :key="msg" class="text-caption text-error mb-1">
                            <v-icon size="x-small" class="mr-1">mdi-alert-circle-outline</v-icon>{{ msg }}
                          </div>
                        </div>
                        <div class="d-flex w-100">
                          <v-spacer></v-spacer>
                          <v-btn color="primary" @click="step = 2" :disabled="!isStep1Valid" variant="flat">Continue to Network</v-btn>
                        </div>
                      </div>
                    </div>
                  </v-stepper-window-item>

                  <v-stepper-window-item :value="2">
                    <div class="pa-4">
                      <h3 class="text-subtitle-1 font-weight-medium mb-4">Microsegmentation & Coraza WAF</h3>
                      <v-row>
                        <v-col cols="12" md="6">
                          <div class="d-flex align-center mb-1">
                            <span class="text-caption font-weight-medium">Allow Ingress From (namespaces)</span>
                            <v-spacer />
                            <v-btn size="x-small" variant="text" color="primary" prepend-icon="mdi-plus" @click="addIngressRule">Add</v-btn>
                          </div>
                          <div v-for="(rule, i) in form.ingressAllowedFrom" :key="`in-${i}`" class="d-flex align-center ga-2 mb-2">
                            <v-combobox v-model="rule.namespace" :items="namespaces" label="Namespace" variant="outlined" density="compact" hide-details :loading="isLoadingNamespaces" no-data-text="No namespaces found" class="flex-grow-1" />
                            <v-btn v-if="form.ingressAllowedFrom.length > 1" size="x-small" variant="text" color="error" icon="mdi-close" @click="removeIngressRule(i)" />
                          </div>
                          <div class="text-caption text-secondary">Each entry maps to a Cilium NetworkPolicy ingressAllowedFrom rule.</div>
                        </v-col>
                        <v-col cols="12" md="6">
                          <div class="d-flex align-center mb-1">
                            <span class="text-caption font-weight-medium">Allow Egress To (namespace + ports)</span>
                            <v-spacer />
                            <v-btn size="x-small" variant="text" color="primary" prepend-icon="mdi-plus" @click="addEgressRule">Add</v-btn>
                          </div>
                          <div v-for="(rule, i) in form.egressAllowedTo" :key="`eg-${i}`" class="d-flex align-center ga-2 mb-2">
                            <v-combobox v-model="rule.namespace" :items="namespaces" label="Namespace" variant="outlined" density="compact" hide-details :loading="isLoadingNamespaces" no-data-text="No namespaces found" class="flex-grow-1" />
                            <v-text-field v-model="rule.ports" label="Ports (CSV)" placeholder="5432, 6379" variant="outlined" density="compact" hide-details style="max-width: 170px" />
                            <v-btn v-if="form.egressAllowedTo.length > 1" size="x-small" variant="text" color="error" icon="mdi-close" @click="removeEgressRule(i)" />
                          </div>
                          <div class="text-caption text-secondary">Per-destination ports → egressAllowedTo. Leave ports empty to allow the namespace on any port.</div>
                        </v-col>
                        <v-col cols="12">
                          <v-row>
                            <v-col cols="12" md="6">
                              <v-select v-model="form.wafMode" :items="WAF_MODES" label="WAF Mode" variant="outlined" density="compact">
                                <template v-slot:append-inner>
                                  <v-tooltip location="top" max-width="300">
                                    <template v-slot:activator="{ props }">
                                      <v-icon v-bind="props" size="small" color="secondary" style="cursor:help;">mdi-help-circle-outline</v-icon>
                                    </template>
                                    <span>Monitor: log requests but allow them through. Block: actively reject requests matching WAF rules. Start with Monitor to assess false-positives, then switch to Block.</span>
                                  </v-tooltip>
                                </template>
                              </v-select>
                            </v-col>
                            <v-col cols="12" md="6">
                              <v-select v-model="form.wafProfile" :items="wafProfiles" label="Coraza WAF Profile" variant="outlined" density="compact">
                                <template v-slot:append-inner>
                                  <v-tooltip location="top" max-width="300">
                                    <template v-slot:activator="{ props }">
                                      <v-icon v-bind="props" size="small" color="secondary" style="cursor:help;">mdi-help-circle-outline</v-icon>
                                    </template>
                                    <span>Choose the Coraza OWASP WAF ruleset tuned for your app type. REST-API: JSON/REST. SPA: single-page apps. GRPC: gRPC microservices. Strict-Baseline: generic strict mode.</span>
                                  </v-tooltip>
                                </template>
                              </v-select>
                            </v-col>
                          </v-row>
                        </v-col>
                      </v-row>
                      <v-divider class="my-5"></v-divider>
                      <div class="d-flex align-center mb-2">
                        <h4 class="text-subtitle-2 font-weight-medium">HTTP Ingress (optional)</h4>
                        <v-spacer></v-spacer>
                        <v-switch v-model="form.ingress.enabled" color="primary" density="compact" hide-details label="Expose via Ingress"></v-switch>
                      </div>
                      <v-row v-if="form.ingress.enabled">
                        <v-col cols="12" md="6"><v-text-field v-model="form.ingress.host" label="Host" placeholder="app.example.com" variant="outlined" density="compact" hide-details="auto"></v-text-field></v-col>
                        <v-col cols="6" md="3"><v-text-field v-model="form.ingress.className" label="Ingress Class" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                        <v-col cols="6" md="3"><v-text-field v-model.number="form.ingress.servicePort" label="Service Port" type="number" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                        <v-col cols="6" md="3"><v-text-field v-model="form.ingress.path" label="Path" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                        <v-col cols="6" md="3"><v-text-field v-model="form.ingress.pathType" label="Path Type" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                        <v-col cols="12" md="6" class="d-flex align-center">
                          <v-switch v-model="form.ingress.oauth2Enabled" color="primary" density="compact" hide-details label="Protect with OAuth2 (oauth2-proxy)"></v-switch>
                        </v-col>
                        <v-col v-if="form.ingress.oauth2Enabled" cols="12">
                          <v-expansion-panels variant="accordion">
                            <v-expansion-panel title="OAuth2 / forward-auth (advanced)">
                              <v-expansion-panel-text>
                                <v-row>
                                  <v-col cols="12" md="6"><v-text-field v-model="form.ingress.authUrl" label="authUrl" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                  <v-col cols="12" md="6"><v-text-field v-model="form.ingress.authSignin" label="authSignin" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                  <v-col cols="12"><v-text-field v-model="form.ingress.authResponseHeaders" label="authResponseHeaders" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                  <v-col cols="12" md="4"><v-text-field v-model="form.ingress.oauth2ServiceName" label="oauth2ServiceName" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                  <v-col cols="12" md="4"><v-text-field v-model="form.ingress.oauth2ServiceNamespace" label="oauth2ServiceNamespace" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                  <v-col cols="6" md="4"><v-text-field v-model.number="form.ingress.oauth2ServicePort" label="oauth2ServicePort" type="number" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                  <v-col cols="12" md="4"><v-text-field v-model="form.ingress.oauth2IngressPath" label="oauth2IngressPath" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                  <v-col cols="12" md="4"><v-text-field v-model="form.ingress.groupsHeader" label="groupsHeader" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                  <v-col cols="12" md="4"><v-text-field v-model="form.ingress.groupsHeaderFallback" label="groupsHeaderFallback" variant="outlined" density="compact" hide-details></v-text-field></v-col>
                                </v-row>
                              </v-expansion-panel-text>
                            </v-expansion-panel>
                          </v-expansion-panels>
                        </v-col>
                      </v-row>

                      <div class="d-flex mt-6">
                        <v-btn variant="text" @click="step = 1">Back</v-btn>
                        <v-spacer></v-spacer>
                        <v-btn color="primary" @click="step = 3" variant="flat">Continue to Runtime</v-btn>
                      </div>
                    </div>
                  </v-stepper-window-item>

                  <v-stepper-window-item :value="3">
                    <div class="pa-4">
                      <h3 class="text-subtitle-1 font-weight-medium mb-4">Runtime Guardrails</h3>
                      <p class="text-body-2 text-secondary mb-4">Definește căile permise și acțiunea operatorului când runtime-ul este compromis.</p>
                      <v-text-field v-model="form.allowedPaths" label="Allowed Paths" variant="outlined" density="compact" placeholder="/tmp/app-data,/var/cache/app">
                        <template v-slot:append-inner>
                          <v-tooltip location="top" max-width="300">
                            <template v-slot:activator="{ props }">
                              <v-icon v-bind="props" size="small" color="secondary" style="cursor:help;">mdi-help-circle-outline</v-icon>
                            </template>
                            <span>Comma-separated filesystem paths the container is permitted to write to. Falco and the runtime agent enforce this via eBPF. Any write outside these paths triggers the On Compromise action.</span>
                          </v-tooltip>
                        </template>
                      </v-text-field>
                      <v-select v-model="form.onCompromise" :items="ON_COMPROMISE_ACTIONS" label="On Compromise Action" variant="outlined" density="compact" class="mt-4">
                        <template v-slot:append-inner>
                          <v-tooltip location="top" max-width="320">
                            <template v-slot:activator="{ props }">
                              <v-icon v-bind="props" size="small" color="secondary" style="cursor:help;">mdi-help-circle-outline</v-icon>
                            </template>
                            <span>Isolate: removes all network policies, cutting the pod off from the mesh — least disruptive. Kill: terminates the pod immediately. Use Kill only for high-risk workloads where containment matters more than availability.</span>
                          </v-tooltip>
                        </template>
                      </v-select>

                      <div class="d-flex mt-6">
                        <v-btn variant="text" @click="step = 2">Back</v-btn>
                        <v-spacer></v-spacer>
                        <v-btn color="primary" @click="step = 4" variant="flat">Review Declaration</v-btn>
                      </div>
                    </div>
                  </v-stepper-window-item>

                  <v-stepper-window-item :value="4">
                    <div class="pa-4">
                      <h3 class="text-subtitle-1 font-weight-medium mb-4">Review & Propose via GitOps</h3>

                      <div class="rounded overflow-hidden gc-border" style="height: 310px;">
                        <VueMonacoEditor
                          :value="yamlPreview"
                          language="yaml"
                          :theme="isDarkTheme ? 'vs-dark' : 'vs'"
                          :options="monacoOptions"
                          style="height: 100%; width: 100%;"
                        />
                      </div>

                      <div class="d-flex mt-6">
                        <v-btn variant="text" @click="step = 3">Edit Specs</v-btn>
                        <v-spacer></v-spacer>
                        <v-btn v-if="isEditingApp" variant="text" color="secondary" class="mr-2" @click="cancelEditApp">Cancel edit</v-btn>
                        <v-btn color="success" :disabled="!canWriteApps" @click="submitDeclaration" :loading="isSubmitting" variant="flat" prepend-icon="mdi-google-cloud">
                          {{ !canWriteApps ? 'Necesită platform-engineer' : (isEditingApp ? 'Update ZTA Application' : 'Deploy ZTA Application') }}
                        </v-btn>
                      </div>
                    </div>
                  </v-stepper-window-item>
                </v-stepper-window>
              </v-stepper>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </v-col>
    </v-row>

    <section v-if="integrityDetails" class="integrity-dashboard mt-6">
      <div class="dashboard-panel span-7-lg span-12-sm">
        <ReconcileFlow
          :flow="integrityDetails.reconcileFlow"
          :retrying="isRetrying"
          @retry="handleRetryReconcile"
        />
      </div>
      <div class="dashboard-panel span-5-lg span-12-sm">
        <EventsTimelinePanel :events="kopfEvents" :connected="streamConnected" />
      </div>

      <div class="dashboard-panel span-12">
        <ErrorLogPanel
          :errors="integrityDetails.application?.status?.errors"
          :stream-error="streamError"
        />
      </div>

      <div class="dashboard-panel span-12">
        <VerificationStatusTable :verifications="integrityDetails.application?.status?.verifications" />
      </div>

      <div class="dashboard-panel span-12">
        <CelEvaluationsTable :evaluations="integrityDetails.application?.summary?.celEvaluations" />
      </div>

      <div class="dashboard-panel span-7-lg span-12-sm">
        <BuildLedgerGraph :nodes="integrityDetails.revalidation?.ledgerNodes || []" :status="integrityDetails.revalidation?.status" />
      </div>
      <div class="dashboard-panel span-5-lg span-12-sm">
        <ProvisioningPlan :plan="integrityDetails.provisioningPlan || []" />
      </div>

      <div class="dashboard-panel span-12">
        <SbomTree :groups="integrityDetails.sbomTree || []" />
      </div>

      <div class="dashboard-panel span-5-lg span-12-sm" v-if="selectedAppSummary?.guacIngestion">
        <v-card class="gc-border panel-card" flat>
          <v-card-title class="text-primary panel-title">
            <v-icon start size="small" color="primary">mdi-graph-outline</v-icon>
            GUAC Threat Intel
          </v-card-title>
          <v-card-text class="panel-content">
            <v-chip
              :color="(selectedAppSummary.guacIngestion.status || '').toLowerCase() === 'completed' ? 'success'
                : (selectedAppSummary.guacIngestion.status || '').toLowerCase() === 'inprogress' ? 'info'
                : (selectedAppSummary.guacIngestion.status || '').toLowerCase() === 'failed' ? 'error' : 'grey'"
              variant="tonal"
              size="small"
            >
              {{ selectedAppSummary.guacIngestion.status || 'unknown' }}
            </v-chip>
            <div class="text-caption text-medium-emphasis mt-2">
              {{ selectedAppSummary.guacIngestion.message || 'no message' }}
            </div>
            <div class="text-caption text-medium-emphasis mt-1" v-if="selectedAppSummary.guacIngestion.completedAt">
              completed at: {{ selectedAppSummary.guacIngestion.completedAt }}
            </div>
            <v-btn
              class="mt-3"
              size="small"
              color="primary"
              variant="outlined"
              prepend-icon="mdi-radar"
              :to="'/blast-radius'"
            >
              Open Blast Radius
            </v-btn>
          </v-card-text>
        </v-card>
      </div>

      <div class="dashboard-panel span-5-lg span-12-sm">
        <v-card class="gc-border panel-card" flat>
          <v-card-title class="text-primary panel-title">
            <v-icon start size="small" color="primary">mdi-radar</v-icon>
            Runtime Forensics
          </v-card-title>
          <v-card-text class="panel-content">
            <!--
              Infrastructure banner: when Falco+Talon Helm charts are not
              installed at all, missing chips below would otherwise look
              like a security failure. This banner makes it explicit that
              the rest of the supply-chain succeeded; only the optional
              runtime-enforcement layer is unavailable.
            -->
            <v-alert
              v-if="integrityDetails.runtimeForensics?.infrastructure?.requested
                    && integrityDetails.runtimeForensics?.infrastructure?.installed === false"
              type="info"
              variant="tonal"
              density="compact"
              class="mb-3"
              icon="mdi-shield-off-outline"
            >
              <div class="text-body-2 font-weight-medium">
                Runtime enforcement layer (Falco + Talon) is not installed in this cluster
              </div>
              <div class="text-caption mt-1">
                {{ integrityDetails.runtimeForensics.infrastructure.reason
                   || 'The Talon ConfigMap was not found. The application is deployed and verified, but no runtime-isolation rule was patched.' }}
              </div>
              <div
                v-if="(integrityDetails.runtimeForensics.infrastructure.missing || []).length"
                class="d-flex flex-wrap ga-1 mt-2"
              >
                <v-chip
                  v-for="item in integrityDetails.runtimeForensics.infrastructure.missing"
                  :key="item"
                  size="x-small"
                  variant="outlined"
                  color="info"
                >
                  {{ item }}
                </v-chip>
              </div>
              <div class="text-caption mt-2 text-medium-emphasis">
                To enable: <code>helm install falco falcosecurity/falco -n falco --create-namespace</code> +
                <code>helm install falco-talon falcosecurity/falco-talon -n falco-talon --create-namespace</code>
              </div>
            </v-alert>

            <div class="forensics-grid">
              <div class="forensic-item">
                <div class="forensic-label">Falco ConfigMap</div>
                <div class="forensic-value font-mono">{{ integrityDetails.runtimeForensics?.localFalcoRuleConfigMap || 'n/a' }}</div>
              </div>
              <div class="forensic-item">
                <div class="forensic-label">Talon Rule Reference</div>
                <div class="forensic-value font-mono">{{ integrityDetails.runtimeForensics?.talonRuleReference || 'n/a' }}</div>
              </div>
            </div>
            <div class="d-flex flex-wrap ga-2 mt-3">
              <v-chip
                :color="integrityDetails.runtimeForensics?.infrastructure?.installed === false
                          ? 'grey'
                          : (integrityDetails.runtimeForensics?.localRulePresent ? 'success' : 'error')"
                variant="tonal"
                size="small"
                :prepend-icon="integrityDetails.runtimeForensics?.infrastructure?.installed === false
                                 ? 'mdi-minus-circle-outline'
                                 : (integrityDetails.runtimeForensics?.localRulePresent ? 'mdi-check-circle' : 'mdi-close-circle')"
              >
                Local rule {{ integrityDetails.runtimeForensics?.infrastructure?.installed === false
                                ? 'n/a (Falco not installed)'
                                : (integrityDetails.runtimeForensics?.localRulePresent ? 'present' : 'missing') }}
              </v-chip>
              <v-chip
                :color="integrityDetails.runtimeForensics?.infrastructure?.installed === false
                          ? 'grey'
                          : (integrityDetails.runtimeForensics?.talonRulePresent ? 'success' : 'error')"
                variant="tonal"
                size="small"
                :prepend-icon="integrityDetails.runtimeForensics?.infrastructure?.installed === false
                                 ? 'mdi-minus-circle-outline'
                                 : (integrityDetails.runtimeForensics?.talonRulePresent ? 'mdi-check-circle' : 'mdi-close-circle')"
              >
                Talon {{ integrityDetails.runtimeForensics?.infrastructure?.installed === false
                           ? 'n/a (Talon not installed)'
                           : (integrityDetails.runtimeForensics?.talonRulePresent ? 'patched' : 'not patched') }}
              </v-chip>
            </div>
            <div class="mt-3">
              <div class="forensic-label mb-2">Allowed write paths</div>
              <div v-if="(integrityDetails.runtimeForensics?.allowedPaths || []).length" class="d-flex flex-wrap ga-1">
                <v-chip
                  v-for="path in integrityDetails.runtimeForensics.allowedPaths"
                  :key="path"
                  size="small"
                  variant="outlined"
                  color="secondary"
                  prepend-icon="mdi-folder-outline"
                >{{ path }}</v-chip>
              </div>
              <div v-else class="text-caption text-secondary font-italic">No allowed paths defined.</div>
            </div>
          </v-card-text>
        </v-card>
      </div>

      <div class="dashboard-panel span-7-lg span-12-sm">
        <v-card class="gc-border panel-card" flat>
          <v-card-title class="text-primary panel-title">
            <v-icon start size="small" color="primary">mdi-history</v-icon>
            Sanction History
          </v-card-title>
          <v-card-text class="panel-content">
            <div v-if="!(integrityDetails.sanctionHistory || []).length" class="text-caption text-secondary font-italic">
              No enforcement history recorded yet.
            </div>
            <div v-else class="sanction-list">
              <div
                v-for="(event, index) in integrityDetails.sanctionHistory"
                :key="`${event.kind}-${index}`"
                class="sanction-item"
                :class="`sanction-${sanctionDotColor(event)}`"
              >
                <div class="sanction-dot">
                  <v-icon size="14" :color="sanctionDotColor(event)">
                    {{ sanctionDotColor(event) === 'success' ? 'mdi-check-circle' : (sanctionDotColor(event) === 'error' ? 'mdi-alert-circle' : 'mdi-alert') }}
                  </v-icon>
                </div>
                <div class="sanction-body">
                  <div class="d-flex align-center ga-2 flex-wrap mb-1">
                    <span class="text-body-2 font-weight-medium">{{ event.action }}</span>
                    <v-chip size="x-small" :color="sanctionDotColor(event)" variant="tonal">{{ event.kind || 'event' }}</v-chip>
                  </div>
                  <div class="text-caption text-secondary">{{ event.message }}</div>
                  <div class="text-caption text-medium-emphasis mt-1">
                    <v-icon size="x-small" class="mr-1">mdi-clock-outline</v-icon>
                    {{ formatSanctionTimestamp(event.timestamp) }}
                  </div>
                </div>
              </div>
            </div>
          </v-card-text>
        </v-card>
      </div>
    </section>
  </div>
</template>

<style scoped>
.integrity-dashboard {
  --space-8: 8px;
  --space-16: 16px;
  --space-24: 24px;

  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: var(--space-24);
  align-items: stretch;
}

.dashboard-panel {
  min-width: 0;
  align-self: stretch;
}

.span-12,
.span-12-sm {
  grid-column: span 12;
}

.panel-card {
  height: 100%;
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
}

.panel-title {
  min-height: 56px;
  display: flex;
  align-items: center;
  padding-top: var(--space-16);
  padding-bottom: var(--space-8);
}

.panel-content {
  padding-top: var(--space-8);
  padding-bottom: var(--space-16);
}

.stack-16 > * + * {
  margin-top: var(--space-16);
}

/* --- Runtime Forensics -------------------------------------------- */
.forensics-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.forensic-item {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
  border-radius: 8px;
  padding: 8px 12px;
  background: rgba(var(--v-theme-on-surface), 0.02);
}

.forensic-label {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: rgba(var(--v-theme-on-surface), 0.45);
  margin-bottom: 3px;
}

.forensic-value {
  font-size: 0.8rem;
  color: rgba(var(--v-theme-on-surface), 0.88);
  word-break: break-all;
}

/* --- Sanction History -------------------------------------------- */
.sanction-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.sanction-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
  background: rgba(var(--v-theme-on-surface), 0.02);
}

.sanction-dot {
  width: 26px;
  height: 26px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: rgba(var(--v-theme-on-surface), 0.06);
  flex-shrink: 0;
  margin-top: 1px;
}

.sanction-body {
  flex: 1;
  min-width: 0;
}

@media (min-width: 1280px) {
  .span-7-lg {
    grid-column: span 7;
  }

  .span-6-lg {
    grid-column: span 6;
  }

  .span-5-lg {
    grid-column: span 5;
  }
}

/* --- ZTA dropdown option (rich list item) --- */
:deep(.zta-option) {
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.06);
  min-height: 64px;
  padding-top: 8px;
  padding-bottom: 8px;
}
:deep(.zta-option:last-child) {
  border-bottom: none;
}
:deep(.zta-option:hover) {
  background: rgba(var(--v-theme-primary), 0.06);
}
:deep(.zta-option .v-list-item__prepend) {
  align-self: flex-start;
  padding-top: 2px;
}
:deep(.zta-option__title) {
  line-height: 1.3;
}
/* Keep the per-app message to a single, ellipsised line so a long verification
   error can't blow up the dropdown height. Full text stays available on hover
   via the row's title attribute. */
:deep(.zta-option__msg) {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.font-mono {
  font-family: 'Roboto Mono', 'JetBrains Mono', ui-monospace, monospace;
  font-size: 0.78rem;
}
</style>
