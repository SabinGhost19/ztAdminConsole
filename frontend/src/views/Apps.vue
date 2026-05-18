<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import type { AxiosError, AxiosResponse } from 'axios'
import { useTheme } from 'vuetify'
import { VueMonacoEditor } from '@guolao/vue-monaco-editor'
import { api } from '../api/axios'
import BuildLedgerGraph from '../components/BuildLedgerGraph.vue'
import MerkleTreeExplorer from '../components/MerkleTreeExplorer.vue'
import ProvisioningPlan from '../components/ProvisioningPlan.vue'
import ReconcileFlow from '../components/ReconcileFlow.vue'
import SbomTree from '../components/SbomTree.vue'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'
import { useAuthStore } from '../store/auth'

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

const namespaces = ref<string[]>(['default'])
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

const form = ref({
  name: '',
  namespace: 'default',
  image: '',
  replicas: 1,
  securityPolicyName: '',
  ingressNamespace: '',
  egressNamespace: '',
  egressPorts: '5432',
  wafMode: 'Block',
  wafProfile: 'REST-API',
  allowedPaths: '/tmp/app-data',
  onCompromise: 'Isolate'
})

const wafProfiles = ['REST-API', 'SPA', 'GRPC', 'Strict-Baseline']
const applications = computed(() => dashboardStore.applications)
const applicationOptions = computed(() => dashboardStore.applicationOptions)
const isLoadingApplications = computed(() => dashboardStore.loadingApplications)
const isLoadingIntegrity = computed(() => dashboardStore.loadingIntegrity)
// SCA dropdown: replaces free-text input so the user cannot reference a
// policy that does not exist in the cluster.
const policyOptions = computed(() => dashboardStore.policyOptions)
const isLoadingPolicies = computed(() => dashboardStore.loadingPolicies)

function applicationSeverity(app: any) {
  const summary = app?.summary || {}
  if (summary.hasErrors || summary.hasHashMismatch) return 'error'
  if (summary.hasViolations || !['Compliant', 'PendingProvenance'].includes(summary.securityState || '')) return 'error'
  if (summary.trustLevel === 'Verified') return 'success'
  return 'warning'
}

function applicationIcon(app: any) {
  const summary = app?.summary || {}
  if (summary.hasHashMismatch) return 'mdi-file-document-alert'
  if (summary.hasErrors) return 'mdi-alert-octagon'
  if (summary.hasViolations || !['Compliant', 'PendingProvenance'].includes(summary.securityState || '')) return 'mdi-shield-alert'
  if (summary.trustLevel === 'Verified') return 'mdi-shield-check'
  return 'mdi-progress-clock'
}

function applicationBadge(app: any) {
  const summary = app?.summary || {}
  if (summary.hasHashMismatch) return 'Manifest Mismatch'
  if (summary.hasErrors) return 'Verification Failed'
  if (summary.hasViolations) return 'Compliance Failed'
  if (summary.trustLevel === 'Verified') return 'Verified'
  return 'Pending'
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
    // Restart polling aggressively so the user sees the new state quickly.
    startIntegrityPolling()
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
  if (!form.value.image.startsWith('ghcr.io/')) return 'Violation: Imaginea trebuie să fie din ghcr.io/'
  if (form.value.image.endsWith(':latest')) return 'Violation: Tag-ul "latest" este strict interzis în producție.'
  return ''
})

const isStep1Valid = computed(() => {
  return form.value.name.length > 2 && form.value.image.length > 5 && !imageError.value && form.value.securityPolicyName.length > 1
})

const yamlPreview = computed(() => {
  const egressPorts = form.value.egressPorts
    .split(',')
    .map(item => Number.parseInt(item.trim(), 10))
    .filter(Number.isFinite)

  const allowedPaths = form.value.allowedPaths
    .split(',')
    .map(item => item.trim())
    .filter(Boolean)

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
      - namespace: ${form.value.ingressNamespace || 'api-gateway'}
    egressAllowedTo:
      - namespace: ${form.value.egressNamespace || 'database'}
        ports: [${egressPorts.join(', ')}]
  wafConfig:
    mode: ${form.value.wafMode}
    appProfile: ${form.value.wafProfile}
  runtimeSecurity:
    allowedPaths:
${allowedPaths.map(path => `      - ${path}`).join('\n')}
    onCompromise: ${form.value.onCompromise}`
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
  stopIntegrityPolling()
})

watch(selectedApplication, async (value) => {
  if (!value) {
    integrityDetails.value = null
    stopIntegrityPolling()
    return
  }

  const [namespace, name] = value.split('/')
  const payload = await dashboardStore.fetchIntegrity(namespace, name, true)
  integrityDetails.value = payload
  if (isIntegrityFlowStable(payload)) {
    stopIntegrityPolling()
  } else {
    startIntegrityPolling()
  }
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
      startIntegrityPolling()
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
  const egressPorts = form.value.egressPorts
    .split(',')
    .map(item => Number.parseInt(item.trim(), 10))
    .filter(Number.isFinite)

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
    networkZeroTrust: {
      ingressAllowedFrom: [{ namespace: form.value.ingressNamespace || 'api-gateway' }],
      egressAllowedTo: [{ namespace: form.value.egressNamespace || 'database', ports: egressPorts }],
    },
    wafConfig: {
      mode: form.value.wafMode,
      appProfile: form.value.wafProfile,
    },
    runtimeSecurity: {
      allowedPaths: form.value.allowedPaths.split(',').map(item => item.trim()).filter(Boolean),
      onCompromise: form.value.onCompromise,
    },
  }

  api.post('/zta/', payload)
    .then((response: AxiosResponse<any>) => {
      isSubmitting.value = false
      step.value = 1
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
        error_code: 'ZTA_CREATED_SUCCESS',
        message: `Aplicația ZTA ${response.data.metadata?.name || 'cu succes'} a fost creată!`,
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
        <v-card class="gc-border mb-4" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary">Existing Applications</v-card-title>
          <v-card-text>
            <v-select
              v-model="selectedApplication"
              :items="applicationOptions"
              label="Inspect integrity"
              variant="outlined"
              density="compact"
              :loading="isLoadingApplications"
              class="mb-4"
            ></v-select>

            <v-list lines="two">
              <v-list-item v-for="app in applications" :key="app.metadata.uid || app.metadata.name">
                <template v-slot:prepend>
                  <v-avatar :color="applicationSeverity(app)" size="28">
                    <v-icon size="16">{{ applicationIcon(app) }}</v-icon>
                  </v-avatar>
                </template>
                <v-list-item-title class="d-flex align-center ga-2 flex-wrap">
                  <span>{{ app.metadata.name }}</span>
                  <v-chip :color="applicationSeverity(app)" size="x-small" variant="tonal">{{ applicationBadge(app) }}</v-chip>
                </v-list-item-title>
                <v-list-item-subtitle>
                  {{ app.summary.securityPolicyRef }} • {{ app.summary.securityState }}
                  <div v-if="app.summary.lastError" class="text-error font-weight-medium mt-1">
                    {{ app.summary.lastErrorSummary || app.summary.lastError }}
                  </div>
                </v-list-item-subtitle>
              </v-list-item>
            </v-list>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12" lg="8">
        <v-card class="gc-border" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
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
                          <v-text-field v-model="form.name" label="App Name" variant="outlined" density="compact"></v-text-field>
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
                          ></v-select>
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
                          ></v-select>
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
                          </v-text-field>
                          <v-alert v-if="imageError" type="error" variant="tonal" density="compact" class="mt-2 text-caption">
                            Politica Zero-Trust (Kyverno) va bloca acest deployment! Asigurați-vă că respectați regulile lanțului de aprovizionare.
                          </v-alert>
                        </v-col>
                      </v-row>
                      <div class="d-flex mt-6">
                        <v-spacer></v-spacer>
                        <v-btn color="primary" @click="step = 2" :disabled="!isStep1Valid" variant="flat">Continue to Network</v-btn>
                      </div>
                    </div>
                  </v-stepper-window-item>

                  <v-stepper-window-item :value="2">
                    <div class="pa-4">
                      <h3 class="text-subtitle-1 font-weight-medium mb-4">Microsegmentation & Coraza WAF</h3>
                      <v-row>
                        <v-col cols="12" md="6">
                          <v-combobox
                            v-model="form.ingressNamespace"
                            :items="namespaces"
                            label="Allow Ingress From (namespace)"
                            variant="outlined"
                            density="compact"
                            :loading="isLoadingNamespaces"
                            no-data-text="No namespaces found"
                            hint="Select a cluster namespace or type a custom one"
                            persistent-hint
                          ></v-combobox>
                        </v-col>
                        <v-col cols="12" md="6">
                          <v-combobox
                            v-model="form.egressNamespace"
                            :items="namespaces"
                            label="Allow Egress To (namespace)"
                            variant="outlined"
                            density="compact"
                            :loading="isLoadingNamespaces"
                            no-data-text="No namespaces found"
                            hint="Select a cluster namespace or type a custom one"
                            persistent-hint
                          ></v-combobox>
                        </v-col>
                        <v-col cols="12" md="6">
                          <v-text-field v-model="form.egressPorts" label="Allowed Egress Ports" variant="outlined" density="compact"></v-text-field>
                        </v-col>
                        <v-col cols="12">
                          <v-row>
                            <v-col cols="12" md="6">
                              <v-select v-model="form.wafMode" :items="['Monitor', 'Block']" label="WAF Mode" variant="outlined" density="compact"></v-select>
                            </v-col>
                            <v-col cols="12" md="6">
                              <v-select v-model="form.wafProfile" :items="wafProfiles" label="Coraza WAF Profile" variant="outlined" density="compact"></v-select>
                            </v-col>
                          </v-row>
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
                      <v-text-field v-model="form.allowedPaths" label="Allowed Paths" variant="outlined" density="compact" placeholder="/tmp/app-data,/var/cache/app"></v-text-field>
                      <v-select v-model="form.onCompromise" :items="['Isolate', 'Kill']" label="On Compromise Action" variant="outlined" density="compact" class="mt-4"></v-select>

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
                        <v-btn color="success" :disabled="!canWriteApps" @click="submitDeclaration" :loading="isSubmitting" variant="flat" prepend-icon="mdi-google-cloud">
                          {{ canWriteApps ? 'Deploy ZTA Application' : 'Necesită platform-engineer' }}
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
      <div class="dashboard-panel span-12">
        <ReconcileFlow
          :flow="integrityDetails.reconcileFlow"
          :retrying="isRetrying"
          @retry="handleRetryReconcile"
        />
      </div>

      <div class="dashboard-panel span-7-lg span-12-sm">
        <BuildLedgerGraph :nodes="integrityDetails.revalidation?.ledgerNodes || []" :status="integrityDetails.revalidation?.status" />
      </div>
      <div class="dashboard-panel span-5-lg span-12-sm">
        <ProvisioningPlan :plan="integrityDetails.provisioningPlan || []" />
      </div>

      <div class="dashboard-panel span-7-lg span-12-sm">
        <MerkleTreeExplorer :levels="integrityDetails.revalidation?.merkleLevels || []" :summary="integrityDetails.revalidation?.merkle || {}" />
      </div>
      <div class="dashboard-panel span-5-lg span-12-sm">
        <SbomTree :groups="integrityDetails.sbomTree || []" />
      </div>

      <div class="dashboard-panel span-6-lg span-12-sm">
        <v-card class="gc-border panel-card" flat>
          <v-card-title class="text-primary panel-title">Runtime Forensics</v-card-title>
          <v-card-text class="panel-content stack-16">
            <div class="text-body-2">Falco CM {{ integrityDetails.runtimeForensics?.localFalcoRuleConfigMap || 'n/a' }} • Talon rule {{ integrityDetails.runtimeForensics?.talonRuleReference || 'n/a' }}</div>
            <div class="d-flex flex-wrap align-center ga-2">
              <v-chip :color="integrityDetails.runtimeForensics?.localRulePresent ? 'success' : 'error'" variant="tonal">Local rule {{ integrityDetails.runtimeForensics?.localRulePresent ? 'present' : 'missing' }}</v-chip>
              <v-chip :color="integrityDetails.runtimeForensics?.talonRulePresent ? 'success' : 'error'" variant="tonal">Talon {{ integrityDetails.runtimeForensics?.talonRulePresent ? 'patched' : 'not patched' }}</v-chip>
            </div>
            <div>
              <div class="text-caption text-secondary mb-2">Allowed paths</div>
              <div class="d-flex flex-wrap align-center ga-2">
                <v-chip v-for="path in (integrityDetails.runtimeForensics?.allowedPaths || [])" :key="path" size="small" variant="outlined">{{ path }}</v-chip>
              </div>
            </div>
          </v-card-text>
        </v-card>
      </div>

      <div class="dashboard-panel span-6-lg span-12-sm">
        <v-card class="gc-border panel-card" flat>
          <v-card-title class="text-primary panel-title">Sanction History</v-card-title>
          <v-card-text class="panel-content">
            <v-timeline density="compact" align="start" side="end">
              <v-timeline-item v-for="(event, index) in (integrityDetails.sanctionHistory || [])" :key="`${event.kind}-${index}`" size="small" :dot-color="sanctionDotColor(event)">
                <div class="text-body-2 font-weight-medium">{{ event.action }}</div>
                <div class="text-caption text-secondary">{{ event.message }}</div>
                <div class="text-caption mt-1">{{ event.timestamp || 'timestamp unavailable' }}</div>
              </v-timeline-item>
            </v-timeline>
            <div v-if="!(integrityDetails.sanctionHistory || []).length" class="text-caption text-secondary">No enforcement history recorded yet.</div>
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
</style>
