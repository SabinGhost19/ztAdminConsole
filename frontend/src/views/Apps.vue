<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import type { AxiosError, AxiosResponse } from 'axios'
import { api } from '../api/axios'
import BuildLedgerGraph from '../components/BuildLedgerGraph.vue'
import MerkleTreeExplorer from '../components/MerkleTreeExplorer.vue'
import SbomTree from '../components/SbomTree.vue'
import TrustCascadeView from '../components/TrustCascadeView.vue'
import VulnerabilityHeatmap from '../components/VulnerabilityHeatmap.vue'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'

const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()

const step = ref(1)
const isSubmitting = ref(false)
const selectedApplication = ref('')
const integrityDetails = ref<any | null>(null)
const isRevalidating = ref(false)

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

const integrityCriticalIssues = computed(() => {
  const details = integrityDetails.value
  if (!details) return []

  const application = details.application || {}
  const summary = application.summary || {}
  const issues = []

  if (summary.lastError) {
    issues.push({
      title: summary.hasHashMismatch ? 'Manifest Hash Mismatch' : 'Verification Failure',
      message: summary.lastError,
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
})

watch(selectedApplication, async (value) => {
  if (!value) {
    integrityDetails.value = null
    return
  }

  const [namespace, name] = value.split('/')
  integrityDetails.value = await dashboardStore.fetchIntegrity(namespace, name, true)
})

async function revalidateIntegrity() {
  if (!selectedApplication.value) return
  const [namespace, name] = selectedApplication.value.split('/')
  isRevalidating.value = true
  try {
    const response = await api.post(`/integrity/applications/${namespace}/${name}/revalidate`)
    integrityDetails.value = response.data
    dashboardStore.setIntegrity(namespace, name, response.data)
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
      dashboardStore.fetchApplications(true).catch(() => undefined)
      dashboardStore.fetchOverview(true).catch(() => undefined)
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
    <h1 class="text-h5 font-weight-medium mb-4 text-primary">ZTA Application Builder</h1>
    <v-row>
      <v-col cols="12" lg="7">
        <v-card class="gc-border" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-text class="pa-0">
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
                    <v-text-field v-model="form.namespace" label="Target Namespace" variant="outlined" density="compact"></v-text-field>
                  </v-col>
                  <v-col cols="12" md="6">
                    <v-text-field v-model="form.securityPolicyName" label="Security Policy Name" variant="outlined" density="compact" hint="SupplyChainAttestation reference" persistent-hint></v-text-field>
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
                    <v-text-field v-model="form.ingressNamespace" label="Allow Ingress From" variant="outlined" density="compact"></v-text-field>
                  </v-col>
                  <v-col cols="12" md="6">
                    <v-text-field v-model="form.egressNamespace" label="Allow Egress To" variant="outlined" density="compact"></v-text-field>
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
                 
                 <div class="bg-surface-variant pa-4 rounded gc-border font-mono text-caption overflow-auto" style="max-height: 250px;">
<pre>{{ yamlPreview }}</pre>
                 </div>

                 <div class="d-flex mt-6">
                  <v-btn variant="text" @click="step = 3">Edit Specs</v-btn>
                  <v-spacer></v-spacer>
                  <v-btn color="success" @click="submitDeclaration" :loading="isSubmitting" variant="flat" prepend-icon="mdi-google-cloud">Deploy ZTA Application</v-btn>
                </div>
              </div>
            </v-stepper-window-item>

          </v-stepper-window>
        </v-stepper>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12" lg="5">
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
                    {{ app.summary.lastError }}
                  </div>
                </v-list-item-subtitle>
              </v-list-item>
            </v-list>
          </v-card-text>
        </v-card>

        <v-card class="gc-border" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary d-flex align-center justify-space-between">
            <span>Integrity Ledger</span>
            <v-btn size="small" variant="outlined" color="primary" :disabled="!selectedApplication" :loading="isRevalidating" @click="revalidateIntegrity">
              Revalidate OCI
            </v-btn>
          </v-card-title>
          <v-card-text>
            <div v-if="isLoadingIntegrity" class="text-caption text-secondary">Loading integrity details...</div>
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

              <v-list lines="two">
              <v-list-item v-for="item in integrityDetails.integrityLedger || []" :key="item.id">
                <template v-slot:prepend>
                  <v-avatar :color="ledgerColor(item.status)" size="28">
                    <v-icon size="16">{{ ledgerIcon(item.status, item.id) }}</v-icon>
                  </v-avatar>
                </template>
                <v-list-item-title class="d-flex align-center ga-2 flex-wrap">
                  <span>{{ item.title }}</span>
                  <v-chip :color="ledgerColor(item.status)" size="x-small" variant="tonal">{{ item.status }}</v-chip>
                </v-list-item-title>
                <v-list-item-subtitle>{{ typeof item.details === 'string' ? item.details : JSON.stringify(item.details) }}</v-list-item-subtitle>
              </v-list-item>
              </v-list>
            </template>
            <div v-else class="text-caption text-secondary">Selectează o aplicație pentru a vedea detaliile VBBI și policy gate-ul.</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row v-if="integrityDetails" class="mt-2">
      <v-col cols="12">
        <TrustCascadeView :cascade="integrityDetails.trustCascade" />
      </v-col>
      <v-col cols="12" xl="7">
        <BuildLedgerGraph :nodes="integrityDetails.revalidation?.ledgerNodes || []" :status="integrityDetails.revalidation?.status" />
      </v-col>
      <v-col cols="12" xl="5">
        <MerkleTreeExplorer :levels="integrityDetails.revalidation?.merkleLevels || []" :summary="integrityDetails.revalidation?.merkle || {}" />
      </v-col>
      <v-col cols="12" lg="6">
        <SbomTree :groups="integrityDetails.sbomTree || []" />
      </v-col>
      <v-col cols="12" lg="6">
        <VulnerabilityHeatmap :heatmap="integrityDetails.vulnerabilityHeatmap" />
      </v-col>
      <v-col cols="12" md="6">
        <v-card class="gc-border" flat>
          <v-card-title class="text-primary">Runtime Forensics</v-card-title>
          <v-card-text>
            <div class="text-body-2 mb-3">Falco CM {{ integrityDetails.runtimeForensics?.localFalcoRuleConfigMap || 'n/a' }} • Talon rule {{ integrityDetails.runtimeForensics?.talonRuleReference || 'n/a' }}</div>
            <div class="d-flex flex-wrap ga-2 mb-3">
              <v-chip :color="integrityDetails.runtimeForensics?.localRulePresent ? 'success' : 'warning'" variant="tonal">Local rule {{ integrityDetails.runtimeForensics?.localRulePresent ? 'present' : 'missing' }}</v-chip>
              <v-chip :color="integrityDetails.runtimeForensics?.talonRulePresent ? 'success' : 'warning'" variant="tonal">Talon {{ integrityDetails.runtimeForensics?.talonRulePresent ? 'patched' : 'not patched' }}</v-chip>
            </div>
            <div class="text-caption text-secondary mb-2">Allowed paths</div>
            <div class="d-flex flex-wrap ga-2">
              <v-chip v-for="path in (integrityDetails.runtimeForensics?.allowedPaths || [])" :key="path" size="small" variant="outlined">{{ path }}</v-chip>
            </div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="6">
        <v-card class="gc-border" flat>
          <v-card-title class="text-primary">Sanction History</v-card-title>
          <v-card-text>
            <v-timeline density="compact" align="start" side="end">
              <v-timeline-item v-for="(event, index) in (integrityDetails.sanctionHistory || [])" :key="`${event.kind}-${index}`" size="small" dot-color="warning">
                <div class="text-body-2 font-weight-medium">{{ event.action }}</div>
                <div class="text-caption text-secondary">{{ event.message }}</div>
                <div class="text-caption mt-1">{{ event.timestamp || 'timestamp unavailable' }}</div>
              </v-timeline-item>
            </v-timeline>
            <div v-if="!(integrityDetails.sanctionHistory || []).length" class="text-caption text-secondary">No enforcement history recorded yet.</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>
