<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'

const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()

const selectedAppIndex = ref(0)
const selectedApplication = ref('')
const integrityDetails = ref<any | null>(null)
const isLoading = computed(() => dashboardStore.loadingDrift)
const driftedApps = computed(() => dashboardStore.driftItems)
const applicationOptions = computed(() => dashboardStore.applicationOptions)

const currentDrift = computed(() => driftedApps.value[selectedAppIndex.value])

function sanctionDotColor(event: any) {
  const severity = String(event?.severity || '').toLowerCase()
  if (severity === 'success') return 'success'
  if (severity === 'warning') return 'warning'
  if (severity === 'error') return 'error'

  const action = String(event?.action || '').toLowerCase()
  if (action.includes('verified')) return 'success'
  if (action.includes('alert') || action.includes('kill') || action.includes('isolate') || action.includes('blocked') || action.includes('noncompliant')) return 'error'
  return 'warning'
}

async function fetchDriftStatus() {
  await dashboardStore.fetchDrift(true)
}

onMounted(() => {
  fetchDriftStatus()
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

function copyPatch() {
  const payload = currentDrift.value
    ? `# Expected\n${currentDrift.value.original}\n\n# Current\n${currentDrift.value.modified}`
    : 'No drift payload available.'
  navigator.clipboard.writeText(payload)
  notifyStore.addAlert({
    error_code: 'PATCH_COPIED_SUCCESS',
    message: 'Fragmentul YAML a fost copiat în clipboard.',
    technical_details: 'Drift-ul poate fi reparat prin reconciliere sau kubectl apply pe starea dorită.',
    component: 'SECURITY_MONACO',
    trace_id: Math.random().toString(36).substring(2),
    action_required: '',
    type: 'warning'
  })
}
</script>

<template>
  <v-container fluid class="pa-6">
    <div class="d-flex align-center justify-space-between mb-5 ga-4 flex-wrap">
      <div>
        <h1 class="text-h5 font-weight-medium text-primary">Security Posture &amp; Drift Analyzer</h1>
        <div class="text-caption text-medium-emphasis mt-1">
          GitOps/ZTA expected state vs. live cluster drift, runtime enforcement evidence, and sanction history.
        </div>
      </div>
      <v-btn @click="fetchDriftStatus" :loading="isLoading" color="primary" variant="outlined" size="small">
        <v-icon start>mdi-refresh</v-icon> Refresh State
      </v-btn>
    </div>

    <!-- Compliant (no drift) -->
    <v-card v-if="driftedApps.length === 0 && !isLoading" class="gc-card mb-6" flat>
      <v-card-text class="d-flex flex-column align-center justify-center text-center py-12">
        <v-icon size="56" color="success" class="mb-3">mdi-shield-check</v-icon>
        <h3 class="text-h6 font-weight-medium mb-2">All systems comply with the Zero-Trust policy (GitOps)</h3>
        <p class="text-medium-emphasis text-caption mb-0" style="max-width: 540px">
          No supply-chain drift or in-cluster spec tampering detected across the K8s cluster.
        </p>
      </v-card-text>
    </v-card>

    <!-- Drift detected -->
    <v-card v-else-if="currentDrift" class="gc-card mb-6" flat>
      <v-toolbar color="surface" density="compact" elevation="0" class="gc-border-bottom">
        <v-icon color="warning" class="mr-2 ml-4">mdi-alert-circle-outline</v-icon>
        <v-toolbar-title class="text-subtitle-2 font-weight-bold d-flex align-center flex-wrap ga-2">
          <span>Policy Drift Detected</span>
          <span class="font-mono text-medium-emphasis">{{ currentDrift.namespace }}/{{ currentDrift.name }}</span>
          <v-select
            v-if="driftedApps.length > 1"
            v-model="selectedAppIndex"
            :items="dashboardStore.driftOptions"
            variant="outlined" density="compact" hide-details style="width: 220px"
          ></v-select>
        </v-toolbar-title>
        <v-spacer></v-spacer>
        <v-chip size="small" color="error" variant="flat" class="mr-3 font-weight-medium">{{ currentDrift.state }}</v-chip>
        <v-btn size="small" variant="outlined" color="primary" class="mr-4" @click="copyPatch">
          <v-icon start size="small">mdi-content-copy</v-icon> Copy Code
        </v-btn>
      </v-toolbar>

      <v-row no-gutters>
        <v-col cols="12" md="6" class="pa-4 gc-border-right">
          <div class="text-caption font-weight-medium text-medium-emphasis mb-2">
            <v-icon size="x-small" color="success" class="mr-1">mdi-lock-check</v-icon>
            Expected CRD State (GitOps/ZTA)
          </div>
          <pre class="diff-block">{{ currentDrift.original }}</pre>
        </v-col>
        <v-col cols="12" md="6" class="pa-4">
          <div class="text-caption font-weight-medium text-medium-emphasis mb-2">
            <v-icon size="x-small" color="error" class="mr-1">mdi-lock-open-alert</v-icon>
            Active Drift Violations (Cluster)
          </div>
          <pre class="diff-block">{{ currentDrift.modified }}</pre>
        </v-col>
      </v-row>
    </v-card>

    <!-- Runtime forensics + sanction history (equal-height columns) -->
    <v-row align="stretch">
      <v-col cols="12" lg="4" class="d-flex">
        <v-card class="gc-card flex-grow-1" flat>
          <v-card-title class="text-subtitle-1 font-weight-medium">Runtime Forensics Inspector</v-card-title>
          <v-card-text>
            <v-select
              v-model="selectedApplication" :items="applicationOptions" label="Select application"
              variant="outlined" density="compact" hide-details class="mb-4"
            ></v-select>
            <div v-if="integrityDetails" class="text-body-2">
              <div class="d-flex justify-space-between align-center mb-2">
                <span class="text-medium-emphasis">Falco ConfigMap</span>
                <span class="font-mono text-truncate ml-3" style="max-width: 60%">{{ integrityDetails.runtimeForensics?.localFalcoRuleConfigMap || '—' }}</span>
              </div>
              <div class="d-flex justify-space-between align-center mb-3">
                <span class="text-medium-emphasis">Talon rule</span>
                <span class="font-mono text-truncate ml-3" style="max-width: 60%">{{ integrityDetails.runtimeForensics?.talonRuleReference || '—' }}</span>
              </div>
              <div class="d-flex ga-2 flex-wrap">
                <v-chip :color="integrityDetails.runtimeForensics?.localRulePresent ? 'success' : 'error'" size="small" variant="tonal">Falco {{ integrityDetails.runtimeForensics?.localRulePresent ? 'present' : 'missing' }}</v-chip>
                <v-chip :color="integrityDetails.runtimeForensics?.talonRulePresent ? 'success' : 'error'" size="small" variant="tonal">Talon {{ integrityDetails.runtimeForensics?.talonRulePresent ? 'patched' : 'missing' }}</v-chip>
              </div>
            </div>
            <div v-else class="text-caption text-medium-emphasis">Select an application to load runtime-level enforcement evidence.</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" lg="8" class="d-flex">
        <v-card class="gc-card flex-grow-1" flat>
          <v-card-title class="text-subtitle-1 font-weight-medium">Sanction History</v-card-title>
          <v-card-text>
            <v-timeline
              v-if="(integrityDetails?.sanctionHistory || []).length"
              density="compact" align="start" side="end" truncate-line="both" class="pl-1"
            >
              <v-timeline-item
                v-for="(event, index) in integrityDetails.sanctionHistory"
                :key="`${event.kind}-${index}`" size="small" :dot-color="sanctionDotColor(event)"
              >
                <div class="text-body-2 font-weight-medium">{{ event.action }}</div>
                <div class="text-caption text-medium-emphasis">{{ event.message }}</div>
                <div class="text-caption text-disabled mt-1">{{ event.timestamp || 'timestamp unavailable' }}</div>
              </v-timeline-item>
            </v-timeline>
            <div v-else class="text-caption text-medium-emphasis py-6 text-center">
              {{ selectedApplication ? 'No sanction history for the selected application.' : 'Select an application to view its sanction history.' }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
.gc-card {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 12px;
}
.font-mono { font-family: 'Roboto Mono', monospace; }
.diff-block {
  background: rgba(var(--v-theme-on-surface), 0.04);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 12px;
  padding: 16px;
  min-height: 320px;
  max-height: 520px;
  white-space: pre-wrap;
  word-break: break-word;
  overflow: auto;
  font-family: 'Roboto Mono', monospace;
  font-size: 0.8rem;
  line-height: 1.5;
}
</style>
