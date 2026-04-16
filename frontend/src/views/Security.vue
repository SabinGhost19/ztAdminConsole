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
  <div class="h-100 d-flex flex-column">
    <div class="d-flex align-center justify-space-between mb-4">
       <h1 class="text-h5 font-weight-medium text-primary">Security Posture & Drift Analyzer</h1>
       <v-btn @click="fetchDriftStatus" :loading="isLoading" color="primary" variant="outlined" size="small">
          <v-icon start>mdi-refresh</v-icon> Refresh State
       </v-btn>
    </div>

    <v-card v-if="driftedApps.length === 0 && !isLoading" class="gc-border d-flex flex-column flex-grow-1" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
      <v-card-text class="d-flex flex-column align-center justify-center text-center h-100 py-16">
        <v-icon size="64" color="success" class="mb-4">mdi-shield-check</v-icon>
        <h3 class="text-h6 font-weight-medium mb-2">Toate sistemele respectă politica Zero-Trust (GitOps)</h3>
        <p class="text-secondary text-caption">Nu a fost detectat niciun fel de supply chain drift sau modificare internă a specificațiilor în clusterul K8s.</p>
      </v-card-text>
    </v-card>

    <v-card v-else-if="currentDrift" class="gc-border d-flex flex-column flex-grow-1" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
      <v-toolbar color="surface" density="compact" class="gc-border-bottom" elevation="0">
        <v-icon color="warning" class="mr-2 ml-4">mdi-alert-circle-outline</v-icon>
        <v-toolbar-title class="text-subtitle-2 font-weight-bold d-flex align-center">
          Policy Drift Detected: <span class="font-mono text-secondary ml-2">{{ currentDrift.namespace }}/{{ currentDrift.name }}</span>
          <v-select
            v-if="driftedApps.length > 1"
            v-model="selectedAppIndex"
            :items="dashboardStore.driftOptions"
            variant="outlined" density="compact" hide-details class="ml-4" style="width: 200px"
          ></v-select>
        </v-toolbar-title>
        <v-spacer></v-spacer>

        <v-chip size="small" color="error" class="mr-4 font-weight-medium">
          Stare Securitate: {{ currentDrift.state }}
        </v-chip>

        <v-btn size="small" variant="outlined" color="primary" class="mr-4" @click="copyPatch">
          <v-icon start size="small">mdi-content-copy</v-icon>
          Copy Code
        </v-btn>
      </v-toolbar>

      <v-card-text class="pa-0 flex-grow-1 position-relative" style="min-height: 500px;">
        <v-row no-gutters>
          <v-col cols="12" md="6" class="pa-4 gc-border-right">
            <div class="text-caption font-weight-medium text-secondary mb-2">
              <v-icon size="x-small" color="success" class="mr-1">mdi-lock-check</v-icon>
              Expected CRD State (GitOps/ZTA)
            </div>
            <pre class="diff-block">{{ currentDrift.original }}</pre>
          </v-col>
          <v-col cols="12" md="6" class="pa-4">
            <div class="text-caption font-weight-medium text-secondary mb-2">
              <v-icon size="x-small" color="error" class="mr-1">mdi-lock-open-alert</v-icon>
              Active Drift Violations (Cluster)
            </div>
            <pre class="diff-block">{{ currentDrift.modified }}</pre>
          </v-col>
        </v-row>
      </v-card-text>
    </v-card>

    <v-row class="mt-4">
      <v-col cols="12" lg="4">
        <v-card class="gc-border" flat>
          <v-card-title class="text-primary">Runtime Forensics Inspector</v-card-title>
          <v-card-text>
            <v-select v-model="selectedApplication" :items="applicationOptions" label="Select application" variant="outlined" density="compact" class="mb-4"></v-select>
            <div v-if="integrityDetails" class="text-body-2">
              <div class="mb-2">Falco CM: {{ integrityDetails.runtimeForensics?.localFalcoRuleConfigMap }}</div>
              <div class="mb-2">Talon rule: {{ integrityDetails.runtimeForensics?.talonRuleReference }}</div>
              <v-chip :color="integrityDetails.runtimeForensics?.localRulePresent ? 'success' : 'warning'" size="small" variant="tonal" class="mr-2">Falco {{ integrityDetails.runtimeForensics?.localRulePresent ? 'present' : 'missing' }}</v-chip>
              <v-chip :color="integrityDetails.runtimeForensics?.talonRulePresent ? 'success' : 'warning'" size="small" variant="tonal">Talon {{ integrityDetails.runtimeForensics?.talonRulePresent ? 'patched' : 'missing' }}</v-chip>
            </div>
            <div v-else class="text-caption text-secondary">Selectează o aplicație pentru runtime-level enforcement evidence.</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" lg="8">
        <v-card class="gc-border" flat>
          <v-card-title class="text-primary">Sanction History</v-card-title>
          <v-card-text>
            <v-timeline density="compact" align="start" side="end">
              <v-timeline-item v-for="(event, index) in (integrityDetails?.sanctionHistory || [])" :key="`${event.kind}-${index}`" size="small" dot-color="warning">
                <div class="text-body-2 font-weight-medium">{{ event.action }}</div>
                <div class="text-caption text-secondary">{{ event.message }}</div>
                <div class="text-caption mt-1">{{ event.timestamp || 'timestamp unavailable' }}</div>
              </v-timeline-item>
            </v-timeline>
            <div v-if="!(integrityDetails?.sanctionHistory || []).length" class="text-caption text-secondary">No sanction history available for the selected application.</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<style scoped>
.h-100 { height: 100%; }
.v-card-text { overflow: hidden; }
.diff-block {
  background: rgba(var(--v-theme-on-surface), 0.04);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 12px;
  padding: 16px;
  min-height: 420px;
  white-space: pre-wrap;
  word-break: break-word;
  overflow: auto;
  font-family: 'Roboto Mono', monospace;
  font-size: 0.8rem;
}
</style>
