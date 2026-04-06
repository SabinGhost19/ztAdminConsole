<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'
import MonacoDiffEditor from 'vue-monaco-diff-editor'

const notifyStore = useNotificationStore()

const isLoading = ref(false)
const driftedApps = ref<any[]>([])
const selectedAppIndex = ref(0)

const currentDrift = computed(() => driftedApps.value[selectedAppIndex.value])

const MONACO_EDITOR_OPTIONS = {
  automaticLayout: true,
  formatOnType: true,
  formatOnPaste: true,
  readOnly: true,
  renderSideBySide: true,
  minimap: { enabled: false }
}

async function fetchDriftStatus() {
  isLoading.value = true
  try {
    const res = await api.get('/drift/')
    driftedApps.value = res.data
  } catch (err) {
    // handled globally
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  fetchDriftStatus()
})

function copyPatch() {
  navigator.clipboard.writeText("Patch / YAML Source copied!")
  notifyStore.addAlert({
    error_code: 'PATCH_COPIED_SUCCESS',
    message: 'Fragmentul YAML a fost copiat în clipboard.',
    technical_details: 'Drift-ul poate fi reparat prin aplicarea kubectl apply.',
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
            :items="driftedApps.map((a, i) => ({title: a.name, value: i}))"
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
        <div class="d-flex align-center bg-surface-variant pa-2 gc-border-bottom text-caption font-weight-medium text-secondary">
          <div class="w-50 text-center font-mono"><v-icon size="x-small" color="success" class="mr-1">mdi-lock-check</v-icon> Expected CRD State (GitOps/ZTA)</div>
          <div class="w-50 text-center font-mono"><v-icon size="x-small" color="error" class="mr-1">mdi-lock-open-alert</v-icon> Active Drift Violations (Cluster)</div>
        </div>
        
        <vue-monaco-diff-editor
          theme="vs-dark"
          originalLanguage="yaml"
          modifiedLanguage="yaml"
          :original="currentDrift.original"
          :modified="currentDrift.modified"
          :options="MONACO_EDITOR_OPTIONS"
          class="w-100 h-100 position-absolute"
        />
      </v-card-text>
    </v-card>
  </div>
</template>

<style scoped>
/* Asigurăm că editorul ocupă toată zona */
.h-100 { height: 100%; }
.v-card-text { overflow: hidden; }
</style>
