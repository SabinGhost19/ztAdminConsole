<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { api } from '../api/axios'
import { useDashboardStore } from '../store/dashboard'

const dashboardStore = useDashboardStore()

const isLoading = computed(() => dashboardStore.loadingOverview)
const summary = computed(() => dashboardStore.summary)
const trustScore = computed(() => dashboardStore.trustScore)
const operatorHealth = computed(() => dashboardStore.operatorHealth)
const recentEvents = computed(() => dashboardStore.recentEvents)
const realtimeStatus = computed(() => dashboardStore.realtimeStatus)
const jitAnalytics = computed(() => dashboardStore.jitAnalytics || { activeSessions: 0, blockedUsers: [], deniedByType: {} })

let eventSource: EventSource | null = null

onMounted(() => {
  dashboardStore.fetchOverview(true).catch(() => undefined)
  eventSource = new EventSource(`${api.defaults.baseURL}/overview/stream`)
  eventSource.addEventListener('pulse', (event: MessageEvent) => {
    try {
      const payload = JSON.parse(event.data)
      dashboardStore.applyRealtimePulse(payload)
    } catch {
      dashboardStore.setRealtimeDisconnected()
    }
  })
  eventSource.onerror = () => {
    dashboardStore.setRealtimeDisconnected()
  }
})

onUnmounted(() => {
  eventSource?.close()
  dashboardStore.setRealtimeDisconnected()
})
</script>

<template>
  <div>
    <div class="d-flex align-center justify-space-between mb-4">
      <h1 class="text-h5 font-weight-medium text-primary">Overview Dashboard</h1>
      <div class="d-flex align-center ga-3">
        <v-chip :color="realtimeStatus.connected ? 'success' : 'warning'" variant="tonal">
          <v-icon start size="small">{{ realtimeStatus.connected ? 'mdi-access-point' : 'mdi-access-point-off' }}</v-icon>
          {{ realtimeStatus.connected ? 'Live stream active' : 'Live stream reconnecting' }}
        </v-chip>
        <v-btn color="primary" variant="outlined" :loading="isLoading" @click="dashboardStore.fetchOverview(true)">
          <v-icon start>mdi-refresh</v-icon>
          Refresh Pulse
        </v-btn>
      </div>
    </div>

    <v-row class="mb-2">
      <v-col cols="12" md="3">
        <v-card class="gc-border h-100" flat>
          <v-card-text>
            <div class="text-caption text-secondary mb-2">Cluster Trust Score</div>
            <div class="text-h4 font-weight-bold text-primary">{{ trustScore.value }}%</div>
            <div class="text-body-2 mt-2">{{ trustScore.verified }} / {{ trustScore.total }} aplicații verificate</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card class="gc-border h-100" flat>
          <v-card-text>
            <div class="text-caption text-secondary mb-2">Zero Trust Applications</div>
            <div class="text-h4 font-weight-bold">{{ summary.applications }}</div>
            <div class="text-body-2 mt-2 text-success">{{ summary.verifiedApplications }} verified</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card class="gc-border h-100" flat>
          <v-card-text>
            <div class="text-caption text-secondary mb-2">Secret Bindings</div>
            <div class="text-h4 font-weight-bold">{{ summary.secretBindings }}</div>
            <div class="text-body-2 mt-2">{{ summary.supplyChainPolicies }} policy objects active</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card class="gc-border h-100" flat>
          <v-card-text>
            <div class="text-caption text-secondary mb-2">JIT Access Requests</div>
            <div class="text-h4 font-weight-bold">{{ summary.jitRequests }}</div>
            <div class="text-body-2 mt-2 text-warning">{{ summary.degradedApplications }} degraded workloads</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card class="gc-border h-100" flat>
          <v-card-text>
            <div class="text-caption text-secondary mb-2">Live JIT Sessions</div>
            <div class="text-h4 font-weight-bold">{{ jitAnalytics.activeSessions }}</div>
            <div class="text-body-2 mt-2">{{ (jitAnalytics.blockedUsers || []).length }} blocked identities</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row>
      <v-col cols="12" lg="5">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Operator Health</v-card-title>
          <v-card-text>
            <v-list v-if="operatorHealth.length" lines="two">
              <v-list-item v-for="item in operatorHealth" :key="item.name">
                <template v-slot:prepend>
                  <v-avatar :color="item.healthy ? 'success' : 'warning'" size="28">
                    <v-icon size="16">{{ item.healthy ? 'mdi-check' : 'mdi-alert' }}</v-icon>
                  </v-avatar>
                </template>
                <v-list-item-title>{{ item.name }}</v-list-item-title>
                <v-list-item-subtitle>
                  {{ item.pods?.length ? item.pods.map((pod: any) => `${pod.namespace}/${pod.podName} ${pod.phase}`).join(' • ') : 'No pods discovered' }}
                </v-list-item-subtitle>
              </v-list-item>
            </v-list>
            <div v-else class="text-secondary text-caption">No operator telemetry loaded yet.</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" lg="7">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Security Event Feed</v-card-title>
          <v-card-text>
            <div class="text-caption text-secondary mb-4">Last pulse {{ realtimeStatus.lastPulseAt || 'not yet received' }}</div>
            <v-timeline density="compact" align="start" side="end">
              <v-timeline-item
                v-for="(event, index) in recentEvents"
                :key="`${event.kind}-${index}`"
                :dot-color="event.severity === 'high' ? 'error' : 'warning'"
                size="small"
              >
                <div class="text-body-2 font-weight-medium">{{ event.resource }}<span v-if="event.namespace"> / {{ event.namespace }}</span></div>
                <div class="text-caption text-secondary">{{ event.message }}</div>
                <div class="text-caption mt-1">{{ event.timestamp || 'timestamp unavailable' }}</div>
              </v-timeline-item>
            </v-timeline>
            <div v-if="!recentEvents.length" class="text-caption text-secondary">No active findings reported by the backend.</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-2">
      <v-col cols="12" md="6">
        <v-card class="gc-border" flat>
          <v-card-title class="text-primary">Denied Access Analytics</v-card-title>
          <v-card-text>
            <div v-if="Object.keys(jitAnalytics.deniedByType || {}).length" class="d-flex flex-wrap ga-2">
              <v-chip v-for="(count, key) in jitAnalytics.deniedByType" :key="key" color="warning" variant="tonal">
                {{ key }}: {{ count }}
              </v-chip>
            </div>
            <div v-else class="text-caption text-secondary">No denied requests observed in the live window.</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="6">
        <v-card class="gc-border" flat>
          <v-card-title class="text-primary">Realtime Channel</v-card-title>
          <v-card-text>
            <div class="text-body-2">The dashboard now consumes a server-sent event pulse for overview and JIT telemetry.</div>
            <div class="text-caption text-secondary mt-2">If this card falls back to warning, verify ingress buffering and backend connectivity.</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<style scoped>
.gc-border { border: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important; }
</style>