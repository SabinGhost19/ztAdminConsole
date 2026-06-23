<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useDashboardStore } from '../store/dashboard'
import { useAuthStore } from '../store/auth'
import { useRelativeTime } from '../composables/useRelativeTime'
import KpiCard from '../components/overview/KpiCard.vue'
import TrustPostureCard from '../components/overview/TrustPostureCard.vue'
import DistributionBars from '../components/overview/DistributionBars.vue'
import OperatorHealthCard from '../components/overview/OperatorHealthCard.vue'
import SecurityFeedCard from '../components/overview/SecurityFeedCard.vue'

const dashboardStore = useDashboardStore()
const auth = useAuthStore()

const isLoading = computed(() => dashboardStore.loadingOverview)
const firstLoad = computed(() => isLoading.value && !dashboardStore.overview)

const summary = computed(() => dashboardStore.summary)
const trustScore = computed(() => dashboardStore.trustScore)
const ztaPhases = computed(() => dashboardStore.ztaPhases)
const jitStates = computed(() => dashboardStore.jitStates)
const operatorHealth = computed(() => dashboardStore.operatorHealth)
const recentEvents = computed(() => dashboardStore.recentEvents)
const jitAnalytics = computed(() => dashboardStore.jitAnalytics || { activeSessions: 0, blockedUsers: [], deniedByType: {} })
const breakglassAnalytics = computed(() => dashboardStore.breakglassAnalytics || { agents: { healthy: 0, total: 0 }, audit: { denied: 0, denied_per_node: {} } })

const canJit = computed(() => auth.can('jit:read'))
const canBreakglass = computed(() => auth.can('breakglass:read'))

const updatedLabel = useRelativeTime(() => dashboardStore.overviewUpdatedAt)

const deniedEntries = computed(() => Object.entries(jitAnalytics.value.deniedByType || {}))

/** Derived single-glance posture from operators, high-severity events and degraded apps. */
const posture = computed(() => {
  const operatorsDown = operatorHealth.value.some((o: any) => o.status !== 'unknown' && !o.healthy)
  const highEvents = recentEvents.value.some((e: any) => e.severity === 'high')
  const degraded = (summary.value.degradedApplications || 0) > 0
  if (operatorsDown || highEvents) return { label: 'Degraded', color: 'error', icon: 'mdi-shield-alert-outline' }
  if (degraded || recentEvents.value.length > 0) return { label: 'Attention', color: 'warning', icon: 'mdi-shield-half-full' }
  return { label: 'Healthy', color: 'success', icon: 'mdi-shield-check-outline' }
})

function refresh() {
  dashboardStore.fetchOverview(true).catch(() => undefined)
  if (canJit.value) dashboardStore.fetchJitAnalytics()
  if (canBreakglass.value) dashboardStore.fetchBreakglassAnalytics()
}

onMounted(() => {
  refresh()
})
</script>

<template>
  <div>
    <!-- Header -->
    <div class="d-flex align-center justify-space-between flex-wrap ga-3 mb-5">
      <div class="d-flex align-center ga-3">
        <h1 class="text-h5 font-weight-medium text-primary">Cluster Overview</h1>
        <v-chip :color="posture.color" variant="tonal" size="small" class="font-weight-medium">
          <v-icon start size="16">{{ posture.icon }}</v-icon>{{ posture.label }}
        </v-chip>
      </div>
      <div class="d-flex align-center ga-3">
        <span class="text-caption text-secondary">Updated {{ updatedLabel }}</span>
        <v-btn color="primary" variant="outlined" size="small" :loading="isLoading" @click="refresh">
          <v-icon start>mdi-refresh</v-icon>Refresh
        </v-btn>
      </div>
    </div>

    <!-- KPI strip -->
    <v-row dense class="mb-1">
      <v-col cols="12" sm="6" md="4" lg="2">
        <KpiCard label="Trust Score" :value="`${trustScore.value}%`" icon="mdi-shield-check-outline" accent="primary"
          :hint="`${trustScore.verified} / ${trustScore.total} verified`" hint-color="success" to="/security" :loading="firstLoad" />
      </v-col>
      <v-col cols="12" sm="6" md="4" lg="2">
        <KpiCard label="Applications" :value="summary.applications" icon="mdi-cube-outline" accent="info"
          :hint="`${summary.verifiedApplications} verified`" hint-color="success" to="/apps" :loading="firstLoad" />
      </v-col>
      <v-col cols="12" sm="6" md="4" lg="2">
        <KpiCard label="Secret Bindings" :value="summary.secretBindings" icon="mdi-lock-pattern" accent="primary"
          to="/secrets" :loading="firstLoad" />
      </v-col>
      <v-col cols="12" sm="6" md="4" lg="2">
        <KpiCard label="Supply-Chain Policies" :value="summary.supplyChainPolicies" icon="mdi-shield-link-variant" accent="info"
          to="/sca" :loading="firstLoad" />
      </v-col>
      <v-col v-if="canJit" cols="12" sm="6" md="4" lg="2">
        <KpiCard label="JIT Requests" :value="summary.jitRequests" icon="mdi-shield-account-outline" accent="warning"
          :hint="`${jitAnalytics.activeSessions} live sessions`" to="/jit" :loading="firstLoad" />
      </v-col>
      <v-col v-if="canBreakglass" cols="12" sm="6" md="4" lg="2">
        <KpiCard label="Node Protection" :value="`${breakglassAnalytics.agents.healthy}/${breakglassAnalytics.agents.total}`"
          icon="mdi-shield-key-outline" accent="success" :hint="`${breakglassAnalytics.audit.denied} denied`"
          hint-color="warning" to="/break-glass" :loading="firstLoad" />
      </v-col>
    </v-row>

    <!-- Visual analytics -->
    <v-row class="mb-1">
      <v-col cols="12" md="4">
        <TrustPostureCard :trust-score="trustScore" :loading="firstLoad" />
      </v-col>
      <v-col cols="12" md="4">
        <DistributionBars title="ZTA Phases" icon="mdi-state-machine" :data="ztaPhases" :loading="firstLoad" />
      </v-col>
      <v-col cols="12" md="4">
        <DistributionBars title="JIT States" icon="mdi-account-clock-outline" :data="jitStates" :loading="firstLoad" />
      </v-col>
    </v-row>

    <!-- Operational detail -->
    <v-row>
      <v-col cols="12" lg="5">
        <OperatorHealthCard :operators="operatorHealth" :loading="firstLoad" />
      </v-col>
      <v-col cols="12" lg="7">
        <SecurityFeedCard :events="recentEvents" :loading="firstLoad" />
      </v-col>
    </v-row>

    <!-- JIT denied access analytics -->
    <v-row v-if="canJit" class="mt-1">
      <v-col cols="12">
        <v-card class="gc-border" flat>
          <v-card-title class="d-flex align-center text-primary text-subtitle-1 font-weight-medium">
            <v-icon size="18" class="mr-2">mdi-cancel</v-icon>JIT Denied Access
          </v-card-title>
          <v-card-text>
            <div v-if="deniedEntries.length" class="d-flex flex-wrap ga-2">
              <v-chip v-for="[reason, count] in deniedEntries" :key="reason" color="warning" variant="tonal" size="small">
                <v-icon start size="14">mdi-block-helper</v-icon>{{ reason }}: {{ count }}
              </v-chip>
            </div>
            <div v-else class="d-flex align-center">
              <v-icon size="18" class="mr-2 text-success">mdi-check-circle-outline</v-icon>
              <span class="text-caption text-secondary">No denied requests in the live window.</span>
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<style scoped>
.gc-border { border: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important; }
</style>
