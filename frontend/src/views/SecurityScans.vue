<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useDashboardStore } from '../store/dashboard'

const dashboardStore = useDashboardStore()

const isLoading = computed(() => dashboardStore.loadingSecurityScans)
const data = computed(() => dashboardStore.securityScans || { rollup: {}, items: [] })
const rollup = computed(() => (data.value.rollup || {}) as Record<string, any>)
const items = computed(() => (data.value.items || []) as Record<string, any>[])

const selectedKey = ref<string | null>(null)
const selectedItem = computed(
  () => items.value.find((i) => `${i.namespace}/${i.name}` === selectedKey.value) || null,
)

const appHeaders = [
  { title: 'Application', key: 'app' },
  { title: 'State', key: 'securityState' },
  { title: 'Attestation', key: 'verified' },
  { title: 'Gating', key: 'gating' },
  { title: 'Secrets', key: 'secrets' },
  { title: 'SAST', key: 'sast' },
  { title: 'IaC', key: 'iac' },
  { title: 'Worst', key: 'worstSeverity' },
]

const findingHeaders = [
  { title: 'Severity', key: 'severity' },
  { title: 'Category', key: 'category' },
  { title: 'Tool', key: 'tool' },
  { title: 'Rule', key: 'ruleId' },
  { title: 'Location', key: 'location' },
  { title: 'Title', key: 'title' },
]

const findingRows = computed<Record<string, any>[]>(() =>
  (selectedItem.value?.findings || []).map((f: Record<string, any>) => ({
    ...f,
    location: `${f.file || ''}${f.line ? ':' + f.line : ''}`,
  })),
)

function sevColor(sev?: string): string {
  switch (String(sev || '').toUpperCase()) {
    case 'CRITICAL': return 'error'
    case 'HIGH': return 'deep-orange'
    case 'MEDIUM': return 'warning'
    case 'LOW': return 'info'
    default: return 'grey'
  }
}

function countColor(n: number, danger = false): string {
  if (!n) return 'grey'
  return danger ? 'error' : 'warning'
}

function refresh() {
  dashboardStore.fetchSecurityScans(true).catch(() => undefined)
}

onMounted(() => {
  dashboardStore.fetchSecurityScans(true).catch(() => undefined)
})
</script>

<template>
  <v-container fluid class="pa-6">
    <div class="d-flex align-center mb-4">
      <v-icon size="28" class="mr-3">mdi-bug-check-outline</v-icon>
      <div>
        <h1 class="text-h5 font-weight-bold">Security Scans</h1>
        <div class="text-caption text-medium-emphasis">
          OSS "Snyk-style" pre-build scanning — gitleaks (secrets), checkov (IaC),
          Semgrep (SAST) — signed as <code>security-scan/v1</code> and verified by the operator.
        </div>
      </div>
      <v-spacer />
      <v-btn :loading="isLoading" variant="tonal" prepend-icon="mdi-refresh" @click="refresh">
        Refresh
      </v-btn>
    </div>

    <!-- Cluster rollup -->
    <v-row class="mb-2">
      <v-col cols="6" md="3">
        <v-card flat border>
          <v-card-text>
            <div class="text-caption text-medium-emphasis">Applications</div>
            <div class="text-h4">{{ rollup.applications || 0 }}</div>
            <div class="text-caption">{{ rollup.enforced || 0 }} with policy enforced</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="6" md="3">
        <v-card flat border :color="(rollup.appsWithSecrets || 0) > 0 ? 'error' : undefined">
          <v-card-text>
            <div class="text-caption">Apps with secrets</div>
            <div class="text-h4">{{ rollup.appsWithSecrets || 0 }}</div>
            <div class="text-caption">{{ (rollup.totals || {}).secrets || 0 }} secret findings total</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="6" md="3">
        <v-card flat border>
          <v-card-text>
            <div class="text-caption text-medium-emphasis">SAST findings</div>
            <div class="text-h4">{{ (rollup.totals || {}).sast || 0 }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="6" md="3">
        <v-card flat border>
          <v-card-text>
            <div class="text-caption text-medium-emphasis">IaC findings</div>
            <div class="text-h4">{{ (rollup.totals || {}).iac || 0 }}</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <!-- Per-application table -->
    <v-card flat border class="mb-4">
      <v-card-title class="text-body-1">Per-application results</v-card-title>
      <v-data-table
        :headers="appHeaders"
        :items="items"
        :loading="isLoading"
        density="comfortable"
        hover
        @click:row="(_e: any, { item }: any) => (selectedKey = `${item.namespace}/${item.name}`)"
      >
        <template #item.app="{ item }">
          <div class="font-weight-medium">{{ item.namespace }}/{{ item.name }}</div>
          <div class="text-caption text-medium-emphasis text-truncate" style="max-width: 320px">
            {{ item.image }}
          </div>
        </template>
        <template #item.securityState="{ item }">
          <v-chip size="small" variant="flat"
            :color="item.securityState === 'Compliant' ? 'success' : item.securityState === 'Alert' ? 'warning' : 'error'">
            {{ item.securityState || 'Unknown' }}
          </v-chip>
        </template>
        <template #item.verified="{ item }">
          <v-chip size="small" variant="flat" :color="item.verified ? 'success' : (item.enforced ? 'error' : 'grey')">
            {{ item.verified ? 'verified' : (item.enforced ? 'failed' : 'not enforced') }}
          </v-chip>
        </template>
        <template #item.gating="{ item }">
          <v-chip size="small" variant="outlined" :color="item.gating === 'pass' ? 'success' : item.gating === 'fail' ? 'error' : 'grey'">
            {{ item.gating || '—' }}
          </v-chip>
        </template>
        <template #item.secrets="{ item }">
          <v-chip size="small" variant="flat" :color="countColor(item.counts.secrets, true)">{{ item.counts.secrets }}</v-chip>
        </template>
        <template #item.sast="{ item }">
          <v-chip size="small" variant="flat" :color="countColor(item.counts.sast)">{{ item.counts.sast }}</v-chip>
        </template>
        <template #item.iac="{ item }">
          <v-chip size="small" variant="flat" :color="countColor(item.counts.iac)">{{ item.counts.iac }}</v-chip>
        </template>
        <template #item.worstSeverity="{ item }">
          <v-chip size="small" variant="flat" :color="sevColor(item.worstSeverity)">{{ item.worstSeverity }}</v-chip>
        </template>
        <template #no-data>
          <div class="pa-4 text-medium-emphasis">No security-scan data yet. Apply a SCA with
            <code>securityScanPolicy.enforceSecurityScan: true</code> and let an app reconcile.</div>
        </template>
      </v-data-table>
    </v-card>

    <!-- Findings drill-down -->
    <v-card v-if="selectedItem" flat border>
      <v-card-title class="text-body-1 d-flex align-center">
        Findings — {{ selectedItem.namespace }}/{{ selectedItem.name }}
        <v-spacer />
        <span class="text-caption text-medium-emphasis">commit {{ (selectedItem.commit || '').slice(0, 12) || 'n/a' }}</span>
      </v-card-title>
      <v-alert
        v-if="selectedItem.reason && !selectedItem.verified"
        type="error" variant="tonal" density="compact" class="mx-4 mb-2"
      >
        {{ selectedItem.reason }}
      </v-alert>
      <v-data-table
        :headers="findingHeaders"
        :items="findingRows"
        density="compact"
        :items-per-page="25"
      >
        <template #item.severity="{ item }">
          <v-chip size="x-small" variant="flat" :color="sevColor(item.severity)">{{ item.severity }}</v-chip>
        </template>
        <template #item.title="{ item }">
          <span class="text-caption">{{ item.title }}</span>
        </template>
        <template #no-data>
          <div class="pa-4 text-medium-emphasis">No findings recorded for this application.</div>
        </template>
      </v-data-table>
    </v-card>
  </v-container>
</template>
