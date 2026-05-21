<script setup lang="ts">
/**
 * "Blast Radius" view — the killer demo for the GUAC integration.
 *
 * Input: a CVE id (typed in the search bar).
 * Action: backend asks GUAC which packages contain that CVE, then joins
 *         the result with the live ZTA list to surface namespace/deployment
 *         context AND any VEX exemption verdicts.
 * Output: a native tree (no iframe) the auditor can read at a glance,
 *         coloured red for affected / green for VEX-exempted.
 */
import { computed, reactive, ref } from 'vue'
import { api } from '../api/axios'
import BlastRadiusTopology from './blast-radius/BlastRadiusTopology.vue'
import BlastRadiusInspector from './blast-radius/BlastRadiusInspector.vue'
import type {
  BlastNodeData,
  BlastRadiusResponse,
  VulnerablePackage,
} from './blast-radius/types'

const state = reactive({
  cve: '',
  loading: false,
  data: null as BlastRadiusResponse | null,
  errorMessage: '',
})

// "Only in-cluster" filter — default ON so the auditor sees the actionable
// signal first (packages with live deployments). Toggle OFF reveals the
// graph-only packages too.
const onlyInCluster = ref(true)

function packageIsInCluster(pkg: VulnerablePackage): boolean {
  return (pkg.affectedImages ?? []).some(img => (img.deployments?.length ?? 0) > 0)
}

// Header counters — filtering itself happens inside the topology component.
const totalPackages = computed(() => state.data?.vulnerablePackages?.length ?? 0)
const inClusterCount = computed(
  () => (state.data?.vulnerablePackages ?? []).filter(packageIsInCluster).length,
)

const guacHealth = ref<{ reachable: boolean; endpoint?: string; reason?: string } | null>(null)

async function probeGuac() {
  try {
    const { data } = await api.get('/guac/health')
    guacHealth.value = data
  } catch {
    guacHealth.value = { reachable: false, reason: 'health endpoint unreachable' }
  }
}

async function runQuery() {
  const raw = state.cve.trim()
  // GUAC stores identifiers in three shapes coming from osv-certifier:
  // "cve-2024-1234", "ghsa-xxxx-xxxx-xxxx", "debian-cve-2024-1234".
  // Accept any of these (case-insensitive); GUAC normalises to lowercase.
  if (!/^(cve|ghsa|debian-cve|osv|rhsa|alas|gms)-/i.test(raw)) {
    state.errorMessage = 'Introdu un identificator valid (CVE-…, GHSA-…, debian-cve-…).'
    return
  }
  state.errorMessage = ''
  state.loading = true
  try {
    const { data } = await api.get<BlastRadiusResponse>('/guac/blast-radius', {
      params: { cve: raw.toLowerCase(), enrich_cluster: true },
    })
    state.data = data
  } catch (err: any) {
    state.errorMessage = err?.response?.data?.detail || err?.message || 'Eroare necunoscută.'
    state.data = null
  } finally {
    state.loading = false
  }
}

// Inspector (right-side drawer) state. The topology component emits the
// `data` payload of the clicked node — we just keep a copy and toggle the
// drawer open.
const inspectorOpen = ref(false)
const inspectorSelected = ref<BlastNodeData | null>(null)
function onNodeSelected(data: BlastNodeData) {
  inspectorSelected.value = data
  inspectorOpen.value = true
}

probeGuac()
</script>

<template>
  <v-container fluid class="pa-6">
    <v-row align="center" class="mb-2">
      <v-col cols="auto">
        <h1 class="text-h5 font-weight-medium">Blast Radius Explorer</h1>
        <p class="text-medium-emphasis">
          Interogare GUAC + corelare cu starea curentă a aplicațiilor din cluster.
          Sursele acoperite: SBOM SPDX, OpenVEX, VBBI, SLSA, edge-uri deployment scrise asincron de operator.
        </p>
      </v-col>
      <v-spacer />
      <v-col cols="auto" v-if="guacHealth">
        <v-chip
          :color="guacHealth.reachable ? 'success' : 'error'"
          :prepend-icon="guacHealth.reachable ? 'mdi-graph-outline' : 'mdi-graph-off-outline'"
          variant="tonal"
        >
          GUAC {{ guacHealth.reachable ? 'online' : 'offline' }}
        </v-chip>
      </v-col>
    </v-row>

    <v-card variant="flat" class="gc-border mb-4" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)">
      <v-card-text class="d-flex align-center ga-3">
        <v-text-field
          v-model="state.cve"
          label="Vulnerability Identifier"
          placeholder="CVE-…, GHSA-…, debian-cve-…"
          variant="outlined"
          density="comfortable"
          hide-details
          @keyup.enter="runQuery"
        />
        <v-btn
          color="primary"
          :loading="state.loading"
          :disabled="!guacHealth?.reachable"
          @click="runQuery"
          prepend-icon="mdi-radar"
        >
          Simulate Blast Radius
        </v-btn>
      </v-card-text>
      <v-card-text class="py-2 d-flex align-center">
        <v-switch
          v-model="onlyInCluster"
          label="Doar pachete care rulează în cluster"
          color="primary"
          density="compact"
          hide-details
        />
        <v-spacer />
        <span v-if="state.data && totalPackages" class="text-medium-emphasis text-caption">
          {{ inClusterCount }} în cluster / {{ totalPackages }} total în graf
        </span>
      </v-card-text>
    </v-card>

    <v-alert v-if="state.errorMessage" type="error" class="mb-4" variant="tonal" closable @click:close="state.errorMessage = ''">
      {{ state.errorMessage }}
    </v-alert>
    <v-alert v-if="state.data?.error" type="warning" class="mb-4" variant="tonal">
      GUAC a răspuns cu un mesaj: {{ state.data.error }}
    </v-alert>
    <v-alert v-if="state.data?.guacUnavailable" type="info" class="mb-4" variant="tonal">
      GUAC nu este configurat — backend-ul nu poate face query-ul. Configurați
      <code>GUAC_GRAPHQL_URL</code> în deployment-ul backend-ului.
    </v-alert>

    <BlastRadiusTopology
      v-if="state.data"
      :response="state.data"
      :only-in-cluster="onlyInCluster"
      @node-selected="onNodeSelected"
      @disable-filter="onlyInCluster = false"
    />

    <BlastRadiusInspector
      v-model="inspectorOpen"
      :selected="inspectorSelected"
    />
  </v-container>
</template>

<style scoped>
.text-mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85rem; }
</style>
