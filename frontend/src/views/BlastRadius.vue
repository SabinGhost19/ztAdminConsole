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
import type { BlastRadiusResponse } from './blast-radius/types'

const state = reactive({
  cve: '',
  loading: false,
  data: null as BlastRadiusResponse | null,
  errorMessage: '',
})

// "Only in-cluster" filter — default ON so the auditor sees the actionable
// signal first (packages with live deployments). The counter chips inside
// the topology toolbar surface the M/N breakdown directly.
const onlyInCluster = ref(true)

const guacHealth = ref<{ reachable: boolean; endpoint?: string; reason?: string } | null>(null)

// Known vulnerabilities loaded once for the picker. Each item carries the
// raw ID, the family (GHSA / CVE / Debian / ...) and how many distinct
// packages it touches — that count is the most useful sort key.
interface KnownVuln {
  id: string
  affectedPackageCount: number
  family: string
}
const knownVulns = ref<KnownVuln[]>([])
const knownVulnsLoading = ref(false)

// Vuetify v-combobox needs (title, value) items. `props` carries the raw
// vuln object so the template can show the family + package count chips.
const vulnPickerItems = computed(() =>
  knownVulns.value.map(v => ({
    title: v.id,
    value: v.id,
    props: { subtitle: `${v.family} · ${v.affectedPackageCount} pachet(e)` },
    family: v.family,
    affectedPackageCount: v.affectedPackageCount,
  })),
)

async function probeGuac() {
  try {
    const { data } = await api.get('/guac/health')
    guacHealth.value = data
  } catch {
    guacHealth.value = { reachable: false, reason: 'health endpoint unreachable' }
  }
}

async function loadKnownVulnerabilities() {
  knownVulnsLoading.value = true
  try {
    const { data } = await api.get<{ vulnerabilities: KnownVuln[] }>('/guac/vulnerabilities')
    knownVulns.value = data.vulnerabilities ?? []
  } catch {
    // Fail silently — the free-text input still works, picker just stays empty.
    knownVulns.value = []
  } finally {
    knownVulnsLoading.value = false
  }
}

// v-combobox model: when the user picks an item the model is set to the
// item object `{ title, value, ... }`; when they type free-text it's a
// plain string. Normalise both to a string before validation.
function normaliseCveModel(v: unknown): string {
  if (typeof v === 'string') return v
  if (v && typeof v === 'object') {
    const obj = v as Record<string, unknown>
    if (typeof obj.value === 'string') return obj.value
    if (typeof obj.title === 'string') return obj.title
  }
  return ''
}

async function runQuery() {
  const raw = normaliseCveModel(state.cve).trim()
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

probeGuac()
loadKnownVulnerabilities()
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
        <v-combobox
          v-model="state.cve"
          :items="vulnPickerItems"
          :loading="knownVulnsLoading"
          label="Vulnerability Identifier"
          placeholder="Selectează din graf sau scrie CVE-…, GHSA-…, debian-cve-…"
          variant="outlined"
          density="comfortable"
          hide-details
          item-title="title"
          item-value="value"
          :return-object="false"
          clearable
          @keyup.enter="runQuery"
        >
          <template #item="{ props: itemProps, item }">
            <v-list-item v-bind="itemProps">
              <template #prepend>
                <v-chip
                  size="x-small"
                  variant="tonal"
                  :color="item.raw.family === 'GHSA' ? 'purple'
                    : item.raw.family === 'Debian' ? 'amber'
                    : item.raw.family === 'CVE' ? 'red'
                    : 'grey'"
                  class="me-2"
                >
                  {{ item.raw.family }}
                </v-chip>
              </template>
              <template #append>
                <span class="text-caption text-medium-emphasis">
                  {{ item.raw.affectedPackageCount }} pkg
                </span>
              </template>
            </v-list-item>
          </template>
          <template #no-data>
            <v-list-item>
              <v-list-item-subtitle class="text-medium-emphasis">
                Niciun ID din graf — scrie unul manual.
              </v-list-item-subtitle>
            </v-list-item>
          </template>
        </v-combobox>
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
      v-model:only-in-cluster="onlyInCluster"
    />
  </v-container>
</template>

<style scoped>
.text-mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85rem; }
</style>
