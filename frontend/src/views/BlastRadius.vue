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
import { reactive, ref } from 'vue'
import { api } from '../api/axios'

interface DeploymentEntry {
  namespace?: string
  name?: string
  trustLevel?: string
  securityState?: string
  vexExempted?: boolean
}

interface AffectedImage {
  image: string
  deployments: DeploymentEntry[]
}

interface VulnerablePackage {
  name: string
  version: string
  affectedImages: AffectedImage[]
}

interface BlastRadiusResponse {
  cve: string
  vulnerablePackages: VulnerablePackage[]
  error?: string
  guacUnavailable?: boolean
}

const state = reactive({
  cve: '',
  loading: false,
  data: null as BlastRadiusResponse | null,
  errorMessage: '',
})

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

function deploymentColor(dep: DeploymentEntry) {
  if (dep.vexExempted) return 'success'
  return 'error'
}

function deploymentIcon(dep: DeploymentEntry) {
  return dep.vexExempted ? 'mdi-shield-check' : 'mdi-alert-octagon'
}

function deploymentLabel(dep: DeploymentEntry) {
  if (dep.vexExempted) return 'Exempted via VEX'
  return 'Action required'
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

    <v-card v-if="state.data && state.data.vulnerablePackages?.length" variant="flat" class="gc-border" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)">
      <v-card-title class="d-flex align-center ga-2">
        <v-icon color="error">mdi-alert-circle</v-icon>
        <span>{{ state.data.cve }} — {{ state.data.vulnerablePackages.length }} vulnerable package(s)</span>
      </v-card-title>
      <v-card-text>
        <v-expansion-panels variant="accordion" multiple>
          <v-expansion-panel
            v-for="pkg in state.data.vulnerablePackages"
            :key="pkg.name + ':' + pkg.version"
          >
            <v-expansion-panel-title>
              <v-icon class="me-2" color="warning">mdi-package-variant</v-icon>
              <span class="font-weight-medium">{{ pkg.name }}</span>
              <span class="ms-2 text-medium-emphasis">v{{ pkg.version || '?' }}</span>
              <v-spacer />
              <v-chip size="x-small" variant="tonal">
                {{ pkg.affectedImages?.length || 0 }} affected image(s)
              </v-chip>
            </v-expansion-panel-title>
            <v-expansion-panel-text>
              <v-list density="compact">
                <template v-for="img in pkg.affectedImages" :key="img.image">
                  <v-list-subheader>
                    <v-icon class="me-1" size="small">mdi-docker</v-icon>
                    <span class="text-mono">{{ img.image }}</span>
                  </v-list-subheader>
                  <v-list-item
                    v-for="dep in img.deployments"
                    :key="(dep.namespace || '') + '/' + (dep.name || '')"
                  >
                    <template #prepend>
                      <v-avatar :color="deploymentColor(dep)" size="24">
                        <v-icon size="14">{{ deploymentIcon(dep) }}</v-icon>
                      </v-avatar>
                    </template>
                    <v-list-item-title class="d-flex align-center ga-2">
                      <span>{{ dep.namespace }} / {{ dep.name }}</span>
                      <v-chip :color="deploymentColor(dep)" size="x-small" variant="tonal">
                        {{ deploymentLabel(dep) }}
                      </v-chip>
                      <v-chip v-if="dep.trustLevel" size="x-small" variant="outlined">
                        trust={{ dep.trustLevel }}
                      </v-chip>
                    </v-list-item-title>
                  </v-list-item>
                  <v-list-item v-if="!img.deployments?.length">
                    <v-list-item-subtitle class="text-medium-emphasis">
                      Imaginea este în GUAC, dar nu rulează în niciun namespace urmărit de ZTA.
                    </v-list-item-subtitle>
                  </v-list-item>
                </template>
                <v-list-item v-if="!pkg.affectedImages?.length">
                  <v-list-item-subtitle class="text-medium-emphasis">
                    Niciun deployment afectat — pachet vulnerabil identificat în GUAC, dar nicio imagine activă nu îl conține.
                  </v-list-item-subtitle>
                </v-list-item>
              </v-list>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </v-card-text>
    </v-card>

    <v-alert
      v-else-if="state.data && !state.data.vulnerablePackages?.length"
      type="success"
      variant="tonal"
      class="mt-4"
    >
      Niciun pachet din graful GUAC nu este afectat de {{ state.data.cve }}.
    </v-alert>
  </v-container>
</template>

<style scoped>
.text-mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85rem; }
</style>
