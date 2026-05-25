<script setup lang="ts">
/**
 * Compact wrapper for the Blast Radius topology, embedded inside the ZTA
 * pipeline view. Accepts a list of CVE candidates (e.g. derived from this
 * app's trivy/SBOM results); on demand fires a GUAC query and renders
 * BlastRadiusTopology inline. Lets the operator pivot from "supply-chain
 * scan failed on CVE-X" straight into the cluster-wide blast radius for X
 * without leaving the page.
 */
import { computed, ref } from 'vue'
import { api } from '../api/axios'
import BlastRadiusTopology from '../views/blast-radius/BlastRadiusTopology.vue'
import type { BlastRadiusResponse } from '../views/blast-radius/types'

const props = defineProps<{
  image?: string
  candidateCves?: string[]
}>()

const cve = ref<string>('')
const loading = ref(false)
const data = ref<BlastRadiusResponse | null>(null)
const errorMessage = ref('')
const expanded = ref(false)

const suggested = computed(() => (props.candidateCves || []).slice(0, 12))

async function runQuery(rawInput?: string) {
  const target = (rawInput ?? cve.value).trim()
  if (!target) {
    errorMessage.value = 'Selectează un CVE pentru a rula interogarea.'
    return
  }
  if (!/^(cve|ghsa|debian-cve|osv|rhsa|alas|gms)-/i.test(target)) {
    errorMessage.value = 'Identificator invalid (CVE-…, GHSA-…, debian-cve-…).'
    return
  }
  errorMessage.value = ''
  loading.value = true
  try {
    cve.value = target
    const resp = await api.get<BlastRadiusResponse>('/guac/blast-radius', {
      params: { cve: target.toLowerCase(), enrich_cluster: true },
    })
    data.value = resp.data
    expanded.value = true
  } catch (exc: any) {
    errorMessage.value = exc?.response?.data?.detail || exc?.message || 'Eroare necunoscută.'
    data.value = null
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <v-card flat border>
    <v-card-title class="d-flex align-center text-body-1">
      <v-icon size="20" class="mr-2">mdi-radar</v-icon>
      Blast radius (GUAC)
      <v-spacer />
      <v-chip v-if="image" size="x-small" variant="outlined" class="text-truncate" style="max-width: 320px;">
        {{ image }}
      </v-chip>
    </v-card-title>
    <v-card-text class="py-2">
      <p class="text-caption text-medium-emphasis mb-2">
        Selectează un CVE detectat de Trivy pentru această aplicație și vezi
        ce alte pachete/deployment-uri din cluster sunt afectate (inclusiv
        statusul VEX).
      </p>

      <div v-if="suggested.length" class="d-flex flex-wrap ga-1 mb-3">
        <v-chip
          v-for="id in suggested"
          :key="id"
          size="small"
          :variant="cve === id ? 'flat' : 'tonal'"
          :color="cve === id ? 'primary' : undefined"
          @click="runQuery(id)"
        >
          {{ id }}
        </v-chip>
      </div>
      <div v-else class="text-caption text-medium-emphasis mb-2">
        Niciun CVE candidat din scanarea curentă. Poți introduce manual:
      </div>

      <div class="d-flex align-center ga-2 mb-2">
        <v-text-field
          v-model="cve"
          density="compact"
          variant="outlined"
          hide-details
          placeholder="CVE-2024-…, GHSA-…, debian-cve-…"
          clearable
          @keyup.enter="runQuery()"
        />
        <v-btn :loading="loading" color="primary" variant="flat" @click="runQuery()">
          Run
        </v-btn>
      </div>
      <div v-if="errorMessage" class="text-caption text-error mb-2">{{ errorMessage }}</div>

      <div v-if="data && expanded">
        <BlastRadiusTopology :response="data" :only-in-cluster="true" />
      </div>
    </v-card-text>
  </v-card>
</template>
