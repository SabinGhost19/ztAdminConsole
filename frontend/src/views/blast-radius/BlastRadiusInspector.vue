<script setup lang="ts">
// Side drawer with details for the currently selected node. Same component
// for every node kind — picks the right template via `data.kind`.

import { computed } from 'vue'
import type { BlastNodeData } from './types'

const props = defineProps<{
  modelValue: boolean
  selected: BlastNodeData | null
}>()

defineEmits<{
  (e: 'update:modelValue', v: boolean): void
}>()

const title = computed(() => {
  if (!props.selected) return ''
  switch (props.selected.kind) {
    case 'cve': return props.selected.cve
    case 'package': return `${props.selected.pkg.name} v${props.selected.pkg.version || '?'}`
    case 'image': return props.selected.repo || props.selected.image.image
    case 'deployment':
      return `${props.selected.deployment.namespace} / ${props.selected.deployment.name}`
  }
})
</script>

<template>
  <v-navigation-drawer
    :model-value="modelValue"
    @update:model-value="$emit('update:modelValue', $event)"
    location="right"
    temporary
    width="380"
  >
    <v-toolbar density="compact" color="surface">
      <v-toolbar-title class="text-body-1 font-weight-medium text-truncate">
        {{ title }}
      </v-toolbar-title>
      <v-btn icon variant="text" @click="$emit('update:modelValue', false)">
        <v-icon>mdi-close</v-icon>
      </v-btn>
    </v-toolbar>
    <v-divider />

    <div class="pa-4" v-if="selected?.kind === 'cve'">
      <p class="text-medium-emphasis text-caption mb-2">Vulnerability identifier</p>
      <code class="text-mono">{{ selected.cve }}</code>
      <v-divider class="my-3" />
      <div class="d-flex justify-space-between">
        <span>Pachete în cluster</span>
        <strong>{{ selected.inClusterCount }}</strong>
      </div>
      <div class="d-flex justify-space-between">
        <span>Pachete în graf</span>
        <strong>{{ selected.totalPackages }}</strong>
      </div>
    </div>

    <div class="pa-4" v-else-if="selected?.kind === 'package'">
      <p class="text-medium-emphasis text-caption mb-2">Pachet vulnerabil</p>
      <div class="text-body-2 mb-1">
        <strong>{{ selected.pkg.name }}</strong>
        <span class="text-medium-emphasis"> v{{ selected.pkg.version || '?' }}</span>
      </div>
      <v-chip v-if="selected.pkg.type" size="small" variant="outlined">
        {{ selected.pkg.type }}
      </v-chip>
      <v-divider class="my-3" />
      <div class="d-flex justify-space-between">
        <span>Imagini afectate</span>
        <strong>{{ selected.imageCount }}</strong>
      </div>
      <div class="d-flex justify-space-between">
        <span>Deployment-uri live</span>
        <strong>{{ selected.deploymentCount }}</strong>
      </div>
      <div class="d-flex justify-space-between">
        <span>Verdict</span>
        <v-chip size="x-small" :color="selected.verdict === 'critical' ? 'error'
          : selected.verdict === 'exempted' ? 'success' : 'grey'" variant="tonal">
          {{ selected.verdict }}
        </v-chip>
      </div>
    </div>

    <div class="pa-4" v-else-if="selected?.kind === 'image'">
      <p class="text-medium-emphasis text-caption mb-2">OCI image</p>
      <div class="text-mono text-caption break-all mb-2">{{ selected.image.image }}</div>
      <v-divider class="my-3" />
      <div class="text-caption text-medium-emphasis mb-1">Repository</div>
      <div class="text-mono text-body-2 break-all">{{ selected.repo }}</div>
      <div class="text-caption text-medium-emphasis mt-3 mb-1">Digest</div>
      <div class="text-mono text-caption break-all">{{ selected.digest || '—' }}</div>
      <v-divider class="my-3" />
      <div class="d-flex justify-space-between">
        <span>Deployment-uri legate</span>
        <strong>{{ selected.image.deployments?.length ?? 0 }}</strong>
      </div>
    </div>

    <div class="pa-4" v-else-if="selected?.kind === 'deployment'">
      <p class="text-medium-emphasis text-caption mb-2">Kubernetes deployment</p>
      <div class="text-body-2">
        <strong>{{ selected.deployment.namespace }} / {{ selected.deployment.name }}</strong>
      </div>
      <v-divider class="my-3" />
      <div class="d-flex justify-space-between mb-1">
        <span>Trust level</span>
        <v-chip size="x-small" variant="outlined">{{ selected.deployment.trustLevel || '?' }}</v-chip>
      </div>
      <div class="d-flex justify-space-between mb-1">
        <span>Security state</span>
        <v-chip size="x-small" variant="outlined">{{ selected.deployment.securityState || '?' }}</v-chip>
      </div>
      <div class="d-flex justify-space-between">
        <span>VEX exempt</span>
        <v-chip
          size="x-small"
          :color="selected.deployment.vexExempted ? 'success' : 'error'"
          variant="tonal"
        >
          {{ selected.deployment.vexExempted ? 'yes' : 'no' }}
        </v-chip>
      </div>
    </div>

    <div class="pa-4 text-medium-emphasis" v-else>
      Selectează un nod pentru detalii.
    </div>
  </v-navigation-drawer>
</template>

<style scoped>
.break-all { word-break: break-all; }
.text-mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; }
</style>
