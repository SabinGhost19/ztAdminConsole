<script setup lang="ts">
import { Handle, Position } from '@vue-flow/core'
import type { CveNodeData } from './types'

defineProps<{ data: CveNodeData }>()
</script>

<template>
  <div class="br-node br-node--cve" role="img" :aria-label="`CVE ${data.cve}`">
    <Handle type="source" :position="Position.Right" />
    <div class="br-node__icon">
      <v-icon size="22" color="error">mdi-radar</v-icon>
    </div>
    <div class="br-node__body">
      <div class="br-node__title text-mono">{{ data.cve }}</div>
      <div class="br-node__meta">
        {{ data.inClusterCount }} în cluster
        <span class="text-medium-emphasis"> / {{ data.totalPackages }} în graf</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.br-node { width: 220px; height: 110px; }
.br-node--cve {
  border: 1px solid rgba(239, 83, 80, 0.45);
  background: linear-gradient(135deg, rgba(239, 83, 80, 0.08), rgba(239, 83, 80, 0.02));
}
</style>
