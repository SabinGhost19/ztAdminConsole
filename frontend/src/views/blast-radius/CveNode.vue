<script setup lang="ts">
import { Handle, Position } from '@vue-flow/core'
import type { CveNodeData } from './types'

defineProps<{ data: CveNodeData }>()
</script>

<template>
  <div class="br-node br-node--critical" :data-kind="data.kind">
    <div class="br-node__rail" />
    <div class="br-node__body">
      <div class="br-node__row">
        <span class="material-symbols-outlined br-node__icon">target</span>
        <span class="br-node__title br-node__title--mono">{{ data.cve }}</span>
      </div>
      <div class="br-node__meta">
        {{ data.inClusterCount }} in cluster · {{ data.totalPackages }} in graph
      </div>
    </div>
    <Handle type="source" :position="Position.Right" />
  </div>
</template>

<style scoped>
.br-node { width: 240px; height: 64px; }
</style>
