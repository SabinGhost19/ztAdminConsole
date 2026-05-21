<script setup lang="ts">
import { Handle, Position } from '@vue-flow/core'
import type { PackageNodeData } from './types'

defineProps<{ data: PackageNodeData }>()

const VERDICT_COLOR: Record<string, string> = {
  critical: 'error',
  exempted: 'success',
  latent: 'grey',
}
</script>

<template>
  <div :class="['br-node', `br-node--${data.verdict}`]">
    <Handle type="target" :position="Position.Left" />
    <Handle type="source" :position="Position.Right" />
    <div class="br-node__icon">
      <v-icon size="20" :color="VERDICT_COLOR[data.verdict]">mdi-package-variant</v-icon>
    </div>
    <div class="br-node__body">
      <div class="br-node__title">
        {{ data.pkg.name }}
        <span class="text-medium-emphasis text-caption">v{{ data.pkg.version || '?' }}</span>
      </div>
      <div class="br-node__meta">
        <span v-if="data.pkg.type" class="text-caption text-medium-emphasis">
          {{ data.pkg.type }}
        </span>
        <span>· {{ data.imageCount }} img · {{ data.deploymentCount }} dep</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.br-node { width: 220px; height: 90px; }
</style>
