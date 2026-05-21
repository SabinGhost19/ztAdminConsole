<script setup lang="ts">
import { Handle, Position } from '@vue-flow/core'
import type { DeploymentNodeData } from './types'

defineProps<{ data: DeploymentNodeData }>()
</script>

<template>
  <div :class="['br-node', `br-node--${data.verdict}`]">
    <Handle type="target" :position="Position.Left" />
    <div class="br-node__icon">
      <v-icon
        size="22"
        :color="data.verdict === 'exempted' ? 'success' : 'error'"
      >
        {{ data.verdict === 'exempted' ? 'mdi-shield-check' : 'mdi-alert-octagon' }}
      </v-icon>
    </div>
    <div class="br-node__body">
      <div class="br-node__title">
        {{ data.deployment.namespace }} / {{ data.deployment.name }}
      </div>
      <div class="br-node__meta d-flex flex-wrap ga-1">
        <v-chip
          v-if="data.deployment.trustLevel"
          size="x-small"
          variant="outlined"
          density="compact"
        >
          trust={{ data.deployment.trustLevel }}
        </v-chip>
        <v-chip
          size="x-small"
          :color="data.verdict === 'exempted' ? 'success' : 'error'"
          variant="tonal"
          density="compact"
        >
          {{ data.verdict === 'exempted' ? 'VEX exempt' : 'Action required' }}
        </v-chip>
      </div>
    </div>
  </div>
</template>

<style scoped>
.br-node { width: 240px; height: 90px; }
</style>
