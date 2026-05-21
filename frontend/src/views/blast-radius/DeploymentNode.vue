<script setup lang="ts">
import { Handle, Position } from '@vue-flow/core'
import type { DeploymentNodeData } from './types'

defineProps<{ data: DeploymentNodeData }>()
</script>

<template>
  <div :class="['br-node', `br-node--${data.verdict}`]" :data-kind="data.kind">
    <div class="br-node__rail" />
    <div class="br-node__body">
      <div class="br-node__row">
        <span class="material-symbols-outlined br-node__icon">
          {{ data.verdict === 'exempted' ? 'shield' : 'warning' }}
        </span>
        <span class="br-node__title">
          {{ data.deployment.namespace }} / {{ data.deployment.name }}
        </span>
      </div>
      <div class="br-node__meta">
        {{ data.verdict === 'exempted' ? 'VEX exempt' : 'Action required' }}
        <template v-if="data.deployment.trustLevel">
          · trust={{ data.deployment.trustLevel }}
        </template>
      </div>
    </div>
    <Handle type="target" :position="Position.Left" />
  </div>
</template>

<style scoped>
.br-node { width: 260px; height: 64px; }
</style>
