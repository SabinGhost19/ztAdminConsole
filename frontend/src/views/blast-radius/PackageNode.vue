<script setup lang="ts">
import { Handle, Position } from '@vue-flow/core'
import type { PackageNodeData } from './types'

defineProps<{ data: PackageNodeData }>()
</script>

<template>
  <div :class="['br-node', `br-node--${data.verdict}`]" :data-kind="data.kind">
    <div class="br-node__rail" />
    <div class="br-node__body">
      <div class="br-node__row">
        <span class="material-symbols-outlined br-node__icon">deployed_code</span>
        <span class="br-node__title">{{ data.pkg.name }}</span>
        <span class="br-node__sub">v{{ data.pkg.version || '?' }}</span>
      </div>
      <div class="br-node__meta">
        <template v-if="data.pkg.type">{{ data.pkg.type }} · </template>
        {{ data.imageCount }} img · {{ data.deploymentCount }} dep
      </div>
    </div>
    <Handle type="target" :position="Position.Left" />
    <Handle type="source" :position="Position.Right" />
  </div>
</template>

<style scoped>
.br-node { width: 240px; height: 64px; }
</style>
