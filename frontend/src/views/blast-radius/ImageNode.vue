<script setup lang="ts">
import { Handle, Position } from '@vue-flow/core'
import type { ImageNodeData } from './types'

const props = defineProps<{ data: ImageNodeData }>()

function shortDigest(d: string): string {
  if (!d.startsWith('sha256:')) return d
  return d.slice(0, 19) + '…'
}

const repoLabel = props.data.repo || props.data.image.image
</script>

<template>
  <div :class="['br-node', `br-node--${data.verdict}`]" :data-kind="data.kind">
    <div class="br-node__rail" />
    <div class="br-node__body">
      <div class="br-node__row">
        <span class="material-symbols-outlined br-node__icon">deployed_code_history</span>
        <span class="br-node__title br-node__title--mono" :title="data.image.image">
          {{ repoLabel }}
        </span>
      </div>
      <div class="br-node__meta">{{ shortDigest(data.digest) || 'no digest' }}</div>
    </div>
    <Handle type="target" :position="Position.Left" />
    <Handle type="source" :position="Position.Right" />
  </div>
</template>

<style scoped>
.br-node { width: 320px; height: 64px; }
</style>
