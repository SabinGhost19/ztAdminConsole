<script setup lang="ts">
import { Handle, Position } from '@vue-flow/core'
import type { ImageNodeData } from './types'

defineProps<{ data: ImageNodeData }>()

const VERDICT_COLOR: Record<string, string> = {
  critical: 'error',
  exempted: 'success',
  latent: 'grey',
}

function shortenDigest(d: string): string {
  if (!d.startsWith('sha256:')) return d
  return 'sha256:' + d.slice(7, 19) + '…'
}
</script>

<template>
  <div :class="['br-node', `br-node--${data.verdict}`]">
    <Handle type="target" :position="Position.Left" />
    <Handle type="source" :position="Position.Right" />
    <div class="br-node__icon">
      <v-icon size="20" :color="VERDICT_COLOR[data.verdict]">mdi-docker</v-icon>
    </div>
    <div class="br-node__body">
      <div class="br-node__title text-mono" :title="data.image.image">
        {{ data.repo || data.image.image }}
      </div>
      <div class="br-node__meta text-mono text-caption text-medium-emphasis">
        {{ shortenDigest(data.digest) }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.br-node { width: 320px; height: 90px; }
.br-node__title { font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; }
</style>
