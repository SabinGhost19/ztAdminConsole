<script setup lang="ts">
interface PodHealth {
  podName?: string
  namespace?: string
  phase?: string
  readyContainers?: number
  totalContainers?: number
  restartCount?: number
  healthy?: boolean
}

interface OperatorHealth {
  name: string
  status?: string
  healthy?: boolean
  pods?: PodHealth[]
}

withDefaults(defineProps<{
  operators?: OperatorHealth[]
  loading?: boolean
}>(), {
  operators: () => [],
  loading: false,
})

function statusColor(op: OperatorHealth): string {
  if (op.healthy) return 'success'
  return op.status === 'unknown' ? 'secondary' : 'warning'
}
function statusIcon(op: OperatorHealth): string {
  if (op.healthy) return 'mdi-check-circle'
  return op.status === 'unknown' ? 'mdi-help-circle' : 'mdi-alert-circle'
}
function podSummary(op: OperatorHealth): string {
  const pods = op.pods || []
  if (!pods.length) return 'No pods discovered'
  const phases = Array.from(new Set(pods.map((p) => p.phase || 'Unknown')))
  const restarts = pods.reduce((acc, p) => acc + (p.restartCount || 0), 0)
  return restarts > 0 ? `${phases.join(', ')} · ${restarts} restarts` : phases.join(', ')
}
</script>

<template>
  <v-card class="gc-border h-100" flat>
    <v-card-title class="d-flex align-center text-primary text-subtitle-1 font-weight-medium">
      <v-icon size="18" class="mr-2">mdi-heart-pulse</v-icon>Operator Health
    </v-card-title>
    <v-card-text>
      <v-skeleton-loader v-if="loading" type="list-item-two-line@3" class="bg-transparent pa-0" />
      <v-list v-else-if="operators.length" class="bg-transparent pa-0" lines="two">
        <v-list-item v-for="op in operators" :key="op.name" class="px-0">
          <template #prepend>
            <v-icon :color="statusColor(op)" size="20" class="mr-3">{{ statusIcon(op) }}</v-icon>
          </template>
          <v-list-item-title class="text-body-2 font-weight-medium">{{ op.name }}</v-list-item-title>
          <v-list-item-subtitle class="text-caption text-secondary">{{ podSummary(op) }}</v-list-item-subtitle>
        </v-list-item>
      </v-list>
      <div v-else class="d-flex flex-column align-center justify-center text-secondary py-10">
        <v-icon size="32" class="mb-2">mdi-server-off</v-icon>
        <span class="text-caption">No operator telemetry available.</span>
      </div>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.gc-border { border: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important; }
</style>
