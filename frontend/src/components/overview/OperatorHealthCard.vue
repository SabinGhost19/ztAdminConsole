<script setup lang="ts">
import { computed } from 'vue'

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

const props = withDefaults(defineProps<{
  operators?: OperatorHealth[]
  loading?: boolean
}>(), {
  operators: () => [],
  loading: false,
})

const healthyCount = computed(() => props.operators.filter((o) => o.healthy).length)
const allHealthy = computed(() => props.operators.length > 0 && healthyCount.value === props.operators.length)

function avatarColor(op: OperatorHealth): string {
  if (op.healthy) return 'success'
  return op.status === 'unknown' ? 'secondary' : 'warning'
}
function avatarIcon(op: OperatorHealth): string {
  if (op.healthy) return 'mdi-check-circle-outline'
  return op.status === 'unknown' ? 'mdi-help-circle-outline' : 'mdi-alert-outline'
}
</script>

<template>
  <v-card class="gc-border h-100" flat>
    <v-card-title class="d-flex align-center text-primary text-subtitle-1 font-weight-medium">
      <v-icon size="18" class="mr-2">mdi-heart-pulse</v-icon>Operator Health
      <v-spacer />
      <v-chip size="small" variant="tonal" :color="allHealthy ? 'success' : 'warning'">
        {{ healthyCount }}/{{ operators.length }} healthy
      </v-chip>
    </v-card-title>
    <v-card-text>
      <v-skeleton-loader v-if="loading" type="list-item-two-line@3" class="bg-transparent pa-0" />
      <v-list v-else-if="operators.length" class="bg-transparent pa-0" lines="two">
        <v-list-item v-for="op in operators" :key="op.name" class="px-0">
          <template #prepend>
            <v-avatar :color="avatarColor(op)" size="32" class="mr-3">
              <v-icon size="18">{{ avatarIcon(op) }}</v-icon>
            </v-avatar>
          </template>
          <v-list-item-title class="text-body-2 font-weight-medium">{{ op.name }}</v-list-item-title>
          <v-list-item-subtitle>
            <template v-if="op.pods && op.pods.length">
              <span v-for="(pod, i) in op.pods" :key="i" class="d-inline-flex align-center mr-3">
                <v-icon size="10" class="mr-1" :color="pod.healthy ? 'success' : 'warning'">mdi-circle</v-icon>
                <span class="text-caption">{{ pod.readyContainers ?? 0 }}/{{ pod.totalContainers ?? 0 }} ready</span>
                <span v-if="(pod.restartCount ?? 0) > 0" class="text-caption text-warning ml-1">· {{ pod.restartCount }} restarts</span>
              </span>
            </template>
            <span v-else class="text-caption text-secondary">No pods discovered</span>
          </v-list-item-subtitle>
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
