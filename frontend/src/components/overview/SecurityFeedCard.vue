<script setup lang="ts">
import { computed } from 'vue'
import { formatRelative } from '../../composables/useRelativeTime'

interface FeedEvent {
  kind: string
  resource: string
  namespace?: string
  severity: string
  message: string
  timestamp?: string | null
}

const props = withDefaults(defineProps<{
  events?: FeedEvent[]
  loading?: boolean
}>(), {
  events: () => [],
  loading: false,
})

const highCount = computed(() => props.events.filter((e) => e.severity === 'high').length)
const mediumCount = computed(() => props.events.filter((e) => e.severity === 'medium').length)

const kindLabels: Record<string, string> = {
  'zta-violation': 'Violation',
  'zta-error': 'ZTA Error',
  'zts-error': 'Secret Error',
  'jit-state': 'JIT',
}
</script>

<template>
  <v-card class="gc-border h-100" flat>
    <v-card-title class="d-flex align-center text-primary text-subtitle-1 font-weight-medium">
      <v-icon size="18" class="mr-2">mdi-bell-alert-outline</v-icon>Security Event Feed
      <v-spacer />
      <div class="d-flex ga-2">
        <v-chip size="small" variant="tonal" color="error">{{ highCount }} high</v-chip>
        <v-chip size="small" variant="tonal" color="warning">{{ mediumCount }} medium</v-chip>
      </div>
    </v-card-title>
    <v-card-text>
      <v-skeleton-loader v-if="loading" type="list-item-two-line@4" class="bg-transparent pa-0" />
      <div v-else-if="events.length" class="feed-scroll">
        <v-timeline density="compact" align="start" side="end">
          <v-timeline-item
            v-for="(event, index) in events"
            :key="`${event.kind}-${index}`"
            :dot-color="event.severity === 'high' ? 'error' : 'warning'"
            size="x-small"
          >
            <div class="d-flex align-center justify-space-between">
              <span class="text-body-2 font-weight-medium">
                {{ event.resource }}<span v-if="event.namespace" class="text-secondary"> · {{ event.namespace }}</span>
              </span>
              <v-chip size="x-small" variant="tonal" :color="event.severity === 'high' ? 'error' : 'warning'">
                {{ kindLabels[event.kind] || event.kind }}
              </v-chip>
            </div>
            <div class="text-caption text-secondary mt-1">{{ event.message }}</div>
            <div class="text-caption text-disabled mt-1">{{ formatRelative(event.timestamp) }}</div>
          </v-timeline-item>
        </v-timeline>
      </div>
      <div v-else class="d-flex flex-column align-center justify-center py-10">
        <v-icon size="32" class="mb-2 text-success">mdi-shield-check-outline</v-icon>
        <span class="text-caption text-secondary">No active findings. Cluster is clean.</span>
      </div>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.gc-border { border: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important; }
.feed-scroll { max-height: 360px; overflow-y: auto; }
</style>
