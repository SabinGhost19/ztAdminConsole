<script setup lang="ts">
import { computed, ref } from 'vue'
import type { KopfEvent } from '../composables/useIntegrityStream'

const props = defineProps<{
  events: KopfEvent[]
  connected?: boolean
}>()

const activeFilters = ref<string[]>([])

const REASON_BUCKETS: { label: string; match: (r: string) => boolean }[] = [
  { label: 'reconcile-*', match: (r) => r.startsWith('reconcile-') },
  { label: 'talon-*', match: (r) => r.startsWith('talon-') },
  { label: 'guac-*', match: (r) => r.startsWith('guac-') },
  { label: 'vex-*', match: (r) => r.startsWith('vex-') },
  { label: 'cosign / trivy / sbom', match: (r) => /^(cosign|trivy|sbom)/i.test(r) },
  { label: 'runtime-drift', match: (r) => r.includes('drift') },
  { label: 'provenance', match: (r) => r.includes('provenance') },
  { label: 'attestation-*', match: (r) => r.startsWith('attestation-') },
]

function toggleFilter(label: string) {
  const i = activeFilters.value.indexOf(label)
  if (i >= 0) activeFilters.value.splice(i, 1)
  else activeFilters.value.push(label)
}

const filtered = computed(() => {
  const evs = [...(props.events || [])]
  // Newest first.
  evs.sort((a, b) => (b.lastTimestamp || b.firstTimestamp || '').localeCompare(a.lastTimestamp || a.firstTimestamp || ''))
  if (!activeFilters.value.length) return evs
  const matchers = REASON_BUCKETS.filter((b) => activeFilters.value.includes(b.label))
  return evs.filter((e) => matchers.some((m) => m.match(e.reason || '')))
})

function eventColor(evt: KopfEvent): string {
  if (evt.type === 'Warning') return 'error'
  if ((evt.reason || '').includes('failed')) return 'error'
  if ((evt.reason || '').includes('skipped')) return 'grey'
  if ((evt.reason || '').includes('success') || (evt.reason || '').includes('completed')) return 'success'
  return 'info'
}

function formatTime(ts: string): string {
  if (!ts) return ''
  try { return new Date(ts).toLocaleTimeString() } catch { return ts }
}
</script>

<template>
  <v-card flat border>
    <v-card-title class="d-flex align-center text-body-1">
      <v-icon size="20" class="mr-2">mdi-timeline-clock-outline</v-icon>
      Operator events
      <v-spacer />
      <v-chip
        :color="connected ? 'success' : 'grey'"
        size="x-small"
        variant="flat"
        prepend-icon="mdi-circle"
      >
        {{ connected ? 'live' : 'idle' }}
      </v-chip>
    </v-card-title>
    <v-card-text class="py-2">
      <div class="d-flex flex-wrap ga-1 mb-3">
        <v-chip
          v-for="bucket in REASON_BUCKETS"
          :key="bucket.label"
          size="x-small"
          :variant="activeFilters.includes(bucket.label) ? 'flat' : 'outlined'"
          :color="activeFilters.includes(bucket.label) ? 'primary' : undefined"
          @click="toggleFilter(bucket.label)"
        >
          {{ bucket.label }}
        </v-chip>
      </div>
      <div v-if="!filtered.length" class="text-caption text-medium-emphasis text-center py-4">
        Niciun eveniment kopf înregistrat încă.
      </div>
      <v-timeline v-else density="compact" side="end" align="start" class="events-timeline">
        <v-timeline-item
          v-for="evt in filtered"
          :key="evt.uid || `${evt.reason}-${evt.lastTimestamp}`"
          :dot-color="eventColor(evt)"
          size="x-small"
        >
          <div class="d-flex align-center ga-2">
            <v-chip size="x-small" variant="tonal" :color="eventColor(evt)">{{ evt.reason }}</v-chip>
            <span class="text-caption text-medium-emphasis">{{ formatTime(evt.lastTimestamp || evt.firstTimestamp) }}</span>
            <v-chip v-if="evt.count > 1" size="x-small" variant="outlined">×{{ evt.count }}</v-chip>
          </div>
          <div class="text-body-2 mt-1">{{ evt.message }}</div>
        </v-timeline-item>
      </v-timeline>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.events-timeline {
  max-height: 420px;
  overflow-y: auto;
}
</style>
