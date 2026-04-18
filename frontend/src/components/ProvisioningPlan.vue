<script setup lang="ts">
const props = defineProps<{
  plan?: Array<Record<string, any>>
}>()

function planColor(enabled?: boolean) {
  return enabled ? 'success' : 'secondary'
}

function planIcon(entry?: Record<string, any>) {
  if (!entry?.enabled) return 'mdi-minus-circle-outline'
  if (String(entry.kind || '').includes('Istio')) return 'mdi-transit-connection-variant'
  if (String(entry.id || '').includes('falco') || String(entry.id || '').includes('talon')) return 'mdi-radar'
  if (String(entry.kind || '').includes('NetworkPolicy')) return 'mdi-router-network'
  if (String(entry.kind || '').includes('Service')) return 'mdi-connection'
  if (String(entry.kind || '').includes('Deployment')) return 'mdi-cube-outline'
  return 'mdi-shape-outline'
}
</script>

<template>
  <div class="plan-shell">
    <div class="d-flex align-center justify-space-between mb-3">
      <div class="text-subtitle-2 font-weight-medium">Provisioning Plan (from ZTA Manifest)</div>
      <v-chip size="small" variant="tonal" color="primary">
        {{ (plan || []).filter((entry) => entry.enabled).length }} active
      </v-chip>
    </div>

    <div v-if="!plan?.length" class="text-caption text-secondary">
      No provisioning plan available.
    </div>

    <div v-else class="plan-grid">
      <div v-for="entry in plan" :key="entry.id" class="plan-item" :class="{ disabled: !entry.enabled }">
        <div class="d-flex align-start ga-3">
          <v-avatar :color="planColor(entry.enabled)" size="28" variant="tonal">
            <v-icon size="15">{{ planIcon(entry) }}</v-icon>
          </v-avatar>
          <div class="flex-grow-1">
            <div class="d-flex align-center ga-2 flex-wrap mb-1">
              <div class="text-body-2 font-weight-medium">{{ entry.title }}</div>
              <v-chip :color="planColor(entry.enabled)" size="x-small" variant="tonal">
                {{ entry.enabled ? 'will create' : 'skipped' }}
              </v-chip>
            </div>
            <div class="text-caption text-secondary">{{ entry.kind }}</div>
            <div class="text-caption mt-1">{{ entry.reason }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.plan-shell {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 16px;
  padding: 16px;
  background: linear-gradient(145deg, rgba(var(--v-theme-primary), 0.04), rgba(var(--v-theme-surface), 1));
}

.plan-grid {
  display: grid;
  gap: 10px;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
}

.plan-item {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
  border-radius: 12px;
  background: rgba(var(--v-theme-surface), 1);
  padding: 12px;
}

.plan-item.disabled {
  opacity: 0.78;
}
</style>
