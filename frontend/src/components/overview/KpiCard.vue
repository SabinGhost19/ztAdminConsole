<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  label: string
  value: string | number
  icon?: string
  accent?: string
  hint?: string
  hintColor?: string
  to?: string
  loading?: boolean
}>(), {
  icon: 'mdi-chart-box-outline',
  accent: 'primary',
  hint: '',
  hintColor: 'secondary',
  to: '',
  loading: false,
})

const isClickable = computed(() => !!props.to)
</script>

<template>
  <v-card
    class="gc-border h-100 kpi-card"
    :class="{ 'kpi-card--link': isClickable }"
    flat
    :to="to || undefined"
    :ripple="false"
  >
    <v-card-text class="kpi-body">
      <div class="d-flex align-center justify-space-between">
        <span class="text-caption text-secondary text-uppercase kpi-label">{{ label }}</span>
        <v-icon :color="accent" size="20">{{ icon }}</v-icon>
      </div>

      <v-skeleton-loader v-if="loading" type="heading" class="bg-transparent pa-0 mt-2" />
      <template v-else>
        <div class="text-h4 font-weight-bold mt-1">{{ value }}</div>
        <div v-if="hint" class="text-body-2 mt-1" :class="`text-${hintColor}`">{{ hint }}</div>
      </template>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.gc-border { border: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important; }
.kpi-body { display: flex; flex-direction: column; }
.kpi-card { transition: border-color 0.15s ease; }
.kpi-card--link { cursor: pointer; }
.kpi-card--link:hover { border-color: rgba(var(--v-theme-primary), 0.55) !important; }
.kpi-label { letter-spacing: 0.06em; }
</style>
