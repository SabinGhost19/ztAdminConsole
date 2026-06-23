<script setup lang="ts">
import { computed } from 'vue'
import VueApexCharts from 'vue3-apexcharts'
import type { ApexOptions } from 'apexcharts'
import { useChartTheme } from '../../composables/useChartTheme'

interface TrustScore {
  value: number
  verified: number
  total: number
  distribution: Record<string, number>
}

const props = withDefaults(defineProps<{
  trustScore?: TrustScore
  loading?: boolean
}>(), {
  trustScore: () => ({ value: 0, verified: 0, total: 0, distribution: {} }),
  loading: false,
})

const { foreColor, isDark, onAccent, statusColor } = useChartTheme()

const entries = computed(() =>
  Object.entries(props.trustScore.distribution || {}).filter(([, v]) => typeof v === 'number' && v > 0),
)
const hasData = computed(() => entries.value.length > 0)
const labels = computed(() => entries.value.map(([k]) => k))
const series = computed(() => entries.value.map(([, v]) => v))
const scoreLabel = computed(() => `${props.trustScore.value ?? 0}%`)

const options = computed<ApexOptions>(() => ({
  chart: { type: 'donut', fontFamily: 'Roboto, sans-serif', foreColor: foreColor.value, background: 'transparent' },
  labels: labels.value,
  colors: labels.value.map((k) => statusColor(k)),
  stroke: { width: 2, colors: [onAccent.value] },
  dataLabels: { enabled: false },
  legend: { show: false },
  tooltip: { theme: isDark.value ? 'dark' : 'light', y: { formatter: (val: number) => `${val}` } },
  plotOptions: {
    pie: {
      donut: {
        size: '74%',
        labels: {
          show: true,
          name: { show: true, fontSize: '13px', color: foreColor.value },
          value: { show: true, fontSize: '26px', fontWeight: '700', color: foreColor.value, formatter: (val: string) => `${val}` },
          total: { show: true, showAlways: true, label: 'Trust score', fontSize: '13px', color: foreColor.value, formatter: () => scoreLabel.value },
        },
      },
    },
  },
}))
</script>

<template>
  <v-card class="gc-border h-100" flat>
    <v-card-title class="d-flex align-center text-primary text-subtitle-1 font-weight-medium">
      <v-icon size="18" class="mr-2">mdi-shield-check-outline</v-icon>Cluster Trust Posture
    </v-card-title>
    <v-card-text>
      <v-skeleton-loader v-if="loading" type="image" height="220" class="bg-transparent" />
      <template v-else-if="hasData">
        <VueApexCharts type="donut" height="220" :options="options" :series="series" />
        <div class="mt-3">
          <div v-for="[key, val] in entries" :key="key" class="d-flex align-center justify-space-between py-1">
            <span class="d-flex align-center text-body-2">
              <span class="legend-dot mr-2" :style="{ backgroundColor: statusColor(key) }"></span>{{ key }}
            </span>
            <span class="text-body-2 font-weight-medium">{{ val }}</span>
          </div>
        </div>
      </template>
      <div v-else class="d-flex flex-column align-center justify-center text-secondary py-10">
        <v-icon size="32" class="mb-2">mdi-shield-off-outline</v-icon>
        <span class="text-caption">No Zero-Trust applications yet.</span>
      </div>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.gc-border { border: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important; }
.legend-dot { width: 10px; height: 10px; border-radius: 3px; display: inline-block; }
</style>
