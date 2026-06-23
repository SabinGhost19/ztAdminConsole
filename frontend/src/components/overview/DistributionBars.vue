<script setup lang="ts">
import { computed } from 'vue'
import VueApexCharts from 'vue3-apexcharts'
import type { ApexOptions } from 'apexcharts'
import { useChartTheme } from '../../composables/useChartTheme'

const props = withDefaults(defineProps<{
  title: string
  icon?: string
  data?: Record<string, number>
  loading?: boolean
}>(), {
  icon: 'mdi-chart-bar',
  data: () => ({}),
  loading: false,
})

const { foreColor, gridColor, isDark, onAccent, statusColor } = useChartTheme()

const entries = computed(() =>
  Object.entries(props.data || {}).filter(([, v]) => typeof v === 'number'),
)
const hasData = computed(() => entries.value.length > 0)
const total = computed(() => entries.value.reduce((acc, [, v]) => acc + v, 0))

const series = computed(() => [{ name: 'Count', data: entries.value.map(([, v]) => v) }])

const options = computed<ApexOptions>(() => ({
  chart: { type: 'bar', fontFamily: 'Roboto, sans-serif', foreColor: foreColor.value, toolbar: { show: false }, background: 'transparent', animations: { enabled: true, speed: 350 } },
  plotOptions: { bar: { horizontal: true, borderRadius: 4, distributed: true, barHeight: '60%' } },
  colors: entries.value.map(([k]) => statusColor(k)),
  dataLabels: { enabled: true, style: { fontSize: '12px', fontWeight: '600', colors: [onAccent.value] } },
  xaxis: { categories: entries.value.map(([k]) => k), labels: { style: { fontSize: '12px' } } },
  yaxis: { labels: { style: { fontSize: '12px' } } },
  grid: { borderColor: gridColor.value, strokeDashArray: 4, yaxis: { lines: { show: false } } },
  legend: { show: false },
  tooltip: { theme: isDark.value ? 'dark' : 'light', y: { formatter: (val: number) => `${val}` } },
}))

const chartHeight = computed(() => Math.max(150, entries.value.length * 44 + 20))
</script>

<template>
  <v-card class="gc-border h-100" flat>
    <v-card-title class="d-flex align-center text-primary text-subtitle-1 font-weight-medium">
      <v-icon size="18" class="mr-2">{{ icon }}</v-icon>{{ title }}
      <v-spacer />
      <span class="text-caption text-secondary">{{ total }} total</span>
    </v-card-title>
    <v-card-text>
      <v-skeleton-loader v-if="loading" type="image" height="170" class="bg-transparent" />
      <VueApexCharts v-else-if="hasData" type="bar" :height="chartHeight" :options="options" :series="series" />
      <div v-else class="d-flex flex-column align-center justify-center text-secondary py-10">
        <v-icon size="32" class="mb-2">mdi-chart-bar-stacked</v-icon>
        <span class="text-caption">No data in the current window.</span>
      </div>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.gc-border { border: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important; }
</style>
