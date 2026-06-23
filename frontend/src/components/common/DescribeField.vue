<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  label: string
  value?: string | number | null
  tone?: 'default' | 'ok' | 'warn' | 'muted'
}>(), {
  value: '',
  tone: 'default',
})

const display = computed(() => {
  const v = props.value
  if (v === null || v === undefined || v === '') return '—'
  return String(v)
})

const valueClass = computed(() => {
  switch (props.tone) {
    case 'ok': return 'df-value-ok'
    case 'warn': return 'df-value-warn'
    case 'muted': return 'df-value-secondary'
    default: return 'df-value'
  }
})
</script>

<template>
  <div class="describe-field">
    <span class="df-label">{{ label }}</span>
    <span :class="valueClass">{{ display }}</span>
  </div>
</template>

<style scoped>
.describe-field { display: flex; flex-direction: column; gap: 2px; }
.df-label {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.7rem;
  color: rgba(var(--v-theme-on-surface), 0.45);
}
.df-value, .df-value-ok, .df-value-warn, .df-value-secondary {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.8rem;
  word-break: break-all;
}
.df-value { color: rgba(var(--v-theme-on-surface), 0.88); }
.df-value-ok { color: rgb(var(--v-theme-success)); }
.df-value-warn { color: rgb(var(--v-theme-warning)); }
.df-value-secondary { color: rgba(var(--v-theme-on-surface), 0.45); }
</style>
