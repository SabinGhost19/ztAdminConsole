<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  label: string
  value?: string | number | null
  items?: (string | number)[]
  tone?: 'default' | 'ok' | 'warn' | 'muted'
  hint?: string
}>(), {
  value: '',
  tone: 'default',
  hint: '',
})

const isList = computed(() => props.items !== undefined)

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
  <div class="describe-field" :class="{ 'df-field--list': isList }">
    <span class="df-label">
      {{ label }}
      <v-tooltip v-if="hint" location="top" max-width="320">
        <template #activator="{ props: tip }">
          <v-icon v-bind="tip" size="12" class="df-help">mdi-help-circle-outline</v-icon>
        </template>
        <span>{{ hint }}</span>
      </v-tooltip>
    </span>

    <template v-if="isList">
      <div v-if="(items || []).length" class="df-list">
        <span v-for="(it, i) in items" :key="i" class="df-list-item">{{ it }}</span>
      </div>
      <span v-else class="df-value-secondary">none</span>
    </template>
    <span v-else :class="valueClass">{{ display }}</span>
  </div>
</template>

<style scoped>
.describe-field { display: flex; flex-direction: column; gap: 2px; }
.df-field--list { grid-column: 1 / -1; }
.df-label {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.7rem;
  color: rgba(var(--v-theme-on-surface), 0.45);
  display: inline-flex;
  align-items: center;
}
.df-help {
  margin-left: 3px;
  color: rgba(var(--v-theme-on-surface), 0.35);
  cursor: help;
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
.df-list { display: flex; flex-direction: column; gap: 4px; margin-top: 2px; }
.df-list-item {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.76rem;
  color: rgba(var(--v-theme-on-surface), 0.85);
  padding: 3px 8px;
  border: 1px solid rgba(var(--v-theme-on-surface), 0.10);
  border-radius: 6px;
  background: rgba(var(--v-theme-on-surface), 0.03);
  width: fit-content;
  max-width: 100%;
  word-break: break-all;
}
</style>
