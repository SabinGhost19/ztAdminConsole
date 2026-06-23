<script setup lang="ts">
withDefaults(defineProps<{
  title: string
  grid?: boolean
  hint?: string
}>(), {
  grid: true,
  hint: '',
})
</script>

<template>
  <div class="describe-section">
    <div class="describe-section-title">
      {{ title }}
      <v-tooltip v-if="hint" location="top" max-width="340">
        <template #activator="{ props: tip }">
          <v-icon v-bind="tip" size="12" class="section-help">mdi-help-circle-outline</v-icon>
        </template>
        <span>{{ hint }}</span>
      </v-tooltip>
    </div>
    <div v-if="grid" class="describe-fields-grid">
      <slot />
    </div>
    <slot v-else />
  </div>
</template>

<style scoped>
.describe-section {
  padding: 12px 0;
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.06);
}
.describe-section:last-child { border-bottom: none; }
.describe-section-title {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: rgba(var(--v-theme-on-surface), 0.38);
  margin-bottom: 8px;
}
.section-help {
  margin-left: 4px;
  color: rgba(var(--v-theme-on-surface), 0.3);
  cursor: help;
  vertical-align: text-top;
}
.describe-fields-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 8px;
}
</style>
