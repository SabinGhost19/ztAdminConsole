<script setup lang="ts">
withDefaults(defineProps<{
  title: string
  grid?: boolean
}>(), {
  grid: true,
})
</script>

<template>
  <div class="describe-section">
    <div class="describe-section-title">{{ title }}</div>
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
.describe-fields-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 8px;
}
</style>
