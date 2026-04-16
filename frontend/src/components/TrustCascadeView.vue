<script setup lang="ts">
const props = defineProps<{
  cascade?: Record<string, any> | null
}>()

const palette = {
  verified: 'success',
  blocked: 'error',
  warning: 'warning',
}

function stageColor(status?: string) {
  return palette[(status || 'warning') as keyof typeof palette] || 'warning'
}
</script>

<template>
  <div class="cascade-shell">
    <div class="text-subtitle-2 font-weight-medium mb-3">Trust Cascade</div>
    <div v-if="!props.cascade?.stages?.length" class="text-caption text-secondary">Cascade data not available.</div>
    <div v-else class="cascade-row">
      <div v-for="stage in props.cascade.stages" :key="stage.id" class="cascade-stage">
        <v-chip :color="stageColor(stage.status)" size="small" variant="flat" class="mb-2">{{ stage.status }}</v-chip>
        <div class="text-body-2 font-weight-medium">{{ stage.label }}</div>
        <div class="text-caption text-secondary">{{ stage.detail }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.cascade-shell {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 16px;
  padding: 16px;
  background: linear-gradient(180deg, rgba(var(--v-theme-warning), 0.05), rgba(var(--v-theme-surface), 1));
}
.cascade-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
}
.cascade-stage {
  position: relative;
  padding: 14px;
  border-radius: 14px;
  background: rgba(var(--v-theme-surface), 1);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
}
.cascade-stage::after {
  content: '→';
  position: absolute;
  right: -12px;
  top: calc(50% - 10px);
  color: rgba(var(--v-theme-on-surface), 0.35);
}
.cascade-stage:last-child::after {
  display: none;
}
</style>