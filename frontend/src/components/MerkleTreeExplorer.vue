<script setup lang="ts">
defineProps<{
  levels: Array<Array<Record<string, any>>>
  summary?: Record<string, any>
}>()

function shortHash(value?: string | null) {
  if (!value) return 'unknown'
  return value.length > 18 ? `${value.slice(0, 8)}...${value.slice(-6)}` : value
}
</script>

<template>
  <div class="tree-shell">
    <div class="d-flex align-center justify-space-between mb-3">
      <div class="text-subtitle-2 font-weight-medium">Merkle Tree Explorer</div>
      <v-chip size="small" variant="tonal" color="primary">{{ summary?.leafCount || 0 }} leaves</v-chip>
    </div>
    <div v-if="!levels?.length" class="text-caption text-secondary">Merkle data not available yet.</div>
    <div v-else class="tree-grid">
      <div v-for="(level, index) in levels" :key="index" class="tree-level">
        <div class="text-caption text-secondary mb-2">Level {{ index + 1 }}</div>
        <div class="tree-row">
          <div v-for="node in level" :key="`${index}-${node.label}-${node.hash}`" class="tree-node">
            <div class="text-caption font-weight-medium">{{ node.label }}</div>
            <div class="text-caption text-secondary">{{ shortHash(node.hash) }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.tree-shell {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 16px;
  padding: 16px;
  background: rgba(var(--v-theme-surface), 1);
}
.tree-grid {
  display: grid;
  gap: 12px;
}
.tree-level {
  padding: 10px;
  border-radius: 12px;
  background: rgba(var(--v-theme-on-surface), 0.03);
}
.tree-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.tree-node {
  min-width: 120px;
  padding: 10px 12px;
  border-radius: 12px;
  background: rgba(var(--v-theme-surface), 1);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
}
</style>