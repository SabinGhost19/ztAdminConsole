<script setup lang="ts">
const props = defineProps<{
  nodes: Array<Record<string, any>>
  status?: string
}>()

function shortHash(value?: string | null) {
  if (!value) return 'hash unavailable'
  return value.length > 18 ? `${value.slice(0, 10)}...${value.slice(-6)}` : value
}
</script>

<template>
  <div class="ledger-shell">
    <div class="d-flex align-center justify-space-between mb-3">
      <div class="text-subtitle-2 font-weight-medium">Build Ledger</div>
      <v-chip :color="status === 'verified' ? 'success' : (status === 'failed' ? 'error' : 'warning')" size="small" variant="tonal">
        {{ status || 'pending' }}
      </v-chip>
    </div>
    <div v-if="!props.nodes?.length" class="empty-state">No cryptographic chain exposed yet.</div>
    <div v-else class="ledger-track">
      <div v-for="node in props.nodes" :key="node.id" class="ledger-node" :class="node.verified ? 'verified' : 'warning'">
        <div class="position-pill">#{{ node.position }}</div>
        <div class="text-body-2 font-weight-medium">{{ node.label }}</div>
        <div class="text-caption text-secondary">Metadata {{ shortHash(node.metadataHash) }}</div>
        <div class="text-caption text-secondary">Voucher {{ shortHash(node.hmacResult || node.computed) }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ledger-shell {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 16px;
  padding: 16px;
  background: linear-gradient(135deg, rgba(var(--v-theme-primary), 0.03), rgba(var(--v-theme-surface), 1));
}
.ledger-track {
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
}
.ledger-node {
  position: relative;
  border-radius: 14px;
  padding: 14px;
  background: rgba(var(--v-theme-surface), 1);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
}
.ledger-node::after {
  content: '';
  position: absolute;
  top: 50%;
  right: -8px;
  width: 16px;
  height: 2px;
  background: rgba(var(--v-theme-on-surface), 0.14);
}
.ledger-node:last-child::after {
  display: none;
}
.ledger-node.verified {
  box-shadow: inset 0 0 0 1px rgba(var(--v-theme-success), 0.2);
}
.ledger-node.warning {
  box-shadow: inset 0 0 0 1px rgba(var(--v-theme-warning), 0.25);
}
.position-pill {
  display: inline-flex;
  font-size: 0.72rem;
  padding: 2px 8px;
  border-radius: 999px;
  margin-bottom: 10px;
  background: rgba(var(--v-theme-primary), 0.08);
}
.empty-state {
  color: rgba(var(--v-theme-on-surface), 0.64);
  font-size: 0.84rem;
}
</style>