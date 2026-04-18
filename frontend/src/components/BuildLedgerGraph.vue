<script setup lang="ts">
const props = defineProps<{
  nodes: Array<Record<string, any>>
  status?: string
}>()

function shortHash(value?: string | null) {
  if (!value) return 'hash unavailable'
  return value.length > 18 ? `${value.slice(0, 10)}...${value.slice(-6)}` : value
}

function nodeStatus(node: Record<string, any>) {
  if (props.status === 'failed') return 'failed'
  if (props.status === 'verified') return 'verified'
  if (node.verified) return 'verified'
  return 'pending'
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
    <div v-else class="ledger-tree">
      <div v-for="(node, index) in props.nodes" :key="node.id" class="ledger-step" :class="`state-${nodeStatus(node)}`">
        <div class="connector" v-if="index < props.nodes.length - 1"></div>
        <div class="node-dot" :class="`dot-${nodeStatus(node)}`">
          <v-icon size="14" :class="{ spin: nodeStatus(node) === 'pending' }">
            {{ nodeStatus(node) === 'verified' ? 'mdi-check' : (nodeStatus(node) === 'failed' ? 'mdi-close' : 'mdi-progress-clock') }}
          </v-icon>
        </div>
        <div class="ledger-content">
          <div class="d-flex align-center ga-2 mb-1 flex-wrap">
            <div class="text-body-2 font-weight-medium">#{{ node.position }} {{ node.label }}</div>
            <v-chip size="x-small" variant="tonal" :color="nodeStatus(node) === 'verified' ? 'success' : (nodeStatus(node) === 'failed' ? 'error' : 'warning')">
              {{ nodeStatus(node) }}
            </v-chip>
          </div>
          <div class="text-caption text-secondary">Metadata hash: {{ shortHash(node.metadataHash) }}</div>
          <div class="text-caption text-secondary">Voucher hash: {{ shortHash(node.hmacResult || node.computed) }}</div>
        </div>
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

.ledger-tree {
  display: grid;
  gap: 10px;
}

.ledger-step {
  position: relative;
  border-radius: 14px;
  padding: 12px;
  background: rgba(var(--v-theme-surface), 1);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
  display: flex;
  align-items: flex-start;
  gap: 10px;
}

.ledger-step.state-verified {
  box-shadow: inset 0 0 0 1px rgba(var(--v-theme-success), 0.2);
}

.ledger-step.state-pending {
  box-shadow: inset 0 0 0 1px rgba(var(--v-theme-warning), 0.25);
}

.ledger-step.state-failed {
  box-shadow: inset 0 0 0 1px rgba(var(--v-theme-error), 0.3);
}

.ledger-content {
  flex: 1;
}

.connector {
  position: absolute;
  left: 27px;
  top: 36px;
  width: 2px;
  height: 18px;
  background: rgba(var(--v-theme-on-surface), 0.18);
}

.node-dot {
  width: 28px;
  height: 28px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.dot-verified {
  background: rgba(var(--v-theme-success), 0.15);
  color: rgb(var(--v-theme-success));
}

.dot-pending {
  background: rgba(var(--v-theme-warning), 0.15);
  color: rgb(var(--v-theme-warning));
}

.dot-failed {
  background: rgba(var(--v-theme-error), 0.15);
  color: rgb(var(--v-theme-error));
}

.spin {
  animation: spin 1s linear infinite;
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

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>