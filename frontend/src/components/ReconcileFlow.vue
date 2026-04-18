<script setup lang="ts">
const props = defineProps<{
  flow?: Record<string, any> | null
}>()

function stageColor(status?: string) {
  if (status === 'success') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'warning') return 'warning'
  if (status === 'running') return 'info'
  if (status === 'skipped') return 'secondary'
  return 'default'
}

function stageIcon(status?: string) {
  if (status === 'success') return 'mdi-check-bold'
  if (status === 'failed') return 'mdi-close-circle'
  if (status === 'warning') return 'mdi-alert-circle'
  if (status === 'running') return 'mdi-loading'
  if (status === 'skipped') return 'mdi-skip-next-circle'
  return 'mdi-circle-outline'
}
</script>

<template>
  <div class="flow-shell">
    <div class="d-flex align-center justify-space-between mb-3">
      <div class="text-subtitle-2 font-weight-medium">Reconcile Execution Flow</div>
      <v-chip size="small" variant="tonal" color="primary">
        {{ flow?.phase || 'Pending' }}
      </v-chip>
    </div>

    <div v-if="!flow?.stages?.length" class="text-caption text-secondary">
      Execution flow not available yet.
    </div>

    <div v-else class="flow-list">
      <div
        v-for="(stage, index) in flow.stages"
        :key="stage.id"
        class="flow-step"
        :class="{
          'is-running': stage.status === 'running',
          'is-failed': stage.status === 'failed',
          'is-success': stage.status === 'success',
          'is-warning': stage.status === 'warning'
        }"
      >
        <div class="flow-connector" v-if="Number(index) < flow.stages.length - 1"></div>
        <div class="d-flex align-start ga-3 position-relative">
          <div class="status-pill" :class="`tone-${stageColor(stage.status)}`">
            <v-icon size="16" :class="{ spin: stage.status === 'running' }">{{ stageIcon(stage.status) }}</v-icon>
          </div>
          <div class="flex-grow-1">
            <div class="d-flex align-center ga-2 flex-wrap mb-1">
              <div class="text-body-2 font-weight-medium">{{ stage.title }}</div>
              <v-chip size="x-small" variant="tonal" :color="stageColor(stage.status)">{{ stage.status }}</v-chip>
            </div>
            <div class="text-caption text-secondary">{{ stage.description }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.flow-shell {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 16px;
  padding: 16px;
  background: linear-gradient(145deg, rgba(var(--v-theme-warning), 0.05), rgba(var(--v-theme-surface), 1));
}

.flow-list {
  display: grid;
  gap: 14px;
}

.flow-step {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
  border-radius: 14px;
  padding: 14px;
  background: rgba(var(--v-theme-surface), 1);
  transition: transform 0.25s ease, box-shadow 0.25s ease;
  position: relative;
}

.flow-step.is-running {
  box-shadow: 0 0 0 1px rgba(var(--v-theme-info), 0.35), 0 8px 22px rgba(0, 0, 0, 0.08);
  transform: translateY(-1px);
}

.flow-step.is-success {
  box-shadow: inset 0 0 0 1px rgba(var(--v-theme-success), 0.3);
}

.flow-step.is-failed {
  box-shadow: inset 0 0 0 1px rgba(var(--v-theme-error), 0.35);
}

.flow-step.is-warning {
  box-shadow: inset 0 0 0 1px rgba(var(--v-theme-warning), 0.35);
}

.flow-connector {
  position: absolute;
  left: 37px;
  top: 50px;
  bottom: -17px;
  width: 2px;
  background: linear-gradient(to bottom, rgba(var(--v-theme-primary), 0.42), rgba(var(--v-theme-on-surface), 0.12));
}

.status-pill {
  width: 46px;
  height: 46px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 2px solid transparent;
}

.tone-success {
  background: rgba(var(--v-theme-success), 0.2);
  color: rgb(var(--v-theme-success));
  border-color: rgba(var(--v-theme-success), 0.6);
}

.tone-error {
  background: rgba(var(--v-theme-error), 0.2);
  color: rgb(var(--v-theme-error));
  border-color: rgba(var(--v-theme-error), 0.6);
}

.tone-warning {
  background: rgba(var(--v-theme-warning), 0.2);
  color: rgb(var(--v-theme-warning));
  border-color: rgba(var(--v-theme-warning), 0.6);
}

.tone-info {
  background: rgba(var(--v-theme-info), 0.2);
  color: rgb(var(--v-theme-info));
  border-color: rgba(var(--v-theme-info), 0.6);
}

.tone-secondary,
.tone-default {
  background: rgba(var(--v-theme-on-surface), 0.1);
  color: rgba(var(--v-theme-on-surface), 0.8);
  border-color: rgba(var(--v-theme-on-surface), 0.2);
}

.spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>
