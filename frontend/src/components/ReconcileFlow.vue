<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'

const props = defineProps<{
  flow?: Record<string, any> | null
  retrying?: boolean
}>()

const emit = defineEmits<{
  (e: 'retry'): void
}>()

function toneColor(status?: string) {
  if (status === 'success') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'warning') return 'warning'
  if (status === 'running') return 'info'
  if (status === 'skipped') return 'secondary'
  return 'default'
}

function toneIcon(status?: string) {
  if (status === 'success') return 'mdi-check-bold'
  if (status === 'failed') return 'mdi-close-circle'
  if (status === 'warning') return 'mdi-alert-circle'
  if (status === 'running') return 'mdi-loading'
  if (status === 'skipped') return 'mdi-skip-next-circle'
  return 'mdi-circle-outline'
}

// Show the retry button only when reconciliation reached a stable failure
// state — the user has likely just fixed the cause (e.g. created the SCA)
// and needs a way to nudge the operator without deleting + recreating.
const showRetry = computed(() => {
  const phase = String(props.flow?.phase || '')
  return phase === 'Failed_SupplyChain' || phase === 'Degraded'
})

// Pipeline selection — clicking a node opens its detail panel below. By
// default we auto-focus the most actionable step: a failed stage first,
// then a running one, then the very first stage. This way the user sees
// "why" a deploy is stuck without having to click around.
const selectedStageId = ref<string | null>(null)
const detailPanelRef = ref<HTMLElement | null>(null)
const stageNodeRefs = ref<Record<string, HTMLElement | null>>({})

watch(
  () => props.flow?.stages,
  (stages) => {
    if (!stages || !stages.length) {
      selectedStageId.value = null
      return
    }
    const stillExists = selectedStageId.value && stages.some((s: any) => s.id === selectedStageId.value)
    if (stillExists) return
    const failed = stages.find((s: any) => s.status === 'failed')
    const running = stages.find((s: any) => s.status === 'running')
    selectedStageId.value = failed?.id || running?.id || stages[0]?.id || null
  },
  { immediate: true, deep: true },
)

const selectedStage = computed(() => {
  const stages = props.flow?.stages || []
  return stages.find((s: any) => s.id === selectedStageId.value) || null
})

function selectStage(stageId: string) {
  selectedStageId.value = stageId
  nextTick(() => {
    // Scroll the clicked node into view horizontally within the pipeline track
    const nodeEl = stageNodeRefs.value[stageId]
    nodeEl?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' })
    // Scroll the detail panel into vertical view so the user sees it immediately
    detailPanelRef.value?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  })
}
</script>

<template>
  <div class="flow-shell">
    <div class="d-flex align-center justify-space-between mb-3 ga-2 flex-wrap">
      <div class="text-subtitle-2 font-weight-medium">Reconcile Pipeline</div>
      <div class="d-flex align-center ga-2">
        <v-btn
          v-if="showRetry"
          size="small"
          variant="tonal"
          color="warning"
          prepend-icon="mdi-refresh"
          :loading="retrying"
          @click="emit('retry')"
        >
          Re-Evaluate
        </v-btn>
        <v-chip size="small" variant="tonal" color="primary">
          {{ flow?.phase || 'Pending' }}
        </v-chip>
      </div>
    </div>

    <div v-if="!flow?.stages?.length" class="text-caption text-secondary">
      Execution flow not available yet.
    </div>

    <template v-else>
      <!-- Horizontal CI/CD pipeline (GitHub Actions / ArgoCD style).
           Scrolls horizontally on narrow screens; each node is a button
           that opens the detail panel below. -->
      <div class="pipeline-track" role="list">
        <template v-for="(stage, index) in flow.stages" :key="stage.id">
          <button
            :ref="(el) => { stageNodeRefs[stage.id] = el as HTMLElement }"
            type="button"
            class="pipeline-node"
            :class="[
              `tone-${toneColor(stage.status)}`,
              { 'is-selected': selectedStageId === stage.id },
            ]"
            role="listitem"
            @click="selectStage(stage.id)"
          >
            <div class="node-pill" :class="`tone-${toneColor(stage.status)}`">
              <v-icon size="18" :class="{ spin: stage.status === 'running' }">
                {{ toneIcon(stage.status) }}
              </v-icon>
            </div>
            <div class="node-body">
              <div class="node-title">{{ stage.title }}</div>
              <div class="node-status" :class="`status-${toneColor(stage.status)}`">
                {{ stage.status }}
              </div>
            </div>
          </button>
          <div
            v-if="Number(index) < flow.stages.length - 1"
            class="pipeline-arrow"
            :class="`arrow-${toneColor(flow.stages[index].status)}`"
            aria-hidden="true"
          >
            <v-icon size="16">mdi-arrow-down-thin</v-icon>
          </div>
        </template>
      </div>

      <!-- Detail panel: opens automatically for failed/running stages.
           Acts like the expanded job view in GitHub Actions — shows the
           sub-task forensics so the user knows *why* a step is in its
           current state. -->
      <div v-if="selectedStage" ref="detailPanelRef" class="detail-panel" :class="`tone-${toneColor(selectedStage.status)}`">
        <div class="detail-header">
          <div class="detail-pill" :class="`tone-${toneColor(selectedStage.status)}`">
            <v-icon size="20" :class="{ spin: selectedStage.status === 'running' }">
              {{ toneIcon(selectedStage.status) }}
            </v-icon>
          </div>
          <div class="flex-grow-1">
            <div class="d-flex align-center ga-2 flex-wrap">
              <div class="text-body-2 font-weight-medium">{{ selectedStage.title }}</div>
              <v-chip size="x-small" variant="tonal" :color="toneColor(selectedStage.status)">
                {{ selectedStage.status }}
              </v-chip>
            </div>
            <div class="text-caption text-secondary">{{ selectedStage.description }}</div>
          </div>
        </div>

        <div
          v-if="selectedStage.message && selectedStage.status === 'running'"
          class="detail-message text-caption text-info font-italic mt-2"
        >
          <v-icon size="12" class="mr-1">mdi-clock-outline</v-icon>{{ selectedStage.message }}
        </div>

        <div v-if="selectedStage.subtasks && selectedStage.subtasks.length" class="subtasks">
          <div
            v-for="task in selectedStage.subtasks"
            :key="task.id"
            class="subtask-row"
            :class="`subtask-tone-${toneColor(task.status)}`"
          >
            <div class="subtask-icon" :class="`tone-${toneColor(task.status)}`">
              <v-icon size="14" :class="{ spin: task.status === 'running' }">
                {{ toneIcon(task.status) }}
              </v-icon>
            </div>
            <div class="flex-grow-1">
              <div class="d-flex align-center ga-2 flex-wrap">
                <div class="text-body-2 font-weight-medium">{{ task.title }}</div>
                <v-chip size="x-small" variant="tonal" :color="toneColor(task.status)">
                  {{ task.status }}
                </v-chip>
              </div>
              <div v-if="task.detail" class="text-caption text-secondary mt-1" style="word-break: break-word;">
                {{ task.detail }}
              </div>
            </div>
          </div>
        </div>
        <div v-else class="text-caption text-secondary mt-2 font-italic">
          No sub-step forensics available for this stage.
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.flow-shell {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 16px;
  padding: 16px;
  background: rgba(var(--v-theme-surface), 1);
}

/* --- Vertical pipeline track --------------------------------------- */
.pipeline-track {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 4px;
  padding: 8px 4px 14px 4px;
}

.pipeline-node {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  min-height: 60px;
  padding: 10px 16px;
  border-radius: 12px;
  border: 3px solid rgba(var(--v-theme-on-surface), 0.22);
  background: transparent;
  cursor: pointer;
  text-align: left;
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}

.pipeline-node:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.08);
}

.pipeline-node.is-selected {
  border-color: rgba(var(--v-theme-primary), 0.7);
  box-shadow: 0 0 0 2px rgba(var(--v-theme-primary), 0.35), 0 8px 22px rgba(0, 0, 0, 0.08);
}

.pipeline-node.tone-error.is-selected {
  border-color: rgba(var(--v-theme-error), 0.8);
  box-shadow: 0 0 0 2px rgba(var(--v-theme-error), 0.35), 0 8px 22px rgba(0, 0, 0, 0.08);
}

.pipeline-node.tone-info.is-selected {
  border-color: rgba(var(--v-theme-info), 0.8);
  box-shadow: 0 0 0 2px rgba(var(--v-theme-info), 0.35), 0 8px 22px rgba(0, 0, 0, 0.08);
}

.node-pill {
  width: 34px;
  height: 34px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 2px solid transparent;
  flex-shrink: 0;
}

.node-body {
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-grow: 1;
  min-width: 0;
}

.node-title {
  font-size: 0.82rem;
  font-weight: 600;
  color: rgba(var(--v-theme-on-surface), 0.92);
  line-height: 1.25;
  white-space: normal;
  word-break: break-word;
  flex: 1 1 auto;
  min-width: 0;
}

.node-status {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-weight: 600;
  opacity: 0.9;
  flex-shrink: 0;
}

.status-success { color: rgb(var(--v-theme-success)); }
.status-error { color: rgb(var(--v-theme-error)); }
.status-warning { color: rgb(var(--v-theme-warning)); }
.status-info { color: rgb(var(--v-theme-info)); }
.status-secondary,
.status-default { color: rgba(var(--v-theme-on-surface), 0.7); }

.pipeline-arrow {
  display: flex;
  align-items: center;
  justify-content: center;
  color: rgba(var(--v-theme-on-surface), 0.4);
  flex-shrink: 0;
  height: 18px;
  margin-left: 28px; /* aligns visually with the icon pill on the left of each node */
  align-self: flex-start;
}

.arrow-success { color: rgba(var(--v-theme-success), 0.7); }
.arrow-error { color: rgba(var(--v-theme-error), 0.55); }
.arrow-info { color: rgba(var(--v-theme-info), 0.7); }

/* --- Detail panel (sub-tasks accordion) ---------------------------- */
.detail-panel {
  border: 3px solid rgba(var(--v-theme-on-surface), 0.15);
  border-radius: 14px;
  padding: 14px 16px;
  background: rgba(var(--v-theme-surface), 1);
  margin-top: 10px;
}

.detail-panel.tone-error {
  border-color: rgb(var(--v-theme-error));
}

.detail-panel.tone-info {
  border-color: rgb(var(--v-theme-info));
}

.detail-panel.tone-success {
  border-color: rgb(var(--v-theme-success));
}

.detail-panel.tone-warning {
  border-color: rgb(var(--v-theme-warning));
}

.detail-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.detail-pill {
  width: 42px;
  height: 42px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 2px solid transparent;
  flex-shrink: 0;
}

.subtasks {
  display: grid;
  gap: 8px;
  margin-top: 14px;
}

.subtask-row {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 10px;
  background: rgba(var(--v-theme-surface), 1);
  border: 3px solid rgba(var(--v-theme-on-surface), 0.1);
}

.subtask-row.subtask-tone-error {
  background: rgba(var(--v-theme-surface), 1);
  border-color: rgb(var(--v-theme-error));
}

.subtask-row.subtask-tone-success {
  background: rgba(var(--v-theme-surface), 1);
  border-color: rgb(var(--v-theme-success));
}

.subtask-row.subtask-tone-info {
  background: rgba(var(--v-theme-surface), 1);
  border-color: rgb(var(--v-theme-info));
}

.subtask-row.subtask-tone-warning {
  background: rgba(var(--v-theme-surface), 1);
  border-color: rgb(var(--v-theme-warning));
}

.subtask-icon {
  width: 28px;
  height: 28px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 2px solid transparent;
  flex-shrink: 0;
  margin-top: 1px;
}

/* --- Shared tone palette: only border + icon colored, no fill ------ */
.tone-success {
  background: transparent;
  color: rgb(var(--v-theme-success));
  border-color: rgb(var(--v-theme-success));
}

.tone-error {
  background: transparent;
  color: rgb(var(--v-theme-error));
  border-color: rgb(var(--v-theme-error));
}

.tone-warning {
  background: transparent;
  color: rgb(var(--v-theme-warning));
  border-color: rgb(var(--v-theme-warning));
}

.tone-info {
  background: transparent;
  color: rgb(var(--v-theme-info));
  border-color: rgb(var(--v-theme-info));
}

.tone-secondary,
.tone-default {
  background: transparent;
  color: rgba(var(--v-theme-on-surface), 0.8);
  border-color: rgba(var(--v-theme-on-surface), 0.4);
}

/* Pipeline node tones: only border is colored, no fill */
.pipeline-node.tone-success,
.pipeline-node.tone-error,
.pipeline-node.tone-warning,
.pipeline-node.tone-info,
.pipeline-node.tone-secondary,
.pipeline-node.tone-default {
  background: transparent;
  color: inherit;
}

.pipeline-node.tone-success { border: 3px solid rgb(var(--v-theme-success)); }
.pipeline-node.tone-error   { border: 3px solid rgb(var(--v-theme-error)); }
.pipeline-node.tone-warning { border: 3px solid rgb(var(--v-theme-warning)); }
.pipeline-node.tone-info    { border: 3px solid rgb(var(--v-theme-info)); }
.pipeline-node.tone-secondary,
.pipeline-node.tone-default { border: 3px solid rgba(var(--v-theme-on-surface), 0.22); }

.spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>
