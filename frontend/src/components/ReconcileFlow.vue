<script setup lang="ts">
import { computed, ref, watch } from 'vue'

const props = defineProps<{
  flow?: Record<string, any> | null
  retrying?: boolean
}>()

const emit = defineEmits<{
  (e: 'retry'): void
}>()

type Tone = 'success' | 'error' | 'warning' | 'running' | 'skipped' | 'pending'

function tone(status?: string): Tone {
  if (status === 'success') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'warning') return 'warning'
  if (status === 'running') return 'running'
  if (status === 'skipped') return 'skipped'
  return 'pending'
}

function statusLabel(status?: string) {
  if (status === 'success') return 'Success'
  if (status === 'failed') return 'Failed'
  if (status === 'warning') return 'Warning'
  if (status === 'running') return 'Running'
  if (status === 'skipped') return 'Skipped'
  return 'Pending'
}

function statusIcon(status?: string) {
  if (status === 'success') return 'mdi-check-circle'
  if (status === 'failed') return 'mdi-close-circle'
  if (status === 'warning') return 'mdi-alert'
  if (status === 'skipped') return 'mdi-skip-next-circle'
  return 'mdi-circle-outline'
}

// Stage metadata indexed by the stable IDs emitted by the backend
// integrity_service. `source` says where the work originates (CI = GitHub
// Actions workflow producing artefacts, Admission = provenance-enforcer
// webhook, Operator = zta-operator reconcile loop in-cluster). `tech` lists
// the underlying tooling so the reader recognises GitHub Actions /
// Cosign / Trivy / OPA / Falco at a glance.
type StageMeta = { icon: string; source: 'CI' | 'Admission' | 'Operator'; tech: string }
const STAGE_META: Record<string, StageMeta> = {
  manifest:        { icon: 'mdi-file-document-check-outline', source: 'Operator',  tech: 'kube-apiserver · CRD validation' },
  provenance:      { icon: 'mdi-shield-key-outline',           source: 'Admission', tech: 'VBBI voucher · HMAC chain · Merkle (RFC 6962)' },
  'supply-chain':  { icon: 'mdi-shield-search',                source: 'CI',        tech: 'Cosign keyless · Trivy CVE gate' },
  attestation:     { icon: 'mdi-certificate-outline',          source: 'CI',        tech: 'SLSA v1.0 · SBOM (SPDX) · OpenVEX · policy attestation' },
  'resource-plan': { icon: 'mdi-clipboard-list-outline',       source: 'Operator',  tech: 'Manifest analysis · Istio/Falco/Talon detection' },
  provisioning:    { icon: 'mdi-rocket-launch-outline',        source: 'Operator',  tech: 'Deployment · Service · NetworkPolicy · AuthorizationPolicy' },
  runtime:         { icon: 'mdi-shield-lock-outline',          source: 'Operator',  tech: 'Falco rules · Talon kill-switch · WasmPlugin' },
  ready:           { icon: 'mdi-check-decagram-outline',       source: 'Operator',  tech: 'securityState + trustLevel exposed to dashboard' },
}

function stageIcon(stage: any): string {
  return STAGE_META[stage?.id as string]?.icon || 'mdi-circle-outline'
}
function stageSource(stage: any): string {
  return STAGE_META[stage?.id as string]?.source || 'Operator'
}
function stageTech(stage: any): string {
  return STAGE_META[stage?.id as string]?.tech || ''
}

function formatDuration(ms?: number | null): string {
  if (!ms || ms <= 0) return ''
  if (ms < 1000) return `${ms} ms`
  const seconds = ms / 1000
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`
  const minutes = Math.floor(seconds / 60)
  const rem = Math.floor(seconds % 60)
  return rem ? `${minutes}m ${rem}s` : `${minutes}m`
}

function stageDuration(stage: any): string {
  // Prefer an explicit aggregate from backend; otherwise sum subtask durations.
  if (typeof stage?.durationMs === 'number') return formatDuration(stage.durationMs)
  const tasks = Array.isArray(stage?.subtasks) ? stage.subtasks : []
  const sum = tasks.reduce((acc: number, t: any) => acc + (Number(t?.durationMs) || 0), 0)
  return formatDuration(sum)
}

// Retry visibility — same logic as before; the operator may leave the flow
// in a terminal failure state that the user can re-trigger manually.
const showRetry = computed(() => {
  const phase = String(props.flow?.phase || '')
  return phase === 'Failed_SupplyChain' || phase === 'Degraded'
})

// Auto-expand the most relevant stage. Failed > Running > first.
const expandedId = ref<string | null>(null)

watch(
  () => props.flow?.stages,
  (stages) => {
    if (!stages || !stages.length) {
      expandedId.value = null
      return
    }
    if (expandedId.value && stages.some((s: any) => s.id === expandedId.value)) return
    const failed = stages.find((s: any) => s.status === 'failed')
    const running = stages.find((s: any) => s.status === 'running')
    expandedId.value = failed?.id || running?.id || null
  },
  { immediate: true, deep: true },
)

function toggleStage(id: string) {
  expandedId.value = expandedId.value === id ? null : id
}
</script>

<template>
  <div class="gh-shell">
    <header class="gh-header">
      <div class="gh-title">Reconcile Pipeline</div>
      <div class="gh-header-actions">
        <button
          v-if="showRetry"
          type="button"
          class="gh-btn"
          :disabled="retrying"
          @click="emit('retry')"
        >
          <v-icon size="14" :class="{ spin: retrying }">mdi-refresh</v-icon>
          <span>Re-Evaluate</span>
        </button>
      </div>
    </header>

    <div v-if="!flow?.stages?.length" class="gh-empty">
      Execution flow not available yet.
    </div>

    <ol v-else class="gh-track">
      <li
        v-for="(stage, index) in flow.stages"
        :key="stage.id"
        class="gh-stage"
        :class="[`tone-${tone(stage.status)}`, { 'is-first': index === 0, 'is-last': index === flow.stages.length - 1 }]"
      >
        <button
          type="button"
          class="gh-stage-row"
          :class="{ 'is-open': expandedId === stage.id }"
          :aria-expanded="expandedId === stage.id"
          @click="toggleStage(stage.id)"
        >
          <span class="gh-stage-icon" :class="`tone-${tone(stage.status)}`">
            <v-icon v-if="stage.status === 'running'" size="18" class="spin">mdi-loading</v-icon>
            <v-icon
              v-else-if="stage.status === 'success' || stage.status === 'failed' || stage.status === 'warning' || stage.status === 'skipped'"
              size="18"
            >{{ statusIcon(stage.status) }}</v-icon>
            <v-icon v-else size="18">{{ stageIcon(stage) }}</v-icon>
          </span>

          <span class="gh-stage-body">
            <span class="gh-stage-headline">
              <span class="gh-stage-title">{{ stage.title }}</span>
              <span class="gh-stage-source" :class="`src-${stageSource(stage).toLowerCase()}`">
                {{ stageSource(stage) }}
              </span>
            </span>
            <span v-if="stageTech(stage)" class="gh-stage-tech">
              <v-icon size="11" class="mr-1">{{ stageIcon(stage) }}</v-icon>{{ stageTech(stage) }}
            </span>
            <span v-if="stage.description" class="gh-stage-sub">{{ stage.description }}</span>
          </span>

          <span class="gh-stage-meta">
            <span v-if="stageDuration(stage)" class="gh-stage-duration">
              <v-icon size="11">mdi-timer-outline</v-icon>{{ stageDuration(stage) }}
            </span>
            <span class="gh-stage-status" :class="`tone-${tone(stage.status)}`">
              {{ statusLabel(stage.status) }}
            </span>
          </span>

          <v-icon
            size="16"
            class="gh-chevron"
            :class="{ 'is-open': expandedId === stage.id }"
          >mdi-chevron-down</v-icon>
        </button>

        <transition name="gh-collapse">
          <div v-if="expandedId === stage.id" class="gh-stage-details">
            <div
              v-if="stage.message && stage.status === 'running'"
              class="gh-detail-banner"
            >
              <v-icon size="14">mdi-clock-outline</v-icon>
              <span>{{ stage.message }}</span>
            </div>

            <div v-if="stage.subtasks && stage.subtasks.length" class="gh-log">
              <div
                v-for="(task, ti) in stage.subtasks"
                :key="task.id"
                class="gh-log-row"
                :class="`tone-${tone(task.status)}`"
              >
                <span class="gh-log-line">{{ String(Number(ti) + 1).padStart(2, '0') }}</span>
                <v-icon size="14" class="gh-log-icon" :class="{ spin: task.status === 'running' }">
                  {{ task.status === 'running' ? 'mdi-loading' : statusIcon(task.status) }}
                </v-icon>
                <div class="gh-log-content">
                  <div class="gh-log-title">{{ task.title }}</div>
                  <div v-if="task.detail" class="gh-log-detail">{{ task.detail }}</div>
                </div>
                <span v-if="formatDuration(task.durationMs)" class="gh-log-duration">
                  {{ formatDuration(task.durationMs) }}
                </span>
              </div>
            </div>
            <div v-else class="gh-log-empty">
              No sub-step forensics available for this stage.
            </div>
          </div>
        </transition>
      </li>
    </ol>
  </div>
</template>

<style scoped>
/* GitHub Actions–inspired palette (dark mode). Hard-coded because these are
   product-identity colors, not theme tokens. */
.gh-shell {
  --gh-canvas: #0d1117;
  --gh-default: #161b22;
  --gh-subtle: #1c2128;
  --gh-border: #30363d;
  --gh-border-muted: #21262d;
  --gh-fg: #c9d1d9;
  --gh-fg-muted: #8b949e;
  --gh-success: #3fb950;
  --gh-error: #f85149;
  --gh-warning: #d29922;
  --gh-info: #58a6ff;
  --gh-skipped: #8b949e;

  background: rgb(var(--v-theme-surface));
  border: 1px solid var(--gh-border);
  border-radius: 12px;
  padding: 16px 18px;
  color: var(--gh-fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
}

/* --- Header -------------------------------------------------------- */
.gh-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--gh-border-muted);
}

.gh-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--gh-fg);
  letter-spacing: -0.01em;
}

.gh-header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.gh-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 12px;
  font-size: 12px;
  font-weight: 500;
  color: var(--gh-fg);
  background: var(--gh-default);
  border: 1px solid var(--gh-border);
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}
.gh-btn:hover:not(:disabled) { background: var(--gh-subtle); border-color: var(--gh-fg-muted); }
.gh-btn:disabled { opacity: 0.6; cursor: not-allowed; }

.gh-phase {
  display: inline-flex;
  align-items: center;
  padding: 2px 10px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--gh-info);
  background: rgba(88, 166, 255, 0.1);
  border: 1px solid rgba(88, 166, 255, 0.4);
  border-radius: 999px;
}

.gh-empty {
  font-size: 12px;
  color: var(--gh-fg-muted);
  padding: 12px 0;
}

/* --- Pipeline rail ------------------------------------------------- */
.gh-track {
  position: relative;
  list-style: none;
  margin: 0;
  padding: 4px 0 4px 0;
}

/* Continuous vertical rail aligned with the center of the 28px icon */
.gh-track::before {
  content: "";
  position: absolute;
  left: 13px;
  top: 24px;
  bottom: 24px;
  width: 2px;
  background: var(--gh-border);
  border-radius: 2px;
  z-index: 0;
}

.gh-stage {
  position: relative;
  margin: 0;
  padding: 0;
}
.gh-stage + .gh-stage { margin-top: 6px; }

/* --- Stage row (the clickable header) ------------------------------ */
.gh-stage-row {
  position: relative;
  z-index: 1;
  display: grid;
  grid-template-columns: 28px 1fr auto 18px;
  align-items: center;
  gap: 12px;
  width: 100%;
  padding: 10px 12px 10px 0;
  background: transparent;
  border: none;
  border-radius: 8px;
  color: inherit;
  text-align: left;
  cursor: pointer;
  transition: background 0.15s;
}
.gh-stage-row:hover { background: var(--gh-default); }
.gh-stage-row.is-open { background: var(--gh-default); }

.gh-stage-icon {
  width: 28px;
  height: 28px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: rgb(var(--v-theme-surface));
  border: 2px solid var(--gh-border);
  color: var(--gh-fg-muted);
  flex-shrink: 0;
}
.gh-stage-icon.tone-success { color: var(--gh-success); border-color: var(--gh-success); }
.gh-stage-icon.tone-error   { color: var(--gh-error);   border-color: var(--gh-error); }
.gh-stage-icon.tone-warning { color: var(--gh-warning); border-color: var(--gh-warning); }
.gh-stage-icon.tone-running { color: var(--gh-info);    border-color: var(--gh-info); }
.gh-stage-icon.tone-skipped { color: var(--gh-skipped); border-color: var(--gh-border); background: rgb(var(--v-theme-surface)); }
.gh-stage-icon.tone-pending { color: var(--gh-fg-muted); border-color: var(--gh-border); }

.gh-stage-body {
  display: flex;
  flex-direction: column;
  min-width: 0;
  gap: 2px;
}
.gh-stage-headline {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.gh-stage-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--gh-fg);
  line-height: 1.3;
}
.gh-stage-source {
  display: inline-flex;
  align-items: center;
  font-size: 9.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid var(--gh-border);
  color: var(--gh-fg-muted);
  background: rgba(255, 255, 255, 0.02);
}
.gh-stage-source.src-ci         { color: var(--gh-info);    border-color: rgba(88, 166, 255, 0.45); }
.gh-stage-source.src-admission  { color: var(--gh-warning); border-color: rgba(210, 153, 34, 0.45); }
.gh-stage-source.src-operator   { color: var(--gh-success); border-color: rgba(63, 185, 80, 0.45); }
.gh-stage-tech {
  display: flex;
  align-items: center;
  font-size: 11.5px;
  color: var(--gh-fg-muted);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  letter-spacing: 0.01em;
  line-height: 1.35;
}
.gh-stage-sub {
  font-size: 11.5px;
  color: var(--gh-fg-muted);
  line-height: 1.4;
  opacity: 0.85;
}

.gh-stage-meta {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  white-space: nowrap;
}
.gh-stage-duration {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 11px;
  color: var(--gh-fg-muted);
  font-variant-numeric: tabular-nums;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}

.gh-stage-status {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid transparent;
  white-space: nowrap;
}
.gh-stage-status.tone-success { color: var(--gh-success); border-color: rgba(63, 185, 80, 0.4);  background: rgba(63, 185, 80, 0.1); }
.gh-stage-status.tone-error   { color: var(--gh-error);   border-color: rgba(248, 81, 73, 0.4);  background: rgba(248, 81, 73, 0.1); }
.gh-stage-status.tone-warning { color: var(--gh-warning); border-color: rgba(210, 153, 34, 0.4); background: rgba(210, 153, 34, 0.1); }
.gh-stage-status.tone-running { color: var(--gh-info);    border-color: rgba(88, 166, 255, 0.4); background: rgba(88, 166, 255, 0.1); }
.gh-stage-status.tone-skipped { color: var(--gh-skipped); border-color: var(--gh-border);        background: transparent; }
.gh-stage-status.tone-pending { color: var(--gh-fg-muted); border-color: var(--gh-border);       background: transparent; }

.gh-chevron {
  color: var(--gh-fg-muted);
  transition: transform 0.2s ease;
}
.gh-chevron.is-open { transform: rotate(180deg); color: var(--gh-fg); }

/* --- Detail panel (inline, doesn't shift sibling positions) ------- */
.gh-stage-details {
  position: relative;
  z-index: 1;
  margin: 4px 0 8px 40px;
  background: var(--gh-default);
  border: 1px solid var(--gh-border-muted);
  border-radius: 8px;
  padding: 12px 14px;
}

.gh-detail-banner {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--gh-info);
  background: rgba(88, 166, 255, 0.08);
  border: 1px solid rgba(88, 166, 255, 0.3);
  border-radius: 6px;
  padding: 4px 10px;
  margin-bottom: 10px;
}

.gh-log {
  display: flex;
  flex-direction: column;
  background: rgb(var(--v-theme-surface));
  border: 1px solid var(--gh-border-muted);
  border-radius: 6px;
  overflow: hidden;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}

.gh-log-row {
  display: grid;
  grid-template-columns: 36px 18px 1fr auto;
  align-items: flex-start;
  gap: 10px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--gh-border-muted);
  font-size: 12px;
  color: var(--gh-fg);
}
.gh-log-row:last-child { border-bottom: none; }

.gh-log-line {
  color: var(--gh-fg-muted);
  font-variant-numeric: tabular-nums;
  user-select: none;
}
.gh-log-icon { margin-top: 1px; }
.gh-log-row.tone-success .gh-log-icon { color: var(--gh-success); }
.gh-log-row.tone-error   .gh-log-icon { color: var(--gh-error); }
.gh-log-row.tone-warning .gh-log-icon { color: var(--gh-warning); }
.gh-log-row.tone-running .gh-log-icon { color: var(--gh-info); }
.gh-log-row.tone-skipped .gh-log-icon { color: var(--gh-skipped); }

.gh-log-content { min-width: 0; }
.gh-log-title {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-weight: 500;
  color: var(--gh-fg);
}
.gh-log-detail {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  color: var(--gh-fg-muted);
  font-size: 11.5px;
  margin-top: 3px;
  word-break: break-word;
  white-space: pre-wrap;
}

.gh-log-status {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 10.5px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding-top: 2px;
}
.gh-log-status.tone-success { color: var(--gh-success); }
.gh-log-status.tone-error   { color: var(--gh-error); }
.gh-log-status.tone-warning { color: var(--gh-warning); }
.gh-log-status.tone-running { color: var(--gh-info); }
.gh-log-status.tone-skipped { color: var(--gh-skipped); }

.gh-log-empty {
  font-size: 12px;
  color: var(--gh-fg-muted);
  font-style: italic;
}

.gh-log-duration {
  align-self: flex-start;
  margin-top: 2px;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  color: var(--gh-fg-muted);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

/* --- Animations ---------------------------------------------------- */
.spin {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}

.gh-collapse-enter-active,
.gh-collapse-leave-active {
  transition: opacity 0.18s ease, max-height 0.22s ease, margin 0.22s ease;
  overflow: hidden;
}
.gh-collapse-enter-from,
.gh-collapse-leave-to {
  opacity: 0;
  max-height: 0;
  margin-top: 0;
  margin-bottom: 0;
}
.gh-collapse-enter-to,
.gh-collapse-leave-from {
  opacity: 1;
  max-height: 800px;
}
</style>
