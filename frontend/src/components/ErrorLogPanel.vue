<script setup lang="ts">
/**
 * Renders the operator's structured error ring-buffer
 * (status.errors[]). Reads from integrity payload directly so the SSE
 * stream keeps it live without a separate fetch.
 *
 * Codes use stable identifiers (sca-policy-missing, k8s-conflict,
 * supply-chain-error, etc.) so we can color-code without parsing text.
 */
import { computed } from 'vue'

interface OperatorError {
  code: string
  message: string
  phase: string
  retryable: boolean
  occurredAt: string
  details?: Record<string, any>
}

const props = defineProps<{
  errors: OperatorError[] | null | undefined
  streamError?: { code: string; message: string; recoverable: boolean } | null
}>()

const rows = computed<OperatorError[]>(() => {
  const arr = Array.isArray(props.errors) ? [...props.errors] : []
  // Newest first.
  arr.sort((a, b) => (b.occurredAt || '').localeCompare(a.occurredAt || ''))
  return arr.slice(0, 20)
})

function codeColor(code: string, retryable: boolean): string {
  if (!retryable) return 'error'
  if (code.startsWith('k8s-server') || code.startsWith('k8s-network')) return 'warning'
  if (code.startsWith('k8s-')) return 'orange'
  if (code.startsWith('sca-')) return 'info'
  if (code.startsWith('attestation-')) return 'error'
  if (code.includes('timeout')) return 'warning'
  if (code === 'reconcile-unexpected') return 'error'
  return 'grey'
}

function formatTime(ts: string): string {
  if (!ts) return ''
  try { return new Date(ts).toLocaleString() } catch { return ts }
}
</script>

<template>
  <v-card flat border>
    <v-card-title class="text-body-1 d-flex align-center">
      <v-icon size="20" class="mr-2">mdi-alert-octagon-outline</v-icon>
      Operator error log
      <v-spacer />
      <v-chip v-if="rows.length" size="x-small" variant="outlined">{{ rows.length }} entries</v-chip>
    </v-card-title>
    <v-card-text class="py-2">
      <v-alert
        v-if="streamError"
        :type="streamError.recoverable ? 'warning' : 'error'"
        variant="tonal"
        density="compact"
        class="mb-3"
      >
        <div class="d-flex align-center ga-2">
          <v-chip size="x-small" variant="flat">{{ streamError.code }}</v-chip>
          <span>{{ streamError.message }}</span>
          <v-spacer />
          <v-chip v-if="!streamError.recoverable" size="x-small" color="error" variant="flat">
            stream closed
          </v-chip>
        </div>
      </v-alert>

      <div v-if="!rows.length && !streamError" class="text-caption text-medium-emphasis text-center py-4">
        Nicio eroare înregistrată — operatorul rulează curat.
      </div>

      <v-table v-if="rows.length" density="compact" hover>
        <thead>
          <tr>
            <th>Code</th>
            <th>Phase</th>
            <th>Message</th>
            <th>Retry?</th>
            <th>When</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(err, idx) in rows" :key="`${err.occurredAt}-${idx}`">
            <td>
              <v-chip
                :color="codeColor(err.code, err.retryable)"
                size="x-small"
                variant="flat"
              >
                {{ err.code }}
              </v-chip>
            </td>
            <td class="text-caption">{{ err.phase || '—' }}</td>
            <td class="text-caption" style="max-width: 440px; white-space: pre-wrap;">
              {{ err.message }}
              <div v-if="err.details" class="text-caption text-medium-emphasis mt-1">
                <details>
                  <summary>details</summary>
                  <pre class="text-mono mb-0" style="white-space: pre-wrap;">{{ JSON.stringify(err.details, null, 2) }}</pre>
                </details>
              </div>
            </td>
            <td>
              <v-chip
                :color="err.retryable ? 'success' : 'error'"
                size="x-small"
                variant="outlined"
              >
                {{ err.retryable ? 'yes' : 'no' }}
              </v-chip>
            </td>
            <td class="text-caption text-medium-emphasis">{{ formatTime(err.occurredAt) }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.text-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
</style>
