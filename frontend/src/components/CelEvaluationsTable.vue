<script setup lang="ts">
import { computed } from 'vue'

interface CelEvaluation {
  name: string
  expression: string
  action: string
  fired: boolean
  outcome: string
  error?: string
}

const props = defineProps<{
  evaluations: CelEvaluation[] | null | undefined
}>()

const rows = computed(() => Array.isArray(props.evaluations) ? props.evaluations : [])

function chipColor(evaluation: CelEvaluation): string {
  if (evaluation.error) return 'error'
  if (!evaluation.fired) return 'success'
  if (evaluation.action === 'Deny' || evaluation.action === 'Allow') return 'error'
  if (evaluation.action === 'Alert') return 'warning'
  return 'info'
}

function chipLabel(evaluation: CelEvaluation): string {
  if (evaluation.error) return 'error'
  if (!evaluation.fired) return 'passed'
  return `${evaluation.action.toLowerCase()} fired`
}
</script>

<template>
  <v-card flat border>
    <v-card-title class="text-body-1 d-flex align-center">
      <v-icon size="20" class="mr-2">mdi-script-text-key-outline</v-icon>
      CEL custom rule evaluations
      <v-spacer />
      <v-chip size="x-small" variant="outlined">{{ rows.length }} rules</v-chip>
    </v-card-title>
    <v-card-text class="py-2">
      <div v-if="!rows.length" class="text-caption text-medium-emphasis text-center py-4">
        Nicio regulă CEL definită în SupplyChainAttestation.spec.customRules.
      </div>
      <v-table v-else density="compact" hover>
        <thead>
          <tr>
            <th>Rule</th>
            <th>Action</th>
            <th>Status</th>
            <th>Expression</th>
            <th>Outcome</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(evaluation, idx) in rows" :key="`${evaluation.name}-${idx}`">
            <td class="font-weight-medium">{{ evaluation.name || '<unnamed>' }}</td>
            <td><v-chip size="x-small" variant="outlined">{{ evaluation.action }}</v-chip></td>
            <td>
              <v-chip :color="chipColor(evaluation)" size="x-small" variant="flat">
                {{ chipLabel(evaluation) }}
              </v-chip>
            </td>
            <td class="text-caption text-mono" style="max-width: 380px; overflow: hidden; text-overflow: ellipsis;">
              {{ evaluation.expression }}
            </td>
            <td class="text-caption">
              <span v-if="evaluation.error" class="text-error">{{ evaluation.error }}</span>
              <span v-else>{{ evaluation.outcome }}</span>
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.text-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
</style>
