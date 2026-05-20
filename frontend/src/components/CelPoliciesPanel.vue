<script setup lang="ts">
/**
 * Visualise the SCA's customRules (CEL expressions) and the verdict
 * that the operator's celpy evaluator emitted for them on the most
 * recent reconcile. Helps the auditor see that security is *declarative
 * and dynamic* — not hardcoded in Python — by reading the expressions
 * verbatim alongside their outcomes.
 */
import { computed } from 'vue'

type Action = 'Allow' | 'Deny' | 'Alert'
type Verdict = 'passed' | 'denied' | 'alerted' | 'skipped' | 'error'

const props = defineProps<{
  rules: Array<{ name: string; description?: string; expression: string; action: Action }>
  // Verdicts come from the operator's status: it records which expressions
  // fired Deny / Alert and which were satisfied (Allow == true).
  evaluations?: Array<{ name: string; verdict: Verdict; message?: string }>
}>()

const verdictByName = computed(() => {
  const m: Record<string, { verdict: Verdict; message?: string }> = {}
  for (const e of props.evaluations || []) m[e.name] = { verdict: e.verdict, message: e.message }
  return m
})

const verdictColor = (v?: Verdict) => {
  switch (v) {
    case 'passed': return 'success'
    case 'denied': return 'error'
    case 'alerted': return 'warning'
    case 'error': return 'error'
    case 'skipped': return 'grey'
    default: return 'info'
  }
}

const verdictIcon = (v?: Verdict) => {
  switch (v) {
    case 'passed': return 'mdi-check-circle'
    case 'denied': return 'mdi-close-octagon'
    case 'alerted': return 'mdi-alert'
    case 'error': return 'mdi-bug'
    case 'skipped': return 'mdi-minus-circle-outline'
    default: return 'mdi-help-circle-outline'
  }
}

const actionColor = (a: Action) => {
  if (a === 'Deny') return 'error'
  if (a === 'Alert') return 'warning'
  return 'success'
}
</script>

<template>
  <v-card variant="flat" class="gc-border" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)">
    <v-card-title class="d-flex align-center ga-2">
      <v-icon>mdi-code-tags-check</v-icon>
      <span>Dynamic Policies Evaluated (CEL)</span>
      <v-spacer />
      <v-chip size="small" variant="tonal">{{ rules?.length || 0 }} rules</v-chip>
    </v-card-title>
    <v-card-text>
      <v-list v-if="rules?.length" density="compact" lines="two">
        <v-list-item v-for="rule in rules" :key="rule.name">
          <template #prepend>
            <v-avatar :color="verdictColor(verdictByName[rule.name]?.verdict)" size="28">
              <v-icon size="16">{{ verdictIcon(verdictByName[rule.name]?.verdict) }}</v-icon>
            </v-avatar>
          </template>
          <v-list-item-title class="d-flex align-center ga-2">
            <span class="font-weight-medium">{{ rule.name }}</span>
            <v-chip :color="actionColor(rule.action)" size="x-small" variant="tonal">{{ rule.action }}</v-chip>
          </v-list-item-title>
          <v-list-item-subtitle class="text-medium-emphasis">
            <code style="background: rgba(0,0,0,0.04); padding: 2px 6px; border-radius: 4px">
              {{ rule.expression }}
            </code>
            <div v-if="rule.description" class="text-caption mt-1">{{ rule.description }}</div>
            <div v-if="verdictByName[rule.name]?.message" class="text-caption mt-1">
              <em>{{ verdictByName[rule.name]?.message }}</em>
            </div>
          </v-list-item-subtitle>
        </v-list-item>
      </v-list>
      <v-alert v-else type="info" variant="tonal" density="compact">
        Acest SCA nu definește nicio regulă dinamică (CEL). Toate validările
        provin din câmpurile statice (sourceValidation, vulnerabilityPolicy,
        sbomPolicy, strictManifestHash).
      </v-alert>
    </v-card-text>
  </v-card>
</template>
