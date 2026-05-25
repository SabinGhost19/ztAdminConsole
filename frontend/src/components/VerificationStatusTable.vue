<script setup lang="ts">
import { computed } from 'vue'

interface VerificationEntry {
  passed?: boolean
  reason?: string
  completedAt?: string
  [extra: string]: any
}

const props = defineProps<{
  verifications: Record<string, VerificationEntry> | null | undefined
}>()

const KNOWN_KEYS: { key: string; title: string; description: string }[] = [
  { key: 'cosign', title: 'Cosign keyless signature', description: 'Verify signed image via Fulcio + Rekor.' },
  { key: 'trivy', title: 'Trivy vulnerability scan', description: 'CVE threshold + fixable + OpenVEX exemptions.' },
  { key: 'sbom', title: 'SBOM attestation (spdxjson)', description: 'In-toto SBOM signed by trusted issuer.' },
  { key: 'policyAttestation', title: 'Custom ZTA policy attestation', description: 'expected_infra_hash + security boundaries.' },
  { key: 'slsaProvenance', title: 'SLSA v1.0 provenance', description: 'buildDefinition + runDetails.builder.id from trusted CI.' },
  { key: 'openvex', title: 'OpenVEX signed attestation', description: 'Signed VEX statements (v0.2.0).' },
]

const rows = computed(() => {
  const v = props.verifications || {}
  return KNOWN_KEYS.map((k) => ({
    ...k,
    entry: v[k.key] as VerificationEntry | undefined,
  }))
})

function statusColor(entry?: VerificationEntry): string {
  if (!entry || typeof entry.passed === 'undefined') return 'grey'
  return entry.passed ? 'success' : 'error'
}

function statusLabel(entry?: VerificationEntry): string {
  if (!entry || typeof entry.passed === 'undefined') return 'not run'
  return entry.passed ? 'passed' : 'failed'
}

function formatTime(ts?: string): string {
  if (!ts) return ''
  try { return new Date(ts).toLocaleString() } catch { return ts }
}
</script>

<template>
  <v-card flat border>
    <v-card-title class="text-body-1 d-flex align-center">
      <v-icon size="20" class="mr-2">mdi-shield-check-outline</v-icon>
      Verifications ledger (status.verifications)
    </v-card-title>
    <v-card-text class="py-2">
      <v-table density="compact" hover>
        <thead>
          <tr>
            <th>Check</th>
            <th>Status</th>
            <th>Reason</th>
            <th>Completed at</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.key">
            <td>
              <div class="font-weight-medium">{{ row.title }}</div>
              <div class="text-caption text-medium-emphasis">{{ row.description }}</div>
            </td>
            <td>
              <v-chip :color="statusColor(row.entry)" size="small" variant="flat">
                {{ statusLabel(row.entry) }}
              </v-chip>
            </td>
            <td class="text-caption">
              {{ row.entry?.reason || (row.entry ? 'ok' : '—') }}
            </td>
            <td class="text-caption text-medium-emphasis">{{ formatTime(row.entry?.completedAt) }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>
