<script setup lang="ts">
/**
 * Render the CVEs that Trivy detected on this image and indicate which
 * ones were exempted via OpenVEX. Goal of the demo: when the panel
 * appears, the auditor can SEE that the operator did not silently lower
 * the severity threshold — every exemption is justified, signed, and
 * itemised. Items marked `not_affected` get a strike-through and a green
 * "Exempted via OpenVEX" badge.
 */
import { computed } from 'vue'

const props = defineProps<{
  // Full list of Trivy findings for the current image. Each row may be
  // present even if exempted — exemption is signalled by `vexStatus`.
  findings: Array<{
    cveId: string
    severity: string
    packageName: string
    packageVersion?: string
    fixedVersion?: string
    vexStatus?: string         // not_affected | fixed | affected | under_investigation
    vexJustification?: string
  }>
  // Pre-filtered CVE ids that the operator already exempted at admission.
  exemptedCveIds: string[]
}>()

const rows = computed(() =>
  (props.findings || []).map((finding) => {
    const exempted = (props.exemptedCveIds || []).includes(finding.cveId)
    return { ...finding, exempted }
  })
)

const severityColor = (sev: string) => {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'red-darken-2'
    case 'HIGH': return 'red'
    case 'MEDIUM': return 'orange'
    case 'LOW': return 'amber'
    default: return 'grey'
  }
}
</script>

<template>
  <v-card variant="flat" class="gc-border">
    <v-card-title class="d-flex align-center ga-2">
      <v-icon>mdi-bug-outline</v-icon>
      <span>Vulnerabilities &mdash; Trivy ∩ OpenVEX</span>
      <v-spacer />
      <v-chip size="small" color="success" variant="tonal" v-if="exemptedCveIds?.length">
        {{ exemptedCveIds.length }} exempted via VEX
      </v-chip>
    </v-card-title>
    <v-card-text>
      <v-table v-if="rows.length" density="compact">
        <thead>
          <tr>
            <th>CVE</th>
            <th>Severity</th>
            <th>Package</th>
            <th>Fixed in</th>
            <th>VEX Status</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.cveId" :class="{ 'vex-exempted': row.exempted }">
            <td>
              <span :style="row.exempted ? 'text-decoration: line-through; opacity: 0.6' : ''">
                {{ row.cveId }}
              </span>
            </td>
            <td>
              <v-chip :color="severityColor(row.severity)" size="x-small" variant="tonal">
                {{ row.severity }}
              </v-chip>
            </td>
            <td>
              {{ row.packageName }}<span v-if="row.packageVersion" class="text-medium-emphasis">@{{ row.packageVersion }}</span>
            </td>
            <td>{{ row.fixedVersion || '—' }}</td>
            <td>
              <v-chip
                v-if="row.exempted"
                color="success"
                size="x-small"
                prepend-icon="mdi-shield-check"
                variant="tonal"
                :title="row.vexJustification || 'Justified via signed OpenVEX attestation'"
              >
                Exempted via OpenVEX ({{ row.vexStatus || 'not_affected' }})
              </v-chip>
              <v-chip v-else-if="row.vexStatus === 'under_investigation'" color="warning" size="x-small" variant="tonal">
                Under investigation
              </v-chip>
              <span v-else class="text-medium-emphasis">—</span>
            </td>
          </tr>
        </tbody>
      </v-table>
      <v-alert v-else type="info" variant="tonal" density="compact">
        Nu există vulnerabilități raportate pentru această imagine.
      </v-alert>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.vex-exempted td { opacity: 0.85; }
</style>
