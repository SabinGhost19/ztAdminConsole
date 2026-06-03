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
  { key: 'securityScan', title: 'Security scan (gitleaks/checkov/semgrep)', description: 'Signed secrets + IaC + SAST aggregate (security-scan/v1).' },
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

function sevColor(sev?: string): string {
  switch (String(sev || '').toUpperCase()) {
    case 'CRITICAL': return 'error'
    case 'HIGH': return 'deep-orange'
    case 'MEDIUM': return 'warning'
    case 'LOW': return 'info'
    default: return 'grey'
  }
}

// Non-zero severity counts as [sev, n] pairs, highest-first.
function severityCounts(entry?: VerificationEntry): [string, number][] {
  const c = entry?.counts || {}
  return (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const)
    .map((s) => [s, Number(c[s] || 0)] as [string, number])
    .filter(([, n]) => n > 0)
}

// Authoritative detail page for a finding: prefer Trivy's PrimaryURL, then NVD
// (CVE), GitHub Advisories (GHSA), else the OSV.dev aggregator.
function cveUrl(f: any): string {
  const url = String(f?.primaryUrl || '').trim()
  if (url) return url
  const id = String(f?.id || '').trim()
  if (/^CVE-/i.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`
  if (/^GHSA-/i.test(id)) return `https://github.com/advisories/${id}`
  if (id) return `https://osv.dev/vulnerability/${id}`
  return ''
}

// A friendlier one-liner for the technical reason codes.
function reasonLabel(entry?: VerificationEntry): string {
  if (!entry) return '—'
  const r = String(entry.reason || (entry.passed ? 'ok' : 'failed'))
  if (r === 'trivy-fixable-vulnerability-found') return 'Fixable CVEs found (policy fails on fixable)'
  if (r === 'trivy-threshold-exceeded') return `Severity ${entry.highest} exceeds allowed ${entry.threshold}`
  if (r === 'trivy-scan-failed') return 'Trivy scan could not run'
  return r
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
            <td class="text-caption" style="min-width: 280px">
              <div>{{ reasonLabel(row.entry) }}</div>

              <!-- severity counts (Trivy) -->
              <div v-if="severityCounts(row.entry).length" class="d-flex ga-1 mt-1 flex-wrap">
                <v-chip
                  v-for="[sev, n] in severityCounts(row.entry)"
                  :key="sev" :color="sevColor(sev)" size="x-small" variant="flat"
                >{{ sev.toLowerCase() }} {{ n }}</v-chip>
                <span v-if="row.entry?.vexExempted?.length" class="text-disabled ml-1 align-self-center">
                  ({{ row.entry.vexExempted.length }} VEX-exempted)
                </span>
              </div>

              <!-- per-CVE findings (Trivy) -->
              <ul v-if="row.entry?.findings?.length" class="gc-findings mt-1">
                <li v-for="(f, i) in row.entry.findings.slice(0, 8)" :key="i">
                  <v-chip :color="sevColor(f.severity)" size="x-small" variant="flat" class="mr-1">{{ String(f.severity || '').toLowerCase() }}</v-chip>
                  <a
                    v-if="cveUrl(f)"
                    :href="cveUrl(f)" target="_blank" rel="noopener noreferrer"
                    class="font-mono gc-cve-link"
                  >{{ f.id }}<v-icon size="11" class="ml-1">mdi-open-in-new</v-icon></a>
                  <span v-else class="font-mono">{{ f.id }}</span>
                  <span class="text-medium-emphasis"> — {{ f.pkg }} {{ f.installed }}</span>
                  <span v-if="f.fixedVersion" class="text-success"> → fixed in {{ f.fixedVersion }}</span>
                </li>
                <li v-if="row.entry.findings.length > 8" class="text-disabled">
                  +{{ row.entry.findings.length - 8 }} more…
                </li>
              </ul>
            </td>
            <td class="text-caption text-medium-emphasis">{{ formatTime(row.entry?.completedAt) }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.gc-findings {
  list-style: none;
  padding: 0;
  margin: 0;
}
.gc-findings li {
  padding: 1px 0;
  line-height: 1.6;
}
.font-mono { font-family: 'Roboto Mono', monospace; }
.gc-cve-link {
  color: rgb(var(--v-theme-info));
  text-decoration: none;
}
.gc-cve-link:hover { text-decoration: underline; }
</style>
