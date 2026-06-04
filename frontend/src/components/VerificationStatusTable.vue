<script setup lang="ts">
import { computed, ref } from 'vue'

interface VerificationEntry {
  passed?: boolean
  reason?: string
  completedAt?: string
  [extra: string]: any
}

const props = defineProps<{
  verifications: Record<string, VerificationEntry> | null | undefined
}>()

// Per-row expand state for the Trivy findings dropdown (keyed by check key).
const open = ref<Record<string, boolean>>({})

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

const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

// Findings sorted by severity (critical first) for the expanded table.
function sortedFindings(entry?: VerificationEntry): any[] {
  const f = Array.isArray(entry?.findings) ? [...entry!.findings] : []
  return f.sort(
    (a, b) =>
      (SEV_RANK[String(b?.severity).toUpperCase()] || 0) -
      (SEV_RANK[String(a?.severity).toUpperCase()] || 0),
  )
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
          <template v-for="row in rows" :key="row.key">
            <tr :class="{ 'gc-has-expand': open[row.key] && row.entry?.findings?.length }">
              <td>
                <div class="font-weight-medium">{{ row.title }}</div>
                <div class="text-caption text-medium-emphasis">{{ row.description }}</div>
              </td>
              <td>
                <v-chip :color="statusColor(row.entry)" size="small" variant="flat">
                  {{ statusLabel(row.entry) }}
                </v-chip>
              </td>
              <td class="text-caption" style="min-width: 300px">
                <div>{{ reasonLabel(row.entry) }}</div>

                <!-- severity summary (Trivy) -->
                <div v-if="severityCounts(row.entry).length" class="d-flex ga-1 mt-1 flex-wrap align-center">
                  <v-chip
                    v-for="[sev, n] in severityCounts(row.entry)"
                    :key="sev" :color="sevColor(sev)" size="x-small" variant="flat" label
                  >{{ sev.toLowerCase() }} · {{ n }}</v-chip>
                  <span v-if="row.entry?.vexExempted?.length" class="text-disabled ml-1">
                    {{ row.entry.vexExempted.length }} VEX-exempted
                  </span>
                </div>

                <!-- expand toggle -->
                <button
                  v-if="row.entry?.findings?.length"
                  type="button" class="gc-toggle mt-2"
                  :aria-expanded="!!open[row.key]"
                  @click="open[row.key] = !open[row.key]"
                >
                  <v-icon size="16">{{ open[row.key] ? 'mdi-chevron-down' : 'mdi-chevron-right' }}</v-icon>
                  {{ open[row.key] ? 'Hide' : 'Show all' }} {{ row.entry.findings.length }} detected vulnerabilities
                </button>
              </td>
              <td class="text-caption text-medium-emphasis">{{ formatTime(row.entry?.completedAt) }}</td>
            </tr>

            <!-- full-width expansion: structured vulnerability table -->
            <tr v-if="open[row.key] && row.entry?.findings?.length" class="gc-expand-row">
              <td colspan="4" class="pa-0">
                <div class="gc-vuln-wrap">
                  <table class="gc-vuln-table">
                    <thead>
                      <tr>
                        <th class="gc-col-sev">Severity</th>
                        <th>CVE / Advisory</th>
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed in</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="(f, i) in sortedFindings(row.entry)" :key="i">
                        <td>
                          <v-chip :color="sevColor(f.severity)" size="x-small" variant="flat" label>
                            {{ String(f.severity || '').toLowerCase() }}
                          </v-chip>
                        </td>
                        <td>
                          <a
                            v-if="cveUrl(f)"
                            :href="cveUrl(f)" target="_blank" rel="noopener noreferrer"
                            class="font-mono gc-cve-link"
                          >{{ f.id }}<v-icon size="11" class="ml-1">mdi-open-in-new</v-icon></a>
                          <span v-else class="font-mono">{{ f.id }}</span>
                          <div v-if="f.title" class="text-caption text-medium-emphasis gc-vuln-title">{{ f.title }}</div>
                        </td>
                        <td class="font-mono">{{ f.pkg || '—' }}</td>
                        <td class="font-mono text-medium-emphasis">{{ f.installed || '—' }}</td>
                        <td class="font-mono">
                          <span v-if="f.fixedVersion" class="text-success">{{ f.fixedVersion }}</span>
                          <span v-else class="text-disabled">no fix</span>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.font-mono { font-family: 'Roboto Mono', monospace; }

.gc-cve-link {
  color: rgb(var(--v-theme-info));
  text-decoration: none;
  white-space: nowrap;
}
.gc-cve-link:hover { text-decoration: underline; }

.gc-toggle {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  color: rgb(var(--v-theme-info));
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  background: none;
  border: none;
  padding: 0;
}
.gc-toggle:hover { text-decoration: underline; }

/* keep the toggled row visually tied to its expansion panel */
.gc-has-expand > td { border-bottom: none !important; }

.gc-expand-row > td {
  background: rgba(var(--v-theme-on-surface), 0.02);
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.12);
}
.gc-vuln-wrap {
  max-height: 360px;
  overflow-y: auto;
}
.gc-vuln-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.78rem;
}
.gc-vuln-table thead th {
  position: sticky;
  top: 0;
  z-index: 1;
  text-align: left;
  font-size: 0.65rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: rgba(var(--v-theme-on-surface), 0.6);
  background: rgb(var(--v-theme-surface));
  padding: 8px 16px;
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.16);
}
.gc-vuln-table tbody td {
  padding: 6px 16px;
  vertical-align: top;
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.06);
}
.gc-vuln-table tbody tr:hover td {
  background: rgba(var(--v-theme-on-surface), 0.04);
}
.gc-col-sev { width: 92px; }
.gc-vuln-title {
  max-width: 460px;
  white-space: normal;
  line-height: 1.35;
  margin-top: 2px;
}
</style>
