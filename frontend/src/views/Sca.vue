<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'
import { useAuthStore } from '../store/auth'
import ScaDetailPanel from '../components/sca/ScaDetailPanel.vue'
import {
  SEVERITIES, RULE_ACTIONS, DRIFT_ACTIONS, VULN_ACTIONS, MANIFEST_ACTIONS,
  ATTESTATION_TYPE_ZTA_POLICY,
} from '../constants/zta'

const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()
const auth = useAuthStore()
const canWriteSca = computed(() => auth.can('apps:write'))

const isLoading = computed(() => dashboardStore.loadingPolicies)
const policies = computed(() => dashboardStore.policies)
const applications = computed(() => dashboardStore.applications)

const expandedScaUid = ref('')
function toggleScaExpand(uid: string) {
  expandedScaUid.value = expandedScaUid.value === uid ? '' : uid
}
// Index applications by their bound SCA once, so each expanded row is an O(1)
// lookup instead of filtering the full applications list on every render.
const scaAppsMap = computed<Record<string, any[]>>(() => {
  const m: Record<string, any[]> = {}
  for (const app of applications.value) {
    const ref = app.summary?.securityPolicyRef
    if (!ref) continue
    if (!m[ref]) m[ref] = []
    m[ref].push(app)
  }
  return m
})

interface ForbiddenPkg { name: string; maxVersion: string }
interface CelRule { name: string; description: string; expression: string; action: string }

function defaultForm() {
  return {
    name: '',
    // sourceValidation
    enforceCosign: true,
    trustedIssuers: '',
    // provenance
    requireVoucher: true,
    enforceHmacChain: true,
    minSlsaLevel: 0,
    trustedRepositories: '',
    // vulnerabilityPolicy
    maxAllowedSeverity: 'High',
    failOnFixable: true,
    // sbomPolicy
    enforceSbom: true,
    forbiddenPackages: [] as ForbiddenPkg[],
    // policyBinding
    policyBindingEnabled: true,
    requireAttestationType: ATTESTATION_TYPE_ZTA_POLICY,
    // strictManifestHash (CRD default enabled=false)
    strictManifestEnabled: false,
    strictManifestAction: 'Reject',
    // slsaProvenancePolicy
    enforceSlsa: false,
    slsaRequiredLevel: 0,
    slsaTrustedIssuers: '',
    slsaTrustedBuilders: '',
    slsaAllowedBuildTypes: '',
    // openVexPolicy
    enforceOpenVex: false,
    requireVexStatements: false,
    // securityScanPolicy
    enforceSecurityScan: false,
    requireScanAttestation: true,
    failOnSecrets: true,
    maxIacSeverity: 'High',
    maxSastSeverity: 'High',
    // customRules
    customRules: [] as CelRule[],
    // runtimeEnforcement
    runtimeEnabled: true,
    onPolicyDrift: 'Isolate',
    onVulnerabilityFound: 'Alert',
  }
}

const form = ref(defaultForm())
const isSubmitting = ref(false)
const editingSca = ref<string | null>(null)
const isEditingSca = computed(() => editingSca.value !== null)

function csvToArr(s: string): string[] {
  return String(s || '').split(',').map((x) => x.trim()).filter(Boolean)
}
function arrToCsv(a: any): string {
  return Array.isArray(a) ? a.join(', ') : ''
}
function addPkg() { form.value.forbiddenPackages.push({ name: '', maxVersion: '' }) }
function removePkg(i: number) { form.value.forbiddenPackages.splice(i, 1) }
function addRule() { form.value.customRules.push({ name: '', description: '', expression: '', action: 'Deny' }) }
function removeRule(i: number) { form.value.customRules.splice(i, 1) }

const canSubmit = computed(() => {
  if (!form.value.name.trim()) return false
  return form.value.customRules.every((r) => r.name.trim() && r.expression.trim())
})

function buildPayload() {
  return {
    name: form.value.name,
    sourceValidation: {
      enforceCosign: form.value.enforceCosign,
      trustedIssuers: csvToArr(form.value.trustedIssuers),
    },
    provenance: {
      requireVoucher: form.value.requireVoucher,
      enforceHmacChain: form.value.enforceHmacChain,
      minSlsaLevel: Number(form.value.minSlsaLevel) || 0,
      trustedRepositories: csvToArr(form.value.trustedRepositories),
    },
    vulnerabilityPolicy: {
      maxAllowedSeverity: form.value.maxAllowedSeverity,
      failOnFixable: form.value.failOnFixable,
    },
    sbomPolicy: {
      enforceSBOM: form.value.enforceSbom,
      forbiddenPackages: form.value.forbiddenPackages
        .filter((p) => p.name.trim())
        .map((p) => (p.maxVersion.trim() ? { name: p.name.trim(), maxVersion: p.maxVersion.trim() } : { name: p.name.trim() })),
    },
    policyBinding: {
      enabled: form.value.policyBindingEnabled,
      requireAttestationType: form.value.requireAttestationType,
    },
    strictManifestHash: {
      enabled: form.value.strictManifestEnabled,
      enforcementAction: form.value.strictManifestAction,
    },
    slsaProvenancePolicy: {
      enforceSlsa: form.value.enforceSlsa,
      requiredLevel: Number(form.value.slsaRequiredLevel) || 0,
      trustedIssuers: csvToArr(form.value.slsaTrustedIssuers),
      trustedBuilders: csvToArr(form.value.slsaTrustedBuilders),
      allowedBuildTypes: csvToArr(form.value.slsaAllowedBuildTypes),
    },
    openVexPolicy: {
      enforceOpenVex: form.value.enforceOpenVex,
      requireStatements: form.value.requireVexStatements,
    },
    securityScanPolicy: {
      enforceSecurityScan: form.value.enforceSecurityScan,
      requireAttestation: form.value.requireScanAttestation,
      failOnSecrets: form.value.failOnSecrets,
      maxIacSeverity: form.value.maxIacSeverity,
      maxSastSeverity: form.value.maxSastSeverity,
    },
    customRules: form.value.customRules
      .filter((r) => r.name.trim() && r.expression.trim())
      .map((r) => ({ name: r.name.trim(), description: r.description.trim(), expression: r.expression.trim(), action: r.action })),
    runtimeEnforcement: {
      enabled: form.value.runtimeEnabled,
      onPolicyDrift: form.value.onPolicyDrift,
      onVulnerabilityFound: form.value.onVulnerabilityFound,
    },
  }
}

function resetForm() {
  form.value = defaultForm()
  editingSca.value = null
}

function startEditSca(sca: any) {
  const spec = sca.spec || {}
  const sv = spec.sourceValidation || {}
  const pv = spec.provenance || {}
  const vp = spec.vulnerabilityPolicy || {}
  const sb = spec.sbomPolicy || {}
  const pb = spec.policyBinding || {}
  const mh = spec.strictManifestHash || {}
  const slsa = spec.slsaProvenancePolicy || {}
  const vex = spec.openVexPolicy || {}
  const ss = spec.securityScanPolicy || {}
  const rt = spec.runtimeEnforcement || {}
  form.value = {
    name: sca.metadata?.name || '',
    enforceCosign: sv.enforceCosign ?? true,
    trustedIssuers: arrToCsv(sv.trustedIssuers),
    requireVoucher: pv.requireVoucher ?? false,
    enforceHmacChain: pv.enforceHmacChain ?? true,
    minSlsaLevel: pv.minSlsaLevel ?? 0,
    trustedRepositories: arrToCsv(pv.trustedRepositories),
    maxAllowedSeverity: vp.maxAllowedSeverity || 'High',
    failOnFixable: vp.failOnFixable ?? false,
    enforceSbom: sb.enforceSBOM ?? true,
    forbiddenPackages: (sb.forbiddenPackages || []).map((p: any) => ({ name: p.name || '', maxVersion: p.maxVersion || '' })),
    policyBindingEnabled: pb.enabled ?? true,
    requireAttestationType: pb.requireAttestationType || ATTESTATION_TYPE_ZTA_POLICY,
    strictManifestEnabled: mh.enabled ?? false,
    strictManifestAction: mh.enforcementAction || 'Reject',
    enforceSlsa: slsa.enforceSlsa ?? false,
    slsaRequiredLevel: slsa.requiredLevel ?? 0,
    slsaTrustedIssuers: arrToCsv(slsa.trustedIssuers),
    slsaTrustedBuilders: arrToCsv(slsa.trustedBuilders),
    slsaAllowedBuildTypes: arrToCsv(slsa.allowedBuildTypes),
    enforceOpenVex: vex.enforceOpenVex ?? false,
    requireVexStatements: vex.requireStatements ?? false,
    enforceSecurityScan: ss.enforceSecurityScan ?? false,
    requireScanAttestation: ss.requireAttestation ?? true,
    failOnSecrets: ss.failOnSecrets ?? true,
    maxIacSeverity: ss.maxIacSeverity || 'High',
    maxSastSeverity: ss.maxSastSeverity || 'High',
    customRules: (spec.customRules || []).map((r: any) => ({ name: r.name || '', description: r.description || '', expression: r.expression || '', action: r.action || 'Deny' })),
    runtimeEnabled: rt.enabled ?? true,
    onPolicyDrift: rt.onPolicyDrift || 'Isolate',
    onVulnerabilityFound: rt.onVulnerabilityFound || 'Alert',
  }
  editingSca.value = sca.metadata.name
  if (typeof window !== 'undefined') window.scrollTo({ top: 0, behavior: 'smooth' })
}

onMounted(() => {
  dashboardStore.fetchPolicies(true).catch(() => undefined)
  dashboardStore.fetchApplications(true).catch(() => undefined)
})

async function submitScaDeclaration() {
  if (!canSubmit.value) return
  isSubmitting.value = true
  try {
    const payload = buildPayload()
    const updating = isEditingSca.value
    const res = updating && editingSca.value
      ? await api.put(`/sca/${editingSca.value}`, payload)
      : await api.post('/sca/', payload)
    const uid = res.data?.metadata?.uid || ''
    await dashboardStore.fetchPolicies(true)
    await dashboardStore.fetchOverview(true)

    notifyStore.addAlert({
      error_code: updating ? 'SCA_UPDATED_SUCCESS' : 'SCA_CREATED_SUCCESS',
      message: `Politica SCA '${payload.name}' a fost ${updating ? 'actualizată' : 'implementată'}.`,
      technical_details: `uid: ${uid || '—'} · trusted issuers: ${payload.sourceValidation.trustedIssuers.join(', ') || '—'}`,
      component: 'SUPPLY_CHAIN_BUILDER',
      trace_id: uid || payload.name,
      action_required: 'Operatorul reconciliază politicile la următoarea evaluare a aplicațiilor legate.',
      type: 'warning'
    })

    resetForm()
  } catch (err) {
  } finally {
    isSubmitting.value = false
  }
}

async function revokeSca(name: string) {
  try {
    const res = await api.delete(`/sca/${name}`)
    if (editingSca.value === name) resetForm()
    await dashboardStore.fetchPolicies(true)
    await dashboardStore.fetchOverview(true)
    notifyStore.addAlert({
      error_code: 'SCA_REVOKED_SUCCESS',
      message: `Politica '${name}' a fost invalidată cu succes.`,
      technical_details: res.data?.message || `SCA ${name} șters din cluster.`,
      component: 'SUPPLY_CHAIN_ADMIN',
      trace_id: name,
      action_required: '',
      type: 'warning'
    })
  } catch (err) {
  }
}
</script>

<template>
  <div>
    <div class="d-flex align-center justify-space-between mb-4">
      <h1 class="text-h5 font-weight-medium text-primary">Supply Chain Attestation</h1>
    </div>

    <v-row>
      <v-col cols="12" md="5" lg="4">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary d-flex align-center">
            <span>{{ isEditingSca ? `Editează: ${editingSca}` : 'Configurare Securitate Pipeline' }}</span>
            <v-spacer />
            <v-btn v-if="isEditingSca" size="x-small" variant="text" color="secondary" @click="resetForm">Anulează</v-btn>
          </v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary mb-4">Cosign + provenance + SBOM + scanări OSS și reguli CEL dinamice. Toate câmpurile CRD-ului sunt configurabile.</p>

            <v-text-field v-model="form.name" :rules="[(v) => !!v || 'Obligatoriu']" :disabled="isEditingSca" label="Nume Politică SCA" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>

            <!-- Source & provenance (core) -->
            <v-text-field v-model="form.trustedIssuers" label="Trusted Issuers (CSV)" placeholder="ghcr.io/org, https://token.actions.githubusercontent.com" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.trustedRepositories" label="Trusted Repositories (CSV)" placeholder="owner/repo, owner/repo-2" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model.number="form.minSlsaLevel" label="Minimum SLSA Level" type="number" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>

            <v-switch v-model="form.enforceCosign" label="Enforce Cosign signature" color="primary" density="compact" hide-details></v-switch>
            <v-switch v-model="form.requireVoucher" label="Require VBBI Voucher" color="primary" density="compact" hide-details></v-switch>
            <v-switch v-model="form.enforceSbom" label="Enforce SBOM Policy" color="primary" density="compact" hide-details></v-switch>
            <v-switch v-model="form.failOnFixable" label="Fail On Fixable Vulnerabilities" color="primary" density="compact" hide-details class="mb-3"></v-switch>

            <v-select v-model="form.maxAllowedSeverity" :items="SEVERITIES" label="Max Allowed Severity" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-select>
            <v-select v-model="form.onPolicyDrift" :items="DRIFT_ACTIONS" label="Policy Drift Action" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-select>
            <v-select v-model="form.onVulnerabilityFound" :items="VULN_ACTIONS" label="On Vulnerability Found" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-select>

            <!-- Advanced groups -->
            <v-expansion-panels multiple variant="accordion" class="mb-4">
              <v-expansion-panel title="Provenance & Manifest">
                <v-expansion-panel-text>
                  <v-switch v-model="form.enforceHmacChain" label="Enforce HMAC chain" color="primary" density="compact" hide-details></v-switch>
                  <v-switch v-model="form.runtimeEnabled" label="Runtime enforcement enabled" color="primary" density="compact" hide-details class="mb-2"></v-switch>
                  <v-switch v-model="form.strictManifestEnabled" label="Strict manifest hash" color="primary" density="compact" hide-details></v-switch>
                  <v-select v-if="form.strictManifestEnabled" v-model="form.strictManifestAction" :items="MANIFEST_ACTIONS" label="Hash mismatch action" variant="outlined" density="compact" hide-details="auto" class="mt-2 mb-3"></v-select>
                  <v-switch v-model="form.policyBindingEnabled" label="Policy binding enabled" color="primary" density="compact" hide-details></v-switch>
                  <v-text-field v-model="form.requireAttestationType" label="requireAttestationType" variant="outlined" density="compact" hide-details="auto" class="mt-2"></v-text-field>
                </v-expansion-panel-text>
              </v-expansion-panel>

              <v-expansion-panel title="Forbidden packages">
                <v-expansion-panel-text>
                  <div class="d-flex align-center mb-2">
                    <span class="text-caption text-secondary">SBOM block-list</span>
                    <v-spacer />
                    <v-btn size="x-small" variant="text" color="primary" prepend-icon="mdi-plus" @click="addPkg">Adaugă</v-btn>
                  </div>
                  <div v-for="(p, i) in form.forbiddenPackages" :key="`pkg-${i}`" class="d-flex align-center ga-2 mb-2">
                    <v-text-field v-model="p.name" label="Package" variant="outlined" density="compact" hide-details class="flex-grow-1"></v-text-field>
                    <v-text-field v-model="p.maxVersion" label="maxVersion" placeholder="optional" variant="outlined" density="compact" hide-details style="max-width: 130px"></v-text-field>
                    <v-btn size="x-small" variant="text" color="error" icon="mdi-close" @click="removePkg(i)"></v-btn>
                  </div>
                  <div v-if="!form.forbiddenPackages.length" class="text-caption text-secondary">No forbidden packages.</div>
                </v-expansion-panel-text>
              </v-expansion-panel>

              <v-expansion-panel title="SLSA provenance">
                <v-expansion-panel-text>
                  <v-switch v-model="form.enforceSlsa" label="Enforce SLSA v1.0 provenance" color="primary" density="compact" hide-details class="mb-2"></v-switch>
                  <v-text-field v-model.number="form.slsaRequiredLevel" label="requiredLevel" type="number" variant="outlined" density="compact" hide-details="auto" class="mb-3"></v-text-field>
                  <v-text-field v-model="form.slsaTrustedIssuers" label="trustedIssuers (CSV)" variant="outlined" density="compact" hide-details="auto" class="mb-3"></v-text-field>
                  <v-text-field v-model="form.slsaTrustedBuilders" label="trustedBuilders (CSV)" variant="outlined" density="compact" hide-details="auto" class="mb-3"></v-text-field>
                  <v-text-field v-model="form.slsaAllowedBuildTypes" label="allowedBuildTypes (CSV)" variant="outlined" density="compact" hide-details="auto"></v-text-field>
                </v-expansion-panel-text>
              </v-expansion-panel>

              <v-expansion-panel title="OpenVEX">
                <v-expansion-panel-text>
                  <v-switch v-model="form.enforceOpenVex" label="Enforce OpenVEX attestations" color="primary" density="compact" hide-details></v-switch>
                  <v-switch v-model="form.requireVexStatements" label="Require statements" color="primary" density="compact" hide-details></v-switch>
                </v-expansion-panel-text>
              </v-expansion-panel>

              <v-expansion-panel title="Security scan (gitleaks / checkov / semgrep)">
                <v-expansion-panel-text>
                  <v-switch v-model="form.enforceSecurityScan" label="Enforce security-scan attestation" color="primary" density="compact" hide-details></v-switch>
                  <v-switch v-model="form.requireScanAttestation" label="Require attestation present" color="primary" density="compact" hide-details></v-switch>
                  <v-switch v-model="form.failOnSecrets" label="Fail on detected secrets" color="primary" density="compact" hide-details class="mb-2"></v-switch>
                  <v-select v-model="form.maxIacSeverity" :items="SEVERITIES" label="Max IaC severity" variant="outlined" density="compact" hide-details="auto" class="mb-3"></v-select>
                  <v-select v-model="form.maxSastSeverity" :items="SEVERITIES" label="Max SAST severity" variant="outlined" density="compact" hide-details="auto"></v-select>
                </v-expansion-panel-text>
              </v-expansion-panel>

              <v-expansion-panel :title="`Custom CEL rules (${form.customRules.length})`">
                <v-expansion-panel-text>
                  <div class="d-flex align-center mb-2">
                    <span class="text-caption text-secondary">Evaluated with {voucher, image, zta, vex, sbom, securityScan}</span>
                    <v-spacer />
                    <v-btn size="x-small" variant="text" color="primary" prepend-icon="mdi-plus" @click="addRule">Adaugă</v-btn>
                  </div>
                  <div v-for="(r, i) in form.customRules" :key="`rule-${i}`" class="rule-editor mb-3">
                    <div class="d-flex align-center ga-2 mb-2">
                      <v-text-field v-model="r.name" :rules="[(v) => !!v || 'Obligatoriu']" label="Name" variant="outlined" density="compact" hide-details="auto" class="flex-grow-1"></v-text-field>
                      <v-select v-model="r.action" :items="RULE_ACTIONS" label="Action" variant="outlined" density="compact" hide-details style="max-width: 120px"></v-select>
                      <v-btn size="x-small" variant="text" color="error" icon="mdi-close" @click="removeRule(i)"></v-btn>
                    </div>
                    <v-text-field v-model="r.description" label="Description" variant="outlined" density="compact" hide-details class="mb-2"></v-text-field>
                    <v-textarea v-model="r.expression" :rules="[(v) => !!v || 'Obligatoriu']" label="CEL expression" rows="2" auto-grow variant="outlined" density="compact" hide-details="auto" class="font-mono"></v-textarea>
                  </div>
                  <div v-if="!form.customRules.length" class="text-caption text-secondary">No custom rules.</div>
                </v-expansion-panel-text>
              </v-expansion-panel>
            </v-expansion-panels>

            <v-btn :loading="isSubmitting" :disabled="!canWriteSca || !canSubmit" @click="submitScaDeclaration" color="primary" block variant="flat" elevation="0" class="text-none font-weight-medium">
              {{ !canWriteSca ? 'Necesită platform-engineer' : (isEditingSca ? 'Update Supply Chain Policy' : 'Aplică Politica Supply Chain') }}
            </v-btn>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12" md="7" lg="8">
        <v-card class="gc-border h-100" flat>
           <v-card-title class="font-weight-medium pb-2 text-warning">
            <v-icon start color="warning" class="mr-2">mdi-shield-link-variant</v-icon> Software Delivery Shield (SCA)
           </v-card-title>
           <v-card-text>
            <p class="text-caption text-secondary mb-3">Click pe o politică pentru a-i inspecta toate câmpurile, grupate ca în Vault.</p>
            <v-table density="comfortable" class="border rounded" hover>
              <thead>
                <tr class="bg-surface-variant">
                  <th class="text-left font-weight-medium">SCA Name</th>
                  <th class="text-left font-weight-medium">Target ZTA</th>
                  <th class="text-left font-weight-medium">Sancțiune/SBOM</th>
                  <th class="text-right font-weight-medium">Actions</th>
                </tr>
              </thead>
              <tbody v-if="isLoading">
                 <tr v-for="i in 3" :key="i"><td colspan="4"><v-skeleton-loader type="table-row" height="40"></v-skeleton-loader></td></tr>
              </tbody>
              <tbody v-else>
                <tr v-if="policies.length === 0">
                  <td colspan="4" class="text-center pa-4 text-caption text-secondary">Nicio regulă SCA nu operează pe acest cluster.</td>
                </tr>
                <template v-for="sca in policies" :key="sca.metadata.uid">
                  <tr
                    class="sca-row"
                    :class="{ 'sca-row--expanded': expandedScaUid === sca.metadata.uid }"
                    @click="toggleScaExpand(sca.metadata.uid)"
                  >
                    <td class="text-body-2 font-weight-medium">
                      <v-icon size="small" class="mr-1" :color="expandedScaUid === sca.metadata.uid ? 'primary' : 'secondary'">
                        {{ expandedScaUid === sca.metadata.uid ? 'mdi-chevron-down' : 'mdi-chevron-right' }}
                      </v-icon>
                      <span :class="expandedScaUid === sca.metadata.uid ? 'text-primary' : 'text-warning'">{{ sca.metadata.name }}</span>
                    </td>
                    <td class="font-mono text-caption text-secondary">{{ sca.summary.trustedRepositories.join(', ') || 'global policy' }}</td>
                    <td class="font-mono text-caption text-secondary">
                      <v-chip size="x-small" :color="sca.summary.enforceSBOM ? 'success' : 'error'" class="mr-1">SBOM</v-chip>
                      <v-chip size="x-small" :color="sca.summary.requireVoucher ? 'success' : 'warning'" class="mr-1">VBBI</v-chip>
                      <v-chip size="x-small" color="primary">{{ sca.summary.onPolicyDrift || 'Isolate' }}</v-chip>
                    </td>
                    <td class="text-right">
                       <v-btn v-if="canWriteSca" @click.stop="startEditSca(sca)" color="primary" size="small" variant="text" icon="mdi-pencil" title="Editează politica SCA"></v-btn>
                       <v-btn v-if="canWriteSca" @click.stop="revokeSca(sca.metadata.name)" color="error" size="small" variant="text" icon="mdi-delete" title="Sterge o politica SCA"></v-btn>
                    </td>
                  </tr>
                  <tr v-if="expandedScaUid === sca.metadata.uid" class="sca-describe-row">
                    <td colspan="4" class="pa-0">
                      <ScaDetailPanel :sca="sca" :bound-apps="scaAppsMap[sca.metadata.name] || []" />
                    </td>
                  </tr>
                </template>
              </tbody>
            </v-table>
           </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<style scoped>
.sca-row {
  cursor: pointer;
  transition: background 0.15s ease;
}
.sca-row:hover {
  background: rgba(var(--v-theme-on-surface), 0.04);
}
.sca-row--expanded {
  background: rgba(var(--v-theme-primary), 0.06);
}
.sca-describe-row td {
  border-bottom: 2px solid rgba(var(--v-theme-primary), 0.25) !important;
}
.rule-editor {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.10);
  border-radius: 8px;
  padding: 10px 12px;
  background: rgba(var(--v-theme-on-surface), 0.02);
}
</style>
