<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'

const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()

const isLoading = computed(() => dashboardStore.loadingPolicies)
const policies = computed(() => dashboardStore.policies)
const applications = computed(() => dashboardStore.applications)
const selectedPolicy = ref('')

const form = ref({
  name: '',
  trustedIssuers: '',
  trustedRepositories: '',
  minSlsaLevel: 3,
  maxAllowedSeverity: 'High',
  failOnFixable: true,
  requireVoucher: true,
  enforceSbom: true,
  onPolicyDrift: 'Isolate',
  onVulnerabilityFound: 'Alert'
})

const isSubmitting = ref(false)

onMounted(() => {
  dashboardStore.fetchPolicies(true).catch(() => undefined)
  dashboardStore.fetchApplications(true).catch(() => undefined)
})

const selectedPolicyObject = computed(() => policies.value.find((item) => item.metadata?.name === selectedPolicy.value) || null)
const appsBoundToSelectedPolicy = computed(() => {
  if (!selectedPolicy.value) return []
  return applications.value.filter((app) => app.summary?.securityPolicyRef === selectedPolicy.value)
})
const selectedPolicyCoverage = computed(() => {
  const policy = selectedPolicyObject.value
  const boundApps = appsBoundToSelectedPolicy.value
  const verifiedApps = boundApps.filter((app) => app.summary?.trustLevel === 'Verified')
  const degradedApps = boundApps.filter((app) => app.summary?.securityState && app.summary?.securityState !== 'Compliant')
  const alertApps = boundApps.filter((app) => app.summary?.securityState === 'Alert')
  const compliantApps = boundApps.filter((app) => app.summary?.securityState === 'Compliant')
  return {
    applications: boundApps.length,
    verified: verifiedApps.length,
    degraded: degradedApps.length,
    alert: alertApps.length,
    compliant: compliantApps.length,
    policy,
  }
})
const selectedPolicyMatrix = computed(() => {
  const summary = selectedPolicyObject.value?.summary || {}
  return [
    { label: 'Cosign issuer enforcement', enabled: summary.enforceCosign, detail: (summary.trustedIssuers || []).join(', ') || 'No issuers defined' },
    { label: 'Voucher requirement', enabled: summary.requireVoucher, detail: `Minimum SLSA ${summary.minSlsaLevel || 0}` },
    { label: 'HMAC chain enforcement', enabled: summary.enforceHmacChain, detail: `Repositories: ${(summary.trustedRepositories || []).join(', ') || 'any'}` },
    { label: 'SBOM enforcement', enabled: summary.enforceSBOM, detail: `Forbidden packages: ${(summary.forbiddenPackages || []).join(', ') || 'none'}` },
    { label: 'Runtime drift action', enabled: true, detail: summary.onPolicyDrift || 'Isolate' },
    { label: 'Vulnerability action', enabled: true, detail: `${summary.maxAllowedSeverity || 'High'} / ${summary.onVulnerabilityFound || 'Alert'}` },
  ]
})

const selectedPolicyFields = computed(() => {
  const policy = selectedPolicyObject.value
  if (!policy) return []

  const summary = policy.summary || {}
  const spec = policy.spec || {}
  const metadata = policy.metadata || {}

  const rows = [
    {
      key: 'metadata.name',
      label: 'Policy Name',
      value: metadata.name || 'n/a',
      description: 'Unique policy identifier used by ZeroTrustApplication.securityPolicyRef.name to bind workloads.',
    },
    {
      key: 'metadata.namespace',
      label: 'Namespace Scope',
      value: metadata.namespace || 'cluster-scope (default behavior)',
      description: 'Namespace where this policy object is stored and resolved during policy matching.',
    },
    {
      key: 'sourceValidation.enforceCosign',
      label: 'Cosign Enforcement',
      value: String(summary.enforceCosign ?? spec.sourceValidation?.enforceCosign ?? false),
      description: 'When true, image signatures are validated against trusted issuer identities before admission.',
    },
    {
      key: 'sourceValidation.trustedIssuers',
      label: 'Trusted Issuers',
      value: (summary.trustedIssuers || spec.sourceValidation?.trustedIssuers || []).join(', ') || 'none',
      description: 'OIDC issuers or CI identities allowed to sign container artifacts for this policy.',
    },
    {
      key: 'provenance.requireVoucher',
      label: 'Require VBBI Voucher',
      value: String(summary.requireVoucher ?? spec.provenance?.requireVoucher ?? false),
      description: 'Requires provenance voucher (attestation) so build origin and delivery chain are cryptographically provable.',
    },
    {
      key: 'provenance.minSlsaLevel',
      label: 'Minimum SLSA Level',
      value: String(summary.minSlsaLevel ?? spec.provenance?.minSlsaLevel ?? 0),
      description: 'Minimum software supply-chain maturity level required for the attested build process.',
    },
    {
      key: 'provenance.enforceHmacChain',
      label: 'HMAC Chain Enforcement',
      value: String(summary.enforceHmacChain ?? spec.provenance?.enforceHmacChain ?? false),
      description: 'Validates each provenance step hash/HMAC chain to ensure no tampering between pipeline stages.',
    },
    {
      key: 'provenance.trustedRepositories',
      label: 'Trusted Repositories',
      value: (summary.trustedRepositories || spec.provenance?.trustedRepositories || []).join(', ') || 'none',
      description: 'Only these source repositories are considered valid origin for workload artifacts.',
    },
    {
      key: 'sbomPolicy.enforceSBOM',
      label: 'SBOM Enforcement',
      value: String(summary.enforceSBOM ?? spec.sbomPolicy?.enforceSBOM ?? false),
      description: 'Requires Software Bill of Materials presence and validates package constraints from policy.',
    },
    {
      key: 'sbomPolicy.forbiddenPackages',
      label: 'Forbidden Packages',
      value: (summary.forbiddenPackages || spec.sbomPolicy?.forbiddenPackages || []).join(', ') || 'none',
      description: 'Package names (optionally version-bounded) that are disallowed in workloads under this policy.',
    },
    {
      key: 'vulnerabilityPolicy.maxAllowedSeverity',
      label: 'Max Allowed Severity',
      value: summary.maxAllowedSeverity || spec.vulnerabilityPolicy?.maxAllowedSeverity || 'n/a',
      description: 'Highest vulnerability severity tolerated before policy action is triggered.',
    },
    {
      key: 'vulnerabilityPolicy.failOnFixable',
      label: 'Fail On Fixable',
      value: String(summary.failOnFixable ?? spec.vulnerabilityPolicy?.failOnFixable ?? false),
      description: 'If true, fixable vulnerabilities trigger policy failure even if severity threshold is not exceeded.',
    },
    {
      key: 'runtimeEnforcement.onPolicyDrift',
      label: 'Policy Drift Action',
      value: summary.onPolicyDrift || spec.runtimeEnforcement?.onPolicyDrift || 'n/a',
      description: 'Action applied when runtime state drifts from declared policy (for example Alert, Isolate, Kill).',
    },
    {
      key: 'runtimeEnforcement.onVulnerabilityFound',
      label: 'Vulnerability Action',
      value: summary.onVulnerabilityFound || spec.runtimeEnforcement?.onVulnerabilityFound || 'n/a',
      description: 'Action applied when vulnerability controls are violated during verification.',
    },
    {
      key: 'strictManifestHash.enabled',
      label: 'Strict Manifest Hash',
      value: String(spec.strictManifestHash?.enabled ?? false),
      description: 'Enforces manifest hash integrity so deployed runtime spec must match attested expected hash.',
    },
    {
      key: 'strictManifestHash.enforcementAction',
      label: 'Hash Enforcement Action',
      value: spec.strictManifestHash?.enforcementAction || 'n/a',
      description: 'Defines remediation behavior when expected infra hash and computed hash differ.',
    },
  ]

  return rows
})

watch(
  policies,
  (items) => {
    if (!selectedPolicy.value && items.length) {
      selectedPolicy.value = items[0].metadata?.name || ''
    }
  },
  { immediate: true },
)

function selectPolicy(name: string) {
  selectedPolicy.value = name
}

async function submitScaDeclaration() {
  isSubmitting.value = true
  try {
    const issuersArray = form.value.trustedIssuers.split(',').map(s => s.trim()).filter(s => s.length > 0)
    const repositories = form.value.trustedRepositories.split(',').map(s => s.trim()).filter(s => s.length > 0)
    
    const payload = {
      name: form.value.name,
      sourceValidation: {
        enforceCosign: true,
        trustedIssuers: issuersArray,
      },
      provenance: {
        requireVoucher: form.value.requireVoucher,
        enforceHmacChain: true,
        minSlsaLevel: form.value.minSlsaLevel,
        trustedRepositories: repositories,
      },
      vulnerabilityPolicy: {
        maxAllowedSeverity: form.value.maxAllowedSeverity,
        failOnFixable: form.value.failOnFixable,
      },
      sbomPolicy: {
        enforceSBOM: form.value.enforceSbom,
        forbiddenPackages: [],
      },
      policyBinding: {
        enabled: true,
        requireAttestationType: 'https://devsecops.licenta.ro/attestations/custom-zta-policy/v1',
      },
      strictManifestHash: {
        enabled: true,
        enforcementAction: 'Reject',
      },
      runtimeEnforcement: {
        enabled: true,
        onPolicyDrift: form.value.onPolicyDrift,
        onVulnerabilityFound: form.value.onVulnerabilityFound,
      },
    }
    
    await api.post('/sca/', payload)
    await dashboardStore.fetchPolicies(true)
    await dashboardStore.fetchOverview(true)
    
    notifyStore.addAlert({
      error_code: 'SCA_CREATED_SUCCESS',
      message: `Rețeaua de încredere (SCA) '${form.value.name}' a fost implementată.`,
      technical_details: `Trusted issuers: ${issuersArray.join(', ')}`,
      component: 'SUPPLY_CHAIN_BUILDER',
      trace_id: Math.random().toString(36).substring(2),
      action_required: `Operatorul va monitoriza container-ul contra vulnerabilităților și va forța regulile din sancțiunea ${form.value.onPolicyDrift}.`,
      type: 'warning'
    })
    
    form.value.name = ''
    form.value.trustedIssuers = ''
  } catch (err) {
  } finally {
    isSubmitting.value = false
  }
}

async function revokeSca(name: string) {
  try {
    await api.delete(`/sca/${name}`)
    await dashboardStore.fetchPolicies(true)
    await dashboardStore.fetchOverview(true)
    notifyStore.addAlert({
      error_code: 'SCA_REVOKED_SUCCESS',
      message: `Politica '${name}' a fost invalidată cu succes.`,
      technical_details: 'Rețeaua ZTA va funcționa acum fără validare semnătură Cosign / SBOM.',
      component: 'SUPPLY_CHAIN_ADMIN',
      trace_id: Math.random().toString(36).substring(2),
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
      <v-select
        v-model="selectedPolicy"
        :items="dashboardStore.policyOptions"
        label="Inspect policy impact"
        variant="outlined"
        density="compact"
        hide-details
        style="max-width: 320px"
      ></v-select>
    </div>
    
    <v-row>
      <v-col cols="12" md="5" lg="4">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary">Configurare Securitate Pipeline</v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary" style="margin-bottom: 24px;">Adăugați o regulă NW pentru verificarea semnăturilor Cosign și a facturilor SBOM ale imaginilor OCI, controlând starea de drift.</p>
            
            <v-text-field v-model="form.name" label="Nume Politică SCA" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.trustedIssuers" label="Trusted Issuers (separate prin virgula)" placeholder="ghcr.io/org, https://token.actions.githubusercontent.com" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.trustedRepositories" label="Trusted Repositories" placeholder="owner/repo, owner/repo-2" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.minSlsaLevel" label="Minimum SLSA Level" type="number" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            
            <div class="d-flex mb-2">
               <v-switch v-model="form.enforceSbom" label="Enforce SBOM Policy" color="primary" density="compact" hide-details></v-switch>
            </div>
            <div class="d-flex mb-2">
              <v-switch v-model="form.requireVoucher" label="Require VBBI Voucher" color="primary" density="compact" hide-details></v-switch>
            </div>
            <div class="d-flex mb-2">
              <v-switch v-model="form.failOnFixable" label="Fail On Fixable Vulnerabilities" color="primary" density="compact" hide-details></v-switch>
            </div>
            <v-select
              v-model="form.maxAllowedSeverity"
              :items="['Low', 'Medium', 'High', 'Critical']"
              label="Max Allowed Severity"
              variant="outlined"
              density="compact"
              hide-details="auto"
              class="mb-4"
            ></v-select>
            
            <v-select
              v-model="form.onPolicyDrift"
              :items="['Alert', 'Isolate', 'Kill']"
              label="Policy Drift Action"
              variant="outlined"
              density="compact"
              hide-details="auto"
              class="mb-4"
            ></v-select>
            <v-select
              v-model="form.onVulnerabilityFound"
              :items="['Alert', 'Kill']"
              label="On Vulnerability Found"
              variant="outlined"
              density="compact"
              hide-details="auto"
              class="mb-4"
            ></v-select>
            
            <v-btn :loading="isSubmitting" @click="submitScaDeclaration" color="primary" block variant="flat" elevation="0" class="mt-4 text-none font-weight-medium">Aplică Politica Supply Chain</v-btn>
          </v-card-text>
        </v-card>
      </v-col>
      
      <v-col cols="12" md="7" lg="8">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
           <v-card-title class="font-weight-medium pb-2 text-warning">
            <v-icon start color="warning" class="mr-2">mdi-shield-link-variant</v-icon> Software Delivery Shield (SCA)
           </v-card-title>
           <v-card-text>
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
                <tr v-for="sca in policies" :key="sca.metadata.uid" class="sca-row" @click="selectPolicy(sca.metadata.name)">
                  <td class="text-body-2 font-weight-medium text-warning">{{ sca.metadata.name }}</td>
                  <td class="font-mono text-caption text-secondary">{{ sca.summary.trustedRepositories.join(', ') || 'global policy' }}</td>
                  <td class="font-mono text-caption text-secondary">
                    <v-chip size="x-small" :color="sca.summary.enforceSBOM ? 'success' : 'error'" class="mr-1">SBOM</v-chip>
                    <v-chip size="x-small" :color="sca.summary.requireVoucher ? 'success' : 'warning'" class="mr-1">VBBI</v-chip>
                    <v-chip size="x-small" color="primary">{{ sca.summary.onPolicyDrift || 'Isolate' }}</v-chip>
                  </td>
                  <td class="text-right">
                     <v-btn @click.stop="revokeSca(sca.metadata.name)" color="error" size="small" variant="text" icon="mdi-delete" title="Sterge o politica SCA"></v-btn>
                  </td>
                </tr>
              </tbody>
            </v-table>
           </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row v-if="selectedPolicyObject" class="mt-2">
      <v-col cols="12" xl="5">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Policy Blast Radius</v-card-title>
          <v-card-text>
            <v-row class="mb-3">
              <v-col cols="6">
                <div class="blast-kpi">
                  <div class="text-caption text-secondary">Bound workloads</div>
                  <div class="text-h5 font-weight-bold">{{ selectedPolicyCoverage.applications }}</div>
                </div>
              </v-col>
              <v-col cols="6">
                <div class="blast-kpi">
                  <div class="text-caption text-secondary">Verified</div>
                  <div class="text-h5 font-weight-bold text-success">{{ selectedPolicyCoverage.verified }}</div>
                </div>
              </v-col>
              <v-col cols="6">
                <div class="blast-kpi">
                  <div class="text-caption text-secondary">Compliant</div>
                  <div class="text-h5 font-weight-bold text-primary">{{ selectedPolicyCoverage.compliant }}</div>
                </div>
              </v-col>
              <v-col cols="6">
                <div class="blast-kpi">
                  <div class="text-caption text-secondary">Alert/Degraded</div>
                  <div class="text-h5 font-weight-bold text-error">{{ selectedPolicyCoverage.alert }}</div>
                </div>
              </v-col>
            </v-row>

            <div class="text-caption text-secondary mb-2">Trusted issuers</div>
            <div class="d-flex flex-wrap ga-2 mb-4">
              <v-chip v-for="issuer in (selectedPolicyObject.summary?.trustedIssuers || [])" :key="issuer" size="small" color="primary" variant="tonal">
                {{ issuer }}
              </v-chip>
            </div>

            <div class="text-caption text-secondary mb-2">Impact on workloads</div>
            <v-list density="compact" class="blast-list" v-if="appsBoundToSelectedPolicy.length">
              <v-list-item v-for="app in appsBoundToSelectedPolicy" :key="app.metadata?.uid || app.metadata?.name">
                <v-list-item-title>{{ app.metadata?.namespace }}/{{ app.metadata?.name }}</v-list-item-title>
                <v-list-item-subtitle>{{ app.summary?.securityState }} • {{ app.summary?.trustLevel }}</v-list-item-subtitle>
              </v-list-item>
            </v-list>
            <div v-else class="text-caption text-secondary">No workloads currently bound to this policy.</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" xl="7">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Enforcement Matrix</v-card-title>
          <v-card-text>
            <v-row>
              <v-col v-for="rule in selectedPolicyMatrix" :key="rule.label" cols="12" md="6">
                <div class="matrix-card">
                  <v-chip :color="rule.enabled ? 'success' : 'warning'" size="small" variant="tonal" class="mb-2">
                    {{ rule.enabled ? 'enforced' : 'optional' }}
                  </v-chip>
                  <div class="text-body-2 font-weight-medium">{{ rule.label }}</div>
                  <div class="text-caption text-secondary">{{ rule.detail }}</div>
                </div>
              </v-col>
            </v-row>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Full Policy Configuration</v-card-title>
          <v-card-text>
            <v-row>
              <v-col cols="12" md="6" v-for="item in selectedPolicyFields" :key="item.key">
                <div class="matrix-card">
                  <div class="d-flex align-center ga-2 mb-1">
                    <div class="text-body-2 font-weight-medium">{{ item.label }}</div>
                    <v-tooltip location="top" max-width="380">
                      <template v-slot:activator="{ props }">
                        <v-icon v-bind="props" size="16" color="secondary">mdi-help-circle-outline</v-icon>
                      </template>
                      <span>{{ item.description }}</span>
                    </v-tooltip>
                  </div>
                  <div class="text-caption text-secondary" style="word-break: break-word;">{{ item.value }}</div>
                </div>
              </v-col>
            </v-row>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<style scoped>
.matrix-card {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 14px;
  padding: 14px;
  height: 100%;
  background: rgba(var(--v-theme-on-surface), 0.03);
}

.sca-row {
  cursor: pointer;
}

.sca-row:hover {
  background: rgba(var(--v-theme-primary), 0.06);
}

.blast-kpi {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 12px;
  padding: 12px;
  background: rgba(var(--v-theme-on-surface), 0.03);
}

.blast-list {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 12px;
}
</style>