<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'
import { useAuthStore } from '../store/auth'
import ScaDetailPanel from '../components/sca/ScaDetailPanel.vue'

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
function boundApps(sca: any) {
  const name = sca?.metadata?.name
  return applications.value.filter((app) => app.summary?.securityPolicyRef === name)
}

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

            <v-btn :loading="isSubmitting" :disabled="!canWriteSca" @click="submitScaDeclaration" color="primary" block variant="flat" elevation="0" class="mt-4 text-none font-weight-medium">
              {{ canWriteSca ? 'Aplică Politica Supply Chain' : 'Necesită platform-engineer' }}
            </v-btn>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12" md="7" lg="8">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
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
                       <v-btn v-if="canWriteSca" @click.stop="revokeSca(sca.metadata.name)" color="error" size="small" variant="text" icon="mdi-delete" title="Sterge o politica SCA"></v-btn>
                    </td>
                  </tr>
                  <tr v-if="expandedScaUid === sca.metadata.uid" class="sca-describe-row">
                    <td colspan="4" class="pa-0">
                      <ScaDetailPanel :sca="sca" :bound-apps="boundApps(sca)" />
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
</style>
