<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'

const notifyStore = useNotificationStore()

const isLoading = ref(false)
const policies = ref<any[]>([])

const form = ref({
  name: '',
  ztaName: '',
  ztaNamespace: 'default',
  trustedIssuers: '',
  enforceSbom: true,
  onPolicyDrift: 'Isolate'
})

const isSubmitting = ref(false)

async function fetchPolicies() {
  isLoading.value = true
  try {
    const res = await api.get('/sca/')
    policies.value = res.data
  } catch (err) {
    // Tratate global prin Axios Interceptor. Tot aici aruncam toast
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  fetchPolicies()
})

async function submitScaDeclaration() {
  isSubmitting.value = true
  try {
    const issuersArray = form.value.trustedIssuers.split(',').map(s => s.trim()).filter(s => s.length > 0)
    
    const payload = {
      name: form.value.name,
      zta_name: form.value.ztaName,
      zta_namespace: form.value.ztaNamespace,
      trusted_issuers: issuersArray,
      enforce_sbom: form.value.enforceSbom,
      on_policy_drift: form.value.onPolicyDrift
    }
    
    await api.post('/sca/', payload)
    
    notifyStore.addAlert({
      error_code: 'SCA_CREATED_SUCCESS',
      message: `Rețeaua de încredere (SCA) '${form.value.name}' a fost implementată.`,
      technical_details: `ZTA Vizat: ${form.value.ztaName}`,
      component: 'SUPPLY_CHAIN_BUILDER',
      trace_id: Math.random().toString(36).substring(2),
      action_required: `Operatorul va monitoriza container-ul contra vulnerabilităților și va forța regulile din sancțiunea ${form.value.onPolicyDrift}.`,
      type: 'warning'
    })
    
    form.value.name = ''
    form.value.ztaName = ''
    form.value.trustedIssuers = ''
    
    fetchPolicies()
  } catch (err) {
    // Interceptor catches standard backend K8s errors gracefully. 
  } finally {
    isSubmitting.value = false
  }
}

async function revokeSca(name: string) {
  try {
    await api.delete(`/sca/${name}`)
    notifyStore.addAlert({
      error_code: 'SCA_REVOKED_SUCCESS',
      message: `Politica '${name}' a fost invalidată cu succes.`,
      technical_details: 'Rețeaua ZTA va funcționa acum fără validare semnătură Cosign / SBOM.',
      component: 'SUPPLY_CHAIN_ADMIN',
      trace_id: Math.random().toString(36).substring(2),
      action_required: '',
      type: 'warning'
    })
    fetchPolicies()
  } catch (err) {
    // Caught by interceptor
  }
}
</script>

<template>
  <div>
    <h1 class="text-h5 font-weight-medium mb-4 text-primary">Supply Chain Attestation</h1>
    
    <v-row>
      <v-col cols="12" md="5" lg="4">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary">Configurare Securitate Pipeline</v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary" style="margin-bottom: 24px;">Adăugați o regulă NW pentru verificarea semnăturilor Cosign și a facturilor SBOM ale imaginilor OCI, controlând starea de drift.</p>
            
            <v-text-field v-model="form.name" label="Nume Politică SCA" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.ztaName" label="ZTA Target Name (Aplicația)" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.ztaNamespace" label="Sistem Target Namespace" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.trustedIssuers" label="Trusted Issuers (separate prin virgula)" placeholder="ghcr.io/org, https://token.actions.githubusercontent.com" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            
            <div class="d-flex mb-2">
               <v-switch v-model="form.enforceSbom" label="Enforce SBOM Policy" color="primary" density="compact" hide-details></v-switch>
            </div>
            
            <v-select
              v-model="form.onPolicyDrift"
              :items="['Alert', 'Isolate', 'Kill']"
              label="Policy Drift Action"
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
                <tr v-for="sca in policies" :key="sca.metadata.uid">
                  <td class="text-body-2 font-weight-medium text-warning">{{ sca.metadata.name }}</td>
                  <td class="font-mono text-caption text-secondary">{{ sca.spec.target.ztaNamespace }}/{{ sca.spec.target.ztaName }}</td>
                  <td class="font-mono text-caption text-secondary">
                     <v-chip size="x-small" :color="sca.spec.sbomPolicy?.enforceSBOM ? 'success' : 'error'" class="mr-1">SBOM</v-chip>
                     <v-chip size="x-small" color="primary">{{ sca.spec.runtimeEnforcement?.onPolicyDrift || 'Isolate' }}</v-chip>
                  </td>
                  <td class="text-right">
                     <v-btn @click="revokeSca(sca.metadata.name)" color="error" size="small" variant="text" icon="mdi-delete" title="Sterge o politica SCA"></v-btn>
                  </td>
                </tr>
              </tbody>
            </v-table>
           </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>