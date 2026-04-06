<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'

const notifyStore = useNotificationStore()

const isLoading = ref(false)
const secrets = ref<any[]>([])

const form = ref({
  name: '',
  namespace: 'default',
  vaultPath: '',
  targetSecret: '',
  rotationInterval: '1h'
})
const isSubmitting = ref(false)

async function fetchSecrets() {
  isLoading.value = true
  try {
    const res = await api.get('/zts/')
    secrets.value = res.data
  } catch (err) {
    // Tratate global prin Axios Interceptor. Tot aici aruncam toast
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  fetchSecrets()
})

async function submitSecretDeclaration() {
  isSubmitting.value = true
  try {
    const payload = {
      name: form.value.name,
      namespace: form.value.namespace,
      vault_path: form.value.vaultPath,
      target_secret: form.value.targetSecret,
      rotation_interval: form.value.rotationInterval
    }
    
    await api.post('/zts/', payload)
    
    notifyStore.addAlert({
      error_code: 'ZTS_CREATED_SUCCESS',
      message: `Delegația Zero-Trust Secret '${form.value.name}' generată.`,
      technical_details: `Path Vault delegat: ${form.value.vaultPath}`,
      component: 'ZTS_BUILDER',
      trace_id: Math.random().toString(36).substring(2),
      action_required: 'Nu faceți nimic. Operatorul ZTA va valida imaginea, iar ESO va prelua secretul.',
      type: 'warning'
    })
    
    form.value.name = ''
    form.value.vaultPath = ''
    form.value.targetSecret = ''
    
    fetchSecrets()
  } catch (err) {
    // Interceptor catches standard backend K8s errors gracefully. 
  } finally {
    isSubmitting.value = false
  }
}

async function revokeZts(namespace: string, name: string) {
  try {
    await api.delete(`/zts/${namespace}/${name}`)
    notifyStore.addAlert({
      error_code: 'ZTS_REVOKED_SUCCESS',
      message: `Delegația ZTS '${name}' ștearsă cu succes din sistem.`,
      technical_details: 'ESO va șterge automat TargetSecret-ul final (Garbage Collection via OwnerReferences).',
      component: 'ZTS_ADMIN',
      trace_id: Math.random().toString(36).substring(2),
      action_required: '',
      type: 'warning'
    })
    fetchSecrets()
  } catch (err) {
    // Caught by interceptor
  }
}
</script>

<template>
  <div>
    <h1 class="text-h5 font-weight-medium mb-4 text-primary">Secret Vault (ZTS Management)</h1>
    
    <v-row>
      <v-col cols="12" md="5" lg="4">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary">Delegare Vault</v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary" style="margin-bottom: 24px;">Zero-Trust Secret. Backend-ul creează CRD, operatorul confirmă, ESO trage secretul.</p>
            
            <v-text-field v-model="form.name" label="Nume CRD (ZTS)" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.namespace" label="Target Namespace" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.vaultPath" label="HashiCorp Vault Path" placeholder="secret/data/product/db" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.targetSecret" label="Mapped Kubernetes Secret" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.rotationInterval" label="Rotation Interval" placeholder="ex. 1h, 15m" variant="outlined" density="compact" hide-details="auto"></v-text-field>
            
            <v-btn :loading="isSubmitting" @click="submitSecretDeclaration" color="primary" block variant="flat" elevation="0" class="mt-6 text-none font-weight-medium">Authorize ESO Pull</v-btn>
          </v-card-text>
        </v-card>
      </v-col>
      
      <v-col cols="12" md="7" lg="8">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
           <v-card-title class="font-weight-medium pb-2 text-error">
            <v-icon start color="error" class="mr-2">mdi-safe</v-icon> Vault Status
           </v-card-title>
           <v-card-text>
            <v-table density="comfortable" class="border rounded" hover>
              <thead>
                <tr class="bg-surface-variant">
                  <th class="text-left font-weight-medium">ZTS Declaration</th>
                  <th class="text-left font-weight-medium">Namespace</th>
                  <th class="text-left font-weight-medium">Source / Path</th>
                  <th class="text-right font-weight-medium">Actions</th>
                </tr>
              </thead>
              <tbody v-if="isLoading">
                 <tr v-for="i in 3" :key="i"><td colspan="4"><v-skeleton-loader type="table-row" height="40"></v-skeleton-loader></td></tr>
              </tbody>
              <tbody v-else>
                <tr v-if="secrets.length === 0">
                  <td colspan="4" class="text-center pa-4 text-caption text-secondary">Nicio regulă Zero Trust Secret declarată</td>
                </tr>
                <tr v-for="zts in secrets" :key="zts.metadata.uid">
                  <td class="text-body-2 font-weight-medium">{{ zts.metadata.name }}</td>
                  <td class="font-mono text-caption text-secondary">{{ zts.metadata.namespace }}</td>
                  <td class="font-mono text-caption text-secondary">{{ zts.spec.vaultPath }} -> {{ zts.spec.targetSecretName }}</td>
                  <td class="text-right">
                     <v-btn @click="revokeZts(zts.metadata.namespace, zts.metadata.name)" color="error" size="small" variant="text" icon="mdi-delete" title="Sterge delegarea ZTS"></v-btn>
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