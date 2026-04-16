<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'

const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()

const isLoading = computed(() => dashboardStore.loadingSecrets)
const secrets = computed(() => dashboardStore.secrets)
const applications = computed(() => dashboardStore.applications)

const form = ref({
  name: '',
  namespace: 'default',
  applicationName: '',
  workloadName: '',
  remotePath: '',
  remoteKey: 'password',
  localKey: 'DB_PASSWORD',
  mappingType: 'EnvVar',
  mountPath: '/var/run/secrets/certs/',
  targetSecret: '',
  refreshInterval: '1m'
})
const isSubmitting = ref(false)

onMounted(() => {
  Promise.all([
    dashboardStore.fetchSecrets(true),
    dashboardStore.fetchApplications(),
  ]).catch(() => undefined)
})

async function submitSecretDeclaration() {
  isSubmitting.value = true
  try {
    const payload = {
      name: form.value.name,
      namespace: form.value.namespace,
      applicationRef: {
        name: form.value.applicationName,
        namespace: form.value.namespace,
      },
      targetWorkload: {
        kind: 'Deployment',
        name: form.value.workloadName,
        namespace: form.value.namespace,
      },
      secretStoreRef: {
        kind: 'ClusterSecretStore',
        name: 'vault-backend',
      },
      targetSecretName: form.value.targetSecret,
      secretData: {
        remotePath: form.value.remotePath,
        mapping: [
          {
            remoteKey: form.value.remoteKey,
            localKey: form.value.localKey,
            type: form.value.mappingType,
            mountPath: form.value.mappingType === 'VolumeMount' ? form.value.mountPath : undefined,
          },
        ],
      },
      zeroTrustConditions: {
        requireVerifiedStatus: true,
        timeBasedAccess: {
          enabled: false,
        },
      },
      lifecycle: {
        refreshInterval: form.value.refreshInterval,
        onUpdateAction: 'RollingRestart',
      },
    }
    
    await api.post('/zts/', payload)
    await dashboardStore.fetchSecrets(true)
    await dashboardStore.fetchOverview(true)
    
    notifyStore.addAlert({
      error_code: 'ZTS_CREATED_SUCCESS',
      message: `Delegația Zero-Trust Secret '${form.value.name}' generată.`,
      technical_details: `Path Vault delegat: ${form.value.remotePath}`,
      component: 'ZTS_BUILDER',
      trace_id: Math.random().toString(36).substring(2),
      action_required: 'Nu faceți nimic. Operatorul ZTA va valida imaginea, iar ESO va prelua secretul.',
      type: 'warning'
    })
    
    form.value.name = ''
    form.value.remotePath = ''
    form.value.targetSecret = ''
  } catch (err) {
  } finally {
    isSubmitting.value = false
  }
}

async function revokeZts(namespace: string, name: string) {
  try {
    await api.delete(`/zts/${namespace}/${name}`)
    await dashboardStore.fetchSecrets(true)
    await dashboardStore.fetchOverview(true)
    notifyStore.addAlert({
      error_code: 'ZTS_REVOKED_SUCCESS',
      message: `Delegația ZTS '${name}' ștearsă cu succes din sistem.`,
      technical_details: 'ESO va șterge automat TargetSecret-ul final (Garbage Collection via OwnerReferences).',
      component: 'ZTS_ADMIN',
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
    <h1 class="text-h5 font-weight-medium mb-4 text-primary">Secret Vault (ZTS Management)</h1>
    
    <v-row>
      <v-col cols="12" md="5" lg="4">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary">Delegare Vault</v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary" style="margin-bottom: 24px;">Zero-Trust Secret. Backend-ul creează CRD, operatorul confirmă, ESO trage secretul.</p>
            
            <v-text-field v-model="form.name" label="Nume CRD (ZTS)" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.namespace" label="Target Namespace" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-select v-model="form.applicationName" :items="applications.map((item: any) => item.metadata.name)" label="Application Ref" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-select>
            <v-text-field v-model="form.workloadName" label="Target Workload Name" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.remotePath" label="HashiCorp Vault Path" placeholder="secret/data/product/db" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.targetSecret" label="Mapped Kubernetes Secret" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-row>
              <v-col cols="12" md="6">
                <v-text-field v-model="form.remoteKey" label="Remote Key" variant="outlined" density="compact" hide-details="auto"></v-text-field>
              </v-col>
              <v-col cols="12" md="6">
                <v-text-field v-model="form.localKey" label="Local Key" variant="outlined" density="compact" hide-details="auto"></v-text-field>
              </v-col>
            </v-row>
            <v-select v-model="form.mappingType" :items="['EnvVar', 'VolumeMount']" label="Mapping Type" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-select>
            <v-text-field v-if="form.mappingType === 'VolumeMount'" v-model="form.mountPath" label="Mount Path" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.refreshInterval" label="Refresh Interval" placeholder="ex. 1m, 10m" variant="outlined" density="compact" hide-details="auto"></v-text-field>
            
            <v-btn :loading="isSubmitting" @click="submitSecretDeclaration" color="primary" block variant="flat" elevation="0" class="mt-6 text-none font-weight-medium">Authorize ESO Pull</v-btn>
          </v-card-text>
        </v-card>
      </v-col>
      
      <v-col cols="12" md="7" lg="8">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
           <v-card-title class="font-weight-medium pb-2 text-error">
            <v-icon start color="error" class="mr-2">mdi-lock-pattern</v-icon> Secret Manager Vault Delegations
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
                  <td class="font-mono text-caption text-secondary">{{ zts.spec.secretData?.remotePath }} -> {{ zts.summary.targetSecretName }}</td>
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