<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'
import { useAuthStore } from '../store/auth'

const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()
const auth = useAuthStore()
const canWriteSecrets = computed(() => auth.can('secrets:write'))

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
const expandedZtsUid = ref<string | null>(null)

function toggleZtsExpand(uid: string) {
  expandedZtsUid.value = expandedZtsUid.value === uid ? null : uid
}

// Maps the operator-computed ZTS phase to a neutral status chip. The phase now
// reflects real cluster state (ExternalSecret synced + Secret present + trust),
// not a blind "Running".
function phaseColor(phase?: string): string {
  switch (phase) {
    case 'Running': return 'success'
    case 'Provisioning':
    case 'Validating': return 'info'
    case 'Degraded': return 'warning'
    case 'BlockedBySecurity': return 'error'
    default: return 'secondary'
  }
}
function phaseIcon(phase?: string): string {
  switch (phase) {
    case 'Running': return 'mdi-check-circle-outline'
    case 'Provisioning':
    case 'Validating': return 'mdi-progress-clock'
    case 'Degraded': return 'mdi-alert-outline'
    case 'BlockedBySecurity': return 'mdi-shield-lock-outline'
    default: return 'mdi-help-circle-outline'
  }
}
function conditionColor(status?: string): string {
  if (status === 'True') return 'success'
  if (status === 'False') return 'error'
  return 'secondary'
}

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
            <v-row class="mb-4">
              <v-col cols="12" md="6">
                <v-text-field v-model="form.remoteKey" label="Remote Key" variant="outlined" density="compact" hide-details="auto"></v-text-field>
              </v-col>
              <v-col cols="12" md="6">
                <v-text-field v-model="form.localKey" label="Local Key" variant="outlined" density="compact" hide-details="auto"></v-text-field>
              </v-col>
            </v-row>
            <v-select v-model="form.mappingType" :items="['EnvVar', 'VolumeMount']" label="Mapping Type" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-select>
            <v-text-field v-if="form.mappingType === 'VolumeMount'" v-model="form.mountPath" label="Mount Path" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.refreshInterval" label="Refresh Interval" placeholder="ex. 1m, 10m" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            
            <v-btn :loading="isSubmitting" :disabled="!canWriteSecrets" @click="submitSecretDeclaration" color="primary" block variant="flat" elevation="0" class="mt-6 text-none font-weight-medium">
              {{ canWriteSecrets ? 'Authorize ESO Pull' : 'Necesită platform-engineer' }}
            </v-btn>
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
                  <th class="text-left font-weight-medium">Status</th>
                  <th class="text-right font-weight-medium">Actions</th>
                </tr>
              </thead>
              <tbody v-if="isLoading">
                 <tr v-for="i in 3" :key="i"><td colspan="5"><v-skeleton-loader type="table-row" height="40"></v-skeleton-loader></td></tr>
              </tbody>
              <tbody v-else>
                <tr v-if="secrets.length === 0">
                  <td colspan="5" class="text-center pa-4 text-caption text-secondary">Nicio regulă Zero Trust Secret declarată</td>
                </tr>
                <template v-for="zts in secrets" :key="zts.metadata.uid">
                  <tr
                    class="zts-row"
                    :class="{ 'zts-row--expanded': expandedZtsUid === zts.metadata.uid }"
                    @click="toggleZtsExpand(zts.metadata.uid)"
                  >
                    <td class="text-body-2 font-weight-medium">
                      <v-icon size="small" class="mr-1" :color="expandedZtsUid === zts.metadata.uid ? 'primary' : 'secondary'">
                        {{ expandedZtsUid === zts.metadata.uid ? 'mdi-chevron-down' : 'mdi-chevron-right' }}
                      </v-icon>
                      {{ zts.metadata.name }}
                    </td>
                    <td class="font-mono text-caption text-secondary">{{ zts.metadata.namespace }}</td>
                    <td class="font-mono text-caption text-secondary">{{ zts.spec.secretData?.remotePath }} → {{ zts.summary.targetSecretName }}</td>
                    <td>
                      <v-chip
                        :color="phaseColor(zts.summary?.phase)"
                        size="small"
                        variant="tonal"
                        :prepend-icon="phaseIcon(zts.summary?.phase)"
                        class="font-weight-medium"
                      >
                        {{ zts.summary?.phase || 'Pending' }}
                      </v-chip>
                    </td>
                    <td class="text-right">
                      <v-btn v-if="canWriteSecrets" @click.stop="revokeZts(zts.metadata.namespace, zts.metadata.name)" color="error" size="small" variant="text" icon="mdi-delete" title="Sterge delegarea ZTS"></v-btn>
                    </td>
                  </tr>
                  <tr v-if="expandedZtsUid === zts.metadata.uid" class="zts-describe-row">
                    <td colspan="5" class="pa-0">
                      <div class="zts-describe-panel">

                        <!-- Header -->
                        <div class="describe-header">
                          <v-icon size="16" color="secondary" class="mr-2">mdi-file-search-outline</v-icon>
                          <span class="text-body-2 font-weight-medium">{{ zts.metadata.name }}</span>
                          <span class="text-caption text-secondary ml-2">· ZeroTrustSecret</span>
                        </div>

                        <!-- Status (real cluster state: trust + ESO sync + Secret presence) -->
                        <div class="describe-section">
                          <div class="describe-section-title">Status</div>
                          <div class="d-flex align-center flex-wrap mb-1" style="gap: 8px;">
                            <v-chip :color="phaseColor(zts.summary?.phase)" size="small" variant="tonal" :prepend-icon="phaseIcon(zts.summary?.phase)" class="font-weight-medium">
                              {{ zts.summary?.phase || 'Pending' }}
                            </v-chip>
                            <span v-if="zts.summary?.lastError" class="text-caption" style="color: rgb(var(--v-theme-warning)); word-break: break-word;">
                              {{ zts.summary.lastError }}
                            </span>
                          </div>
                          <div v-if="zts.summary?.conditions?.length" class="mt-2">
                            <div v-for="(c, i) in zts.summary.conditions" :key="i" class="zts-condition-row">
                              <v-icon size="13" :color="conditionColor(c.status)" class="mr-1">
                                {{ c.status === 'True' ? 'mdi-check-circle' : 'mdi-close-circle' }}
                              </v-icon>
                              <span class="zc-type">{{ c.type }}</span>
                              <span class="zc-reason">{{ c.reason }}</span>
                              <span v-if="c.message" class="zc-message text-secondary">{{ c.message }}</span>
                            </div>
                          </div>
                        </div>

                        <!-- Identity -->
                        <div class="describe-section">
                          <div class="describe-section-title">Identity</div>
                          <div class="describe-fields-grid">
                            <div class="describe-field">
                              <span class="df-label">name</span>
                              <span class="df-value">{{ zts.metadata.name }}</span>
                            </div>
                            <div class="describe-field">
                              <span class="df-label">namespace</span>
                              <span class="df-value">{{ zts.metadata.namespace }}</span>
                            </div>
                            <div class="describe-field">
                              <span class="df-label">uid</span>
                              <span class="df-value text-secondary" style="font-size:0.72rem;">{{ zts.metadata.uid || '—' }}</span>
                            </div>
                          </div>
                        </div>

                        <!-- References -->
                        <div class="describe-section">
                          <div class="describe-section-title">References</div>
                          <div class="describe-fields-grid">
                            <div class="describe-field">
                              <span class="df-label">applicationRef</span>
                              <span class="df-value">{{ zts.spec.applicationRef?.name || '—' }}<span class="text-secondary">/{{ zts.spec.applicationRef?.namespace || '—' }}</span></span>
                            </div>
                            <div class="describe-field">
                              <span class="df-label">targetWorkload</span>
                              <span class="df-value">{{ zts.spec.targetWorkload?.kind || 'Deployment' }}<span class="text-secondary">/{{ zts.spec.targetWorkload?.name || '—' }}</span></span>
                            </div>
                            <div class="describe-field">
                              <span class="df-label">secretStore</span>
                              <span class="df-value">{{ zts.spec.secretStoreRef?.kind || 'ClusterSecretStore' }}<span class="text-secondary">/{{ zts.spec.secretStoreRef?.name || '—' }}</span></span>
                            </div>
                          </div>
                        </div>

                        <!-- Secret Data -->
                        <div class="describe-section">
                          <div class="describe-section-title">Secret Data</div>
                          <div class="describe-fields-grid">
                            <div class="describe-field">
                              <span class="df-label">remotePath</span>
                              <span class="df-value">{{ zts.spec.secretData?.remotePath || '—' }}</span>
                            </div>
                            <div class="describe-field">
                              <span class="df-label">targetSecret</span>
                              <span class="df-value">{{ zts.summary?.targetSecretName || '—' }}</span>
                            </div>
                            <div class="describe-field">
                              <span class="df-label">refreshInterval</span>
                              <span class="df-value">{{ zts.spec.lifecycle?.refreshInterval || '—' }}</span>
                            </div>
                            <div class="describe-field">
                              <span class="df-label">onUpdateAction</span>
                              <span class="df-value">{{ zts.spec.lifecycle?.onUpdateAction || '—' }}</span>
                            </div>
                          </div>
                          <div v-if="zts.spec.secretData?.mapping?.length" class="mt-2">
                            <div class="df-label mb-1">mappings</div>
                            <div v-for="(m, i) in zts.spec.secretData.mapping" :key="i" class="describe-mapping-row">
                              <span class="dm-remote">{{ m.remoteKey }}</span>
                              <v-icon size="12" class="mx-1 text-secondary">mdi-arrow-right</v-icon>
                              <span class="dm-local">{{ m.localKey }}</span>
                              <span class="dm-type">{{ m.type }}</span>
                              <span v-if="m.mountPath" class="dm-mount text-secondary">{{ m.mountPath }}</span>
                            </div>
                          </div>
                        </div>

                        <!-- Zero-Trust Conditions -->
                        <div v-if="zts.spec.zeroTrustConditions" class="describe-section">
                          <div class="describe-section-title">Zero-Trust Conditions</div>
                          <div class="describe-fields-grid">
                            <div class="describe-field">
                              <span class="df-label">requireVerifiedStatus</span>
                              <span :class="zts.spec.zeroTrustConditions.requireVerifiedStatus ? 'df-value-ok' : 'df-value-warn'">
                                {{ zts.spec.zeroTrustConditions.requireVerifiedStatus ? 'true' : 'false' }}
                              </span>
                            </div>
                            <div class="describe-field">
                              <span class="df-label">timeBasedAccess</span>
                              <span :class="zts.spec.zeroTrustConditions.timeBasedAccess?.enabled ? 'df-value-ok' : 'df-value-secondary'">
                                {{ zts.spec.zeroTrustConditions.timeBasedAccess?.enabled ? 'enabled' : 'disabled' }}
                              </span>
                            </div>
                          </div>
                        </div>

                      </div>
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
.zts-row {
  cursor: pointer;
  transition: background 0.15s ease;
}

.zts-row:hover {
  background: rgba(var(--v-theme-on-surface), 0.04);
}

.zts-row--expanded {
  background: rgba(var(--v-theme-primary), 0.06);
}

.zts-describe-row td {
  border-bottom: 2px solid rgba(var(--v-theme-primary), 0.25) !important;
}

.zts-describe-panel {
  padding: 16px 20px 20px;
  background: rgba(var(--v-theme-surface), 1);
  border-top: 1px solid rgba(var(--v-theme-on-surface), 0.07);
}

.describe-header {
  display: flex;
  align-items: center;
  padding: 0 0 12px 0;
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.08);
  margin-bottom: 0;
}

.describe-section {
  padding: 12px 0;
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.06);
}

.describe-section:last-child {
  border-bottom: none;
  padding-bottom: 0;
}

.describe-section-title {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: rgba(var(--v-theme-on-surface), 0.38);
  margin-bottom: 8px;
}

.describe-fields-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 8px;
}

.describe-field {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.df-label {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.7rem;
  color: rgba(var(--v-theme-on-surface), 0.45);
}

.df-value {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.8rem;
  color: rgba(var(--v-theme-on-surface), 0.88);
  word-break: break-all;
}

.df-value-ok {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.8rem;
  color: rgb(var(--v-theme-success));
}

.df-value-warn {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.8rem;
  color: rgb(var(--v-theme-warning));
}

.df-value-secondary {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.8rem;
  color: rgba(var(--v-theme-on-surface), 0.45);
}

.describe-mapping-row {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 10px;
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
  border-radius: 6px;
  background: rgba(var(--v-theme-on-surface), 0.02);
  font-family: 'Roboto Mono', monospace;
  font-size: 0.78rem;
  margin-bottom: 4px;
}

.zts-condition-row {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 3px 0;
  font-family: 'Roboto Mono', monospace;
  font-size: 0.74rem;
}
.zc-type {
  font-weight: 600;
  color: rgba(var(--v-theme-on-surface), 0.85);
  min-width: 64px;
}
.zc-reason {
  padding: 1px 6px;
  border-radius: 4px;
  background: rgba(var(--v-theme-on-surface), 0.07);
  color: rgba(var(--v-theme-on-surface), 0.6);
  font-size: 0.68rem;
}
.zc-message {
  font-size: 0.7rem;
  word-break: break-word;
}

.dm-remote { color: rgba(var(--v-theme-on-surface), 0.75); }
.dm-local  { color: rgba(var(--v-theme-on-surface), 0.88); font-weight: 500; }
.dm-type   {
  font-size: 0.68rem;
  padding: 1px 6px;
  border-radius: 4px;
  background: rgba(var(--v-theme-on-surface), 0.07);
  color: rgba(var(--v-theme-on-surface), 0.55);
  margin-left: 4px;
}
.dm-mount  { font-size: 0.72rem; margin-left: 4px; }
</style>