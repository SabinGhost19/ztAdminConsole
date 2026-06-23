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

// Match the ZeroTrustSecret CRD enums exactly.
const WORKLOAD_KINDS = ['Deployment', 'StatefulSet', 'DaemonSet']
const MAPPING_TYPES = ['EnvVar', 'VolumeMount']

interface MappingRow { remoteKey: string; localKey: string; type: string; mountPath: string }

function blankMapping(): MappingRow {
  return { remoteKey: '', localKey: '', type: 'EnvVar', mountPath: '' }
}

function defaultForm() {
  return {
    name: '',
    namespace: 'default',
    applicationName: '',
    workloadKind: 'Deployment',
    workloadName: '',
    remotePath: '',
    targetSecret: '',
    mappings: [{ remoteKey: 'password', localKey: 'DB_PASSWORD', type: 'EnvVar', mountPath: '' }] as MappingRow[],
    requireVerifiedStatus: true,
    refreshInterval: '1m',
  }
}

const form = ref(defaultForm())
const isSubmitting = ref(false)
const editing = ref<{ namespace: string; name: string } | null>(null)
const isEditing = computed(() => editing.value !== null)
const expandedZtsUid = ref<string | null>(null)

const required = (v: any) => (!!v && String(v).trim().length > 0) || 'Obligatoriu'

// Client-side gating so an empty/partial declaration is never submitted (G6).
const canSubmit = computed(() => {
  const f = form.value
  if (!f.name.trim() || !f.namespace.trim() || !f.applicationName.trim()) return false
  if (!f.workloadName.trim() || !f.remotePath.trim() || !f.targetSecret.trim()) return false
  if (!f.mappings.length) return false
  return f.mappings.every((m) =>
    m.remoteKey.trim() && m.localKey.trim() && (m.type !== 'VolumeMount' || m.mountPath.trim()),
  )
})

function toggleZtsExpand(uid: string) {
  expandedZtsUid.value = expandedZtsUid.value === uid ? null : uid
}

function addMapping() { form.value.mappings.push(blankMapping()) }
function removeMapping(i: number) {
  if (form.value.mappings.length > 1) form.value.mappings.splice(i, 1)
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

onMounted(() => {
  Promise.all([
    dashboardStore.fetchSecrets(true),
    dashboardStore.fetchApplications(),
  ]).catch(() => undefined)
})

function resetForm() {
  form.value = defaultForm()
  editing.value = null
}

function startEdit(zts: any) {
  const spec = zts.spec || {}
  const mapping: MappingRow[] = (spec.secretData?.mapping || []).map((m: any) => ({
    remoteKey: m.remoteKey || '',
    localKey: m.localKey || '',
    type: m.type || 'EnvVar',
    mountPath: m.mountPath || '',
  }))
  form.value = {
    name: zts.metadata?.name || '',
    namespace: zts.metadata?.namespace || 'default',
    applicationName: spec.applicationRef?.name || '',
    workloadKind: spec.targetWorkload?.kind || 'Deployment',
    workloadName: spec.targetWorkload?.name || '',
    remotePath: spec.secretData?.remotePath || '',
    targetSecret: spec.targetSecretName || zts.summary?.targetSecretName || '',
    mappings: mapping.length ? mapping : [blankMapping()],
    requireVerifiedStatus: spec.zeroTrustConditions?.requireVerifiedStatus ?? true,
    refreshInterval: spec.lifecycle?.refreshInterval || '10m',
  }
  editing.value = { namespace: zts.metadata.namespace, name: zts.metadata.name }
  if (typeof window !== 'undefined') window.scrollTo({ top: 0, behavior: 'smooth' })
}

function buildPayload() {
  return {
    name: form.value.name,
    namespace: form.value.namespace,
    applicationRef: {
      name: form.value.applicationName,
      namespace: form.value.namespace,
    },
    targetWorkload: {
      kind: form.value.workloadKind,
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
      mapping: form.value.mappings.map((m) => ({
        remoteKey: m.remoteKey,
        localKey: m.localKey,
        type: m.type,
        mountPath: m.type === 'VolumeMount' ? m.mountPath : undefined,
      })),
    },
    zeroTrustConditions: {
      requireVerifiedStatus: form.value.requireVerifiedStatus,
      timeBasedAccess: {
        enabled: false,
      },
    },
    lifecycle: {
      refreshInterval: form.value.refreshInterval,
      onUpdateAction: 'RollingRestart',
    },
  }
}

async function submitSecretDeclaration() {
  if (!canSubmit.value) return
  isSubmitting.value = true
  try {
    const payload = buildPayload()
    const updating = isEditing.value
    if (updating && editing.value) {
      await api.put(`/zts/${editing.value.namespace}/${editing.value.name}`, payload)
    } else {
      await api.post('/zts/', payload)
    }
    await dashboardStore.fetchSecrets(true)
    await dashboardStore.fetchOverview(true)

    notifyStore.addAlert({
      error_code: updating ? 'ZTS_UPDATED_SUCCESS' : 'ZTS_CREATED_SUCCESS',
      message: updating
        ? `Delegația Zero-Trust Secret '${payload.name}' actualizată.`
        : `Delegația Zero-Trust Secret '${payload.name}' generată.`,
      technical_details: `Path Vault delegat: ${payload.secretData.remotePath}`,
      component: 'ZTS_BUILDER',
      trace_id: Math.random().toString(36).substring(2),
      action_required: 'Operatorul ZTA validează, iar ESO preia secretul din Vault.',
      type: 'warning'
    })

    resetForm()
  } catch (err) {
  } finally {
    isSubmitting.value = false
  }
}

async function revokeZts(namespace: string, name: string) {
  try {
    await api.delete(`/zts/${namespace}/${name}`)
    if (editing.value && editing.value.namespace === namespace && editing.value.name === name) {
      resetForm()
    }
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
          <v-card-title class="font-weight-medium pb-2 text-primary d-flex align-center">
            <span>{{ isEditing ? `Editează: ${editing?.name}` : 'Delegare Vault' }}</span>
            <v-spacer />
            <v-btn v-if="isEditing" size="x-small" variant="text" color="secondary" @click="resetForm">Anulează</v-btn>
          </v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary" style="margin-bottom: 16px;">
              Zero-Trust Secret: backend-ul creează CRD, operatorul confirmă, ESO trage secretul.
              Valoarea trebuie să existe deja în Vault la path-ul de mai jos.
            </p>

            <v-text-field v-model="form.name" :rules="[required]" :disabled="isEditing" label="Nume CRD (ZTS)" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-text-field v-model="form.namespace" :rules="[required]" :disabled="isEditing" label="Target Namespace" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>
            <v-select v-model="form.applicationName" :rules="[required]" :items="applications.map((item: any) => item.metadata.name)" label="Application Ref" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-select>

            <v-row dense class="mb-1">
              <v-col cols="5">
                <v-select v-model="form.workloadKind" :items="WORKLOAD_KINDS" label="Workload Kind" variant="outlined" density="compact" hide-details="auto"></v-select>
              </v-col>
              <v-col cols="7">
                <v-text-field v-model="form.workloadName" :rules="[required]" label="Workload Name" variant="outlined" density="compact" hide-details="auto"></v-text-field>
              </v-col>
            </v-row>

            <v-text-field v-model="form.remotePath" :rules="[required]" label="HashiCorp Vault Path" placeholder="secret/data/product/db" variant="outlined" density="compact" hide-details="auto" class="mt-3 mb-4"></v-text-field>
            <v-text-field v-model="form.targetSecret" :rules="[required]" label="Mapped Kubernetes Secret" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>

            <!-- Secret mappings (supports multiple keys → multiple env/volume injections) -->
            <div class="d-flex align-center mb-2">
              <span class="text-caption text-secondary font-weight-medium">Secret Mappings</span>
              <v-spacer />
              <v-btn size="x-small" variant="text" color="primary" prepend-icon="mdi-plus" @click="addMapping">Adaugă</v-btn>
            </div>
            <div v-for="(m, i) in form.mappings" :key="i" class="mapping-editor mb-3">
              <div class="d-flex align-center mb-2">
                <span class="text-caption text-secondary">Mapping #{{ i + 1 }}</span>
                <v-spacer />
                <v-btn v-if="form.mappings.length > 1" size="x-small" variant="text" color="error" icon="mdi-close" title="Elimină maparea" @click="removeMapping(i)"></v-btn>
              </div>
              <v-row dense>
                <v-col cols="6">
                  <v-text-field v-model="m.remoteKey" :rules="[required]" label="Remote Key" variant="outlined" density="compact" hide-details="auto"></v-text-field>
                </v-col>
                <v-col cols="6">
                  <v-text-field v-model="m.localKey" :rules="[required]" label="Local Key" variant="outlined" density="compact" hide-details="auto"></v-text-field>
                </v-col>
                <v-col cols="6">
                  <v-select v-model="m.type" :items="MAPPING_TYPES" label="Type" variant="outlined" density="compact" hide-details="auto"></v-select>
                </v-col>
                <v-col v-if="m.type === 'VolumeMount'" cols="6">
                  <v-text-field v-model="m.mountPath" :rules="[required]" label="Mount Path" placeholder="/var/run/secrets/..." variant="outlined" density="compact" hide-details="auto"></v-text-field>
                </v-col>
              </v-row>
            </div>

            <v-switch
              v-model="form.requireVerifiedStatus"
              color="primary"
              density="compact"
              hide-details
              class="mb-2"
              label="Require Verified ZTA (zero-trust gate)"
            ></v-switch>

            <v-text-field v-model="form.refreshInterval" label="Refresh Interval" placeholder="ex. 1m, 10m" variant="outlined" density="compact" hide-details="auto" class="mb-4"></v-text-field>

            <v-btn :loading="isSubmitting" :disabled="!canWriteSecrets || !canSubmit" @click="submitSecretDeclaration" color="primary" block variant="flat" elevation="0" class="mt-2 text-none font-weight-medium">
              {{ !canWriteSecrets ? 'Necesită platform-engineer' : (isEditing ? 'Update ESO Delegation' : 'Authorize ESO Pull') }}
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
                      <v-btn v-if="canWriteSecrets" @click.stop="startEdit(zts)" color="primary" size="small" variant="text" icon="mdi-pencil" title="Editează delegarea ZTS"></v-btn>
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

.mapping-editor {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.10);
  border-radius: 8px;
  padding: 10px 12px;
  background: rgba(var(--v-theme-on-surface), 0.02);
}
</style>
