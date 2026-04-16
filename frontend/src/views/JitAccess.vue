<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api/axios'
import { useJitStore, JitSession } from '../store/jit'
import { useNotificationStore } from '../store/notification'
import { useDashboardStore } from '../store/dashboard'

const jitStore = useJitStore()
const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()

const sessions = computed(() => jitStore.sessions)
const isLoading = computed(() => jitStore.isLoading)
const isSubmitting = computed(() => jitStore.isSubmitting)
const summary = computed(() => dashboardStore.summary)

const generatedCommand = ref('')
const copySuccess = ref(false)
const jitAnalytics = ref<any | null>(null)
const jitPolicies = ref<any | null>(null)
const isLoadingPolicies = ref(false)
const isSavingPolicies = ref(false)

const policyForm = ref({
  blockedUsersText: '',
  maxActiveSessions: 1,
  cooldownMinutes: 15,
  maxRequestsPerDay: 5,
  maxDurationMinutes: 120,
})

const form = ref({
  namespace: 'default',
  role: 'view',
  duration: 60,
  reason: ''
})

const roles = ['view', 'edit', 'admin']

const isConfirmRevokeOpen = ref(false)
const sessionToRevoke = ref<JitSession | null>(null)
const isRevoking = ref(false)

let timerId: ReturnType<typeof setInterval>
const now = ref(Date.now())

onMounted(() => {
  jitStore.fetchSessions()
  dashboardStore.fetchOverview(true).catch(() => undefined)
  loadJitAdmin().catch(() => undefined)
  timerId = setInterval(() => {
    now.value = Date.now()
  }, 1000)
})

onUnmounted(() => {
  clearInterval(timerId)
})

async function submitRequest() {
  try {
    await jitStore.requestAccess({
      namespace: form.value.namespace,
      role: form.value.role,
      duration: form.value.duration
    })
    await dashboardStore.fetchOverview(true)
    await loadJitAdmin()
    generatedCommand.value = `export KUBECONFIG=~/.kube/cache/new-session.yaml\nkubectl auth whoami\nkubectl get pods -n ${form.value.namespace}`
    notifyStore.addAlert({
        error_code: 'JIT_CREATED',
        message: 'JIT Access request trimis cu succes.',
        technical_details: `Rolul ${form.value.role} în ns ${form.value.namespace} pentru ${form.value.duration} minute. ${form.value.reason || 'Fără justificare adițională.'}`,
        component: 'JIT_OPERATOR',
        trace_id: Math.random().toString(36).substring(2),
        action_required: 'Monitorizează statusul cererii și mesajul întors de operator.',
        type: 'warning'
    })
  } catch (err) {
    console.error('JIT request failed', err)
  }
}

function copyCommand() {
  navigator.clipboard.writeText(generatedCommand.value)
  copySuccess.value = true
  notifyStore.addAlert({
    error_code: 'COPIED',
    message: 'Comanda Kubeconfig copiată în clipboard.',
    technical_details: generatedCommand.value,
    component: 'JIT_UI',
    trace_id: Math.random().toString(36).substring(2),
    action_required: '',
    type: 'warning'
  })
  setTimeout(() => (copySuccess.value = false), 2000)
}

function promptRevoke(session: JitSession) {
  sessionToRevoke.value = session
  isConfirmRevokeOpen.value = true
}

async function confirmRevoke() {
  if (!sessionToRevoke.value) return
  isRevoking.value = true
  try {
    await jitStore.revokeSession(sessionToRevoke.value.namespace, sessionToRevoke.value.id)
    await dashboardStore.fetchOverview(true)
    await loadJitAdmin()
    notifyStore.addAlert({
      error_code: 'JIT_REVOKED',
      message: `Sesiunea ${sessionToRevoke.value.id} a fost revocată.`,
      technical_details: `Namespace=${sessionToRevoke.value.namespace}, user=${sessionToRevoke.value.user}`,
      component: 'JIT_OPERATOR',
      trace_id: Math.random().toString(36).substring(2),
      action_required: '',
      type: 'warning'
    })
    isConfirmRevokeOpen.value = false
  } catch (err) {
    console.error('JIT revoke failed', err)
  } finally {
    isRevoking.value = false
    sessionToRevoke.value = null
  }
}

function formatTimeLeft(expiresAtStr: string) {
  const diff = new Date(expiresAtStr).getTime() - now.value
  if (diff <= 0) return '00:00'
  const h = Math.floor(diff / 3600000).toString().padStart(2, '0')
  const m = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0')
  const s = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0')
  return parseInt(h) > 0 ? `${h}:${m}:${s}` : `${m}:${s}`
}

function getStatusColor(status: string) {
  if (status === 'ACTIVE' || status === 'APPROVED') return 'success'
  if (status === 'EXPIRED') return 'secondary'
  if (status === 'REVOKED') return 'error'
  if (status.startsWith('DENIED') || status.startsWith('BLOCKED')) return 'error'
  if (status === 'PENDING') return 'warning'
  return 'secondary'
}

function getStatusIcon(status: string) {
  if (status === 'ACTIVE' || status === 'APPROVED') return 'mdi-check-circle'
  if (status === 'EXPIRED') return 'mdi-progress-clock'
  if (status === 'REVOKED') return 'mdi-cancel'
  if (status.startsWith('DENIED') || status.startsWith('BLOCKED')) return 'mdi-alert'
  if (status === 'PENDING') return 'mdi-dots-horizontal-circle'
  return 'mdi-help-circle'
}

function getTTLPercentage(expiresAtStr: string, durationMin: number) {
  const diff = new Date(expiresAtStr).getTime() - now.value
  const total = Math.max(durationMin * 60000, 1)
  return Math.max(0, Math.min(100, (diff / total) * 100))
}

function getTTLColor(expiresAtStr: string) {
  const diff = new Date(expiresAtStr).getTime() - now.value
  if (diff < 300000) return 'error'
  if (diff < 900000) return 'warning'
  return 'success'
}

function getTTLColorClass(expiresAtStr: string) {
  const color = getTTLColor(expiresAtStr)
  return `text-${color}`
}

function copyKubeconfig(sessionId: string) {
  navigator.clipboard.writeText(`export KUBECONFIG=~/.kube/cache/${sessionId}.yaml\nkubectl config view`)
  notifyStore.addAlert({
    error_code: 'CLIPBOARD_SUCCESS',
    message: 'Kubeconfig command copied.',
    technical_details: `Stored command for session ${sessionId}`,
    component: 'JIT_MODULE',
    trace_id: `SYS-${Math.random().toString(36).substring(2)}`,
    action_required: '',
    type: 'warning'
  })
}

async function loadJitAdmin() {
  isLoadingPolicies.value = true
  try {
    const [analyticsResponse, policiesResponse] = await Promise.all([
      api.get('/jit/analytics'),
      api.get('/jit/policies')
    ])
    jitAnalytics.value = analyticsResponse.data
    jitPolicies.value = policiesResponse.data
    policyForm.value = {
      blockedUsersText: (policiesResponse.data.blockedUsers || []).join('\n'),
      maxActiveSessions: policiesResponse.data.antiAbuse?.maxActiveSessions || 1,
      cooldownMinutes: policiesResponse.data.antiAbuse?.cooldownMinutes || 15,
      maxRequestsPerDay: policiesResponse.data.antiAbuse?.maxRequestsPerDay || 5,
      maxDurationMinutes: policiesResponse.data.antiAbuse?.maxDurationMinutes || 120,
    }
  } finally {
    isLoadingPolicies.value = false
  }
}

async function savePolicies() {
  isSavingPolicies.value = true
  try {
    const payload = {
      blockedUsers: policyForm.value.blockedUsersText.split('\n').map((item) => item.trim()).filter(Boolean),
      antiAbuse: {
        maxActiveSessions: policyForm.value.maxActiveSessions,
        cooldownMinutes: policyForm.value.cooldownMinutes,
        maxRequestsPerDay: policyForm.value.maxRequestsPerDay,
        maxDurationMinutes: policyForm.value.maxDurationMinutes,
      },
    }
    const response = await api.put('/jit/policies', payload)
    jitPolicies.value = response.data
    await loadJitAdmin()
    notifyStore.addAlert({
      error_code: 'JIT_POLICIES_UPDATED',
      message: 'Politicile anti-abuse au fost actualizate în ConfigMap.',
      technical_details: JSON.stringify(response.data, null, 2),
      component: 'JIT_POLICY_EDITOR',
      trace_id: Math.random().toString(36).substring(2),
      action_required: 'Verifică imediat efectul asupra cererilor JIT active.',
      type: 'warning'
    })
  } finally {
    isSavingPolicies.value = false
  }
}
</script>

<template>
  <div>
    <div class="d-flex align-center justify-space-between mb-4">
      <h1 class="text-h5 font-weight-medium text-primary">JIT Access Portal</h1>
      <v-chip color="primary" variant="tonal" class="font-weight-medium">
        <v-icon start size="small">mdi-shield-account</v-icon>
        {{ summary.jitRequests }} Requests In Cluster
      </v-chip>
    </div>
    
    <v-row>
      <v-col cols="12" md="5" lg="4">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary">Ephemeral Access Wizard (IAM)</v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary mb-6">Cerere JIT bazată pe `JITAccessRequest`, cu status și mesaj complet afișate din backend.</p>
            
            <v-text-field 
              v-model="form.namespace"
              density="compact" 
              label="Target Namespace" 
              variant="outlined" 
              placeholder="e.g., default"
              prepend-inner-icon="mdi-google-cloud"
              hide-details="auto"
              class="mb-4"
            ></v-text-field>
            
            <v-select 
              v-model="form.role"
              density="compact" 
              label="Requested Kubernetes Role" 
              :items="roles" 
              variant="outlined"
              prepend-inner-icon="mdi-shield-account-variant"
              hide-details="auto"
              class="mb-4"
            ></v-select>
            
            <div class="px-2 mt-6">
              <div class="text-caption text-secondary mb-1">Duration: {{ form.duration }} minutes</div>
              <v-slider 
                v-model="form.duration"
                color="primary" 
                min="5" 
                max="120" 
                step="5" 
                thumb-label
                hide-details
              ></v-slider>
            </div>

            <v-textarea
              v-model="form.reason"
              label="Justificare (SecOps Audit)"
              variant="outlined"
              density="compact"
              rows="2"
              class="mt-4"
              hide-details="auto"
              prepend-inner-icon="mdi-text-box-edit-outline"
            ></v-textarea>
            
            <v-btn 
              :loading="isSubmitting"
              @click="submitRequest"
              color="primary" 
              block 
              variant="flat" 
              elevation="0" 
              class="mt-6 text-none font-weight-medium"
              prepend-icon="mdi-shield-key-outline"
            >
              Request Access
            </v-btn>

            <v-expand-transition>
              <div v-if="generatedCommand" class="mt-4">
                <div class="d-flex align-center justify-space-between bg-surface-variant pa-2 rounded gc-border">
                  <pre class="font-mono text-caption text-secondary ma-0" style="white-space: pre-wrap;">{{ generatedCommand }}</pre>
                  <v-btn 
                    icon 
                    size="x-small" 
                    variant="text" 
                    :color="copySuccess ? 'success' : 'secondary'"
                    @click="copyCommand"
                  >
                    <v-icon>{{ copySuccess ? 'mdi-check' : 'mdi-content-copy' }}</v-icon>
                  </v-btn>
                </div>
              </div>
            </v-expand-transition>

          </v-card-text>
        </v-card>
      </v-col>
      
      <v-col cols="12" md="7" lg="8">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-error">
            <v-icon start color="error" class="mr-2">mdi-google-cloud</v-icon>
            IAM & Service Accounts Admin
          </v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary mb-4">Monitorizează sesiunile active, pending, denied sau revocate și vezi motivul complet întors de operator.</p>
            
            <v-table density="comfortable" class="border rounded" hover>
              <thead>
                <tr class="bg-surface-variant">
                  <th class="text-left font-weight-medium">Identity (User)</th>
                  <th class="text-left font-weight-medium">Namespace</th>
                  <th class="text-left font-weight-medium">Role</th>
                  <th class="text-center font-weight-medium">Status</th>
                  <th class="text-center font-weight-medium" style="width: 150px">TTL</th>
                  <th class="text-left font-weight-medium">Visibility</th>
                  <th class="text-right font-weight-medium">Actions</th>
                </tr>
              </thead>
              <tbody v-if="isLoading">
                <tr v-for="i in 3" :key="i">
                  <td colspan="7">
                    <v-skeleton-loader type="table-row" height="40"></v-skeleton-loader>
                  </td>
                </tr>
              </tbody>
              <tbody v-else>
                <tr v-for="session in sessions" :key="session.id" class="cursor-pointer hover:bg-surface-variant transition-colors">
                  <td class="text-body-2 font-weight-medium d-flex align-center">
                    <v-avatar size="24" color="primary" class="mr-2 text-caption font-weight-bold">{{ session.user.substring(0,2).toUpperCase() }}</v-avatar>
                    {{ session.user }}
                  </td>
                  <td class="font-mono text-caption text-secondary">{{ session.namespace }}</td>
                  <td class="font-mono text-caption text-secondary">{{ session.role }}</td>
                  <td class="text-center">
                    <v-chip 
                      :color="getStatusColor(session.status)" 
                      size="small" 
                      variant="flat" 
                      class="font-weight-bold text-caption px-3"
                    >
                      <v-icon start size="x-small">{{ getStatusIcon(session.status) }}</v-icon>
                      {{ session.status }}
                    </v-chip>
                  </td>
                  <td class="text-center font-mono text-caption">
                    <template v-if="session.status === 'ACTIVE' || session.status === 'APPROVED' || session.status === 'PENDING'">
                      <div class="d-flex flex-column align-center w-100">
                        <span class="mb-1" :class="getTTLColorClass(session.expiresAt)">{{ formatTimeLeft(session.expiresAt) }}</span>
                        <v-progress-linear 
                          :model-value="getTTLPercentage(session.expiresAt, session.duration)" 
                          :color="getTTLColor(session.expiresAt)" 
                          height="4" 
                          rounded="pill"
                          class="w-100"
                        ></v-progress-linear>
                      </div>
                    </template>
                    <template v-else>
                      <span class="text-secondary">00:00:00</span>
                      <v-progress-linear model-value="0" color="secondary" height="4" rounded="pill" class="w-100 mt-1"></v-progress-linear>
                    </template>
                  </td>
                  <td class="text-caption text-secondary" style="max-width: 220px;">{{ session.message || 'No operator message available.' }}</td>
                  <td class="text-right">
                    <v-btn 
                      v-if="session.status === 'ACTIVE' || session.status === 'APPROVED' || session.status === 'PENDING'"
                      @click="promptRevoke(session)"
                      color="error" 
                      size="small" 
                      variant="text" 
                      icon="mdi-lock-reset"
                      title="Kill Switch (Revoke)"
                    ></v-btn>
                    
                    <v-menu location="start">
                      <template v-slot:activator="{ props }">
                        <v-btn icon="mdi-dots-vertical" variant="text" size="small" v-bind="props" color="secondary"></v-btn>
                      </template>
                      <v-list density="compact" class="gc-border" elevation="2">
                        <v-list-item @click="copyKubeconfig(session.sessionId || session.id)" :disabled="session.status !== 'ACTIVE' && session.status !== 'APPROVED'" prepend-icon="mdi-code-json">
                          <v-list-item-title class="text-caption">Copy Kubeconfig</v-list-item-title>
                        </v-list-item>
                        <v-list-item prepend-icon="mdi-information-outline">
                          <v-list-item-title class="text-caption">{{ session.message || 'No details' }}</v-list-item-title>
                        </v-list-item>
                      </v-list>
                    </v-menu>
                  </td>
                </tr>
              </tbody>
            </v-table>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-2">
      <v-col cols="12" lg="5">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Anti-Abuse Policy Editor</v-card-title>
          <v-card-text>
            <div class="text-caption text-secondary mb-4">Editează direct ConfigMap-ul `jit-security-policies` din cluster.</div>
            <v-skeleton-loader v-if="isLoadingPolicies" type="article"></v-skeleton-loader>
            <template v-else>
              <v-textarea v-model="policyForm.blockedUsersText" label="Blocked Users" rows="5" variant="outlined" density="compact" hint="One identity per line" persistent-hint></v-textarea>
              <v-row>
                <v-col cols="12" md="6">
                  <v-text-field v-model.number="policyForm.maxActiveSessions" type="number" label="Max Active Sessions" variant="outlined" density="compact"></v-text-field>
                </v-col>
                <v-col cols="12" md="6">
                  <v-text-field v-model.number="policyForm.cooldownMinutes" type="number" label="Cooldown Minutes" variant="outlined" density="compact"></v-text-field>
                </v-col>
                <v-col cols="12" md="6">
                  <v-text-field v-model.number="policyForm.maxRequestsPerDay" type="number" label="Max Requests / Day" variant="outlined" density="compact"></v-text-field>
                </v-col>
                <v-col cols="12" md="6">
                  <v-text-field v-model.number="policyForm.maxDurationMinutes" type="number" label="Max Duration Minutes" variant="outlined" density="compact"></v-text-field>
                </v-col>
              </v-row>
              <v-btn color="primary" variant="flat" :loading="isSavingPolicies" @click="savePolicies">Apply Cluster Policy</v-btn>
            </template>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" lg="7">
        <v-card class="gc-border h-100" flat>
          <v-card-title class="text-primary">Anti-Abuse Analytics</v-card-title>
          <v-card-text>
            <div class="d-flex flex-wrap ga-2 mb-4">
              <v-chip color="primary" variant="tonal">Active {{ jitAnalytics?.activeSessions || 0 }}</v-chip>
              <v-chip color="error" variant="tonal">Blocked {{ (jitAnalytics?.blockedUsers || []).length }}</v-chip>
              <v-chip color="warning" variant="tonal">Tracked identities {{ (jitAnalytics?.topIdentities || []).length }}</v-chip>
            </div>
            <div class="text-caption text-secondary mb-2">Denied by type</div>
            <div class="d-flex flex-wrap ga-2 mb-4">
              <v-chip v-for="(count, key) in (jitAnalytics?.deniedByType || {})" :key="key" color="warning" variant="outlined">
                {{ key }}: {{ count }}
              </v-chip>
            </div>
            <v-table density="compact" class="border rounded">
              <thead>
                <tr>
                  <th class="text-left">Identity</th>
                  <th class="text-left">Requests</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="identity in (jitAnalytics?.topIdentities || [])" :key="identity.identity">
                  <td>{{ identity.identity }}</td>
                  <td>{{ identity.requests }}</td>
                </tr>
              </tbody>
            </v-table>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-dialog v-model="isConfirmRevokeOpen" max-width="400" persistent>
      <v-card class="gc-border" flat>
        <v-card-title class="text-error font-weight-medium pt-4 bg-error-lighten-5">
          <v-icon color="error" class="mr-2">mdi-alert-decagram</v-icon> Confirm Revoke IAM
        </v-card-title>
        <v-card-text class="pt-4">
          Ești pe cale să revoci sesiunea critică:
          <div class="mt-3 pa-3 bg-surface-variant rounded border gc-border font-mono text-caption">
            <strong>ID:</strong> {{ sessionToRevoke?.id }}<br>
            <strong>User:</strong> {{ sessionToRevoke?.user }}<br>
            <strong>Namespace:</strong> {{ sessionToRevoke?.namespace }}<br>
            <strong>Role:</strong> {{ sessionToRevoke?.role }}<br>
            <strong>Message:</strong> {{ sessionToRevoke?.message || 'No backend message' }}
          </div>
          <p class="mt-4 text-body-2 font-weight-medium text-error">Acest lucru va declanșa instantaneu ștergerea RoleBinding-ului în cluster-ul selectat. Continuăm?</p>
        </v-card-text>
        <v-card-actions class="px-4 pb-4">
          <v-spacer></v-spacer>
          <v-btn color="secondary" variant="text" :disabled="isRevoking" @click="isConfirmRevokeOpen = false">Cancel</v-btn>
          <v-btn color="error" variant="flat" elevation="0" :loading="isRevoking" @click="confirmRevoke">Revoke Access Now</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<style scoped>
.v-table th { white-space: nowrap; }
.bg-error-lighten-5 { background-color: rgba(var(--v-theme-error), 0.05); }
</style>
