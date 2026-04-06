features pentru zts ai adaugat? cel de aici: zeroTrustSecretDOC ? ce operator face deployed la el? raspunde scurt. adauga aceasta logica de tratare de erori mai ales pe backend si cu afisare in frotnend mai ales te rog, pentru orice ar merge prost si nu este ok, sa fie vizibilitate toatla si afiasare totala. <script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useJitStore, JitSession } from '../store/jit'
import { useNotificationStore } from '../store/notification'

const jitStore = useJitStore()
const sessions = computed(() => jitStore.sessions)
const isLoading = computed(() => jitStore.isLoading)
const isSubmitting = computed(() => jitStore.isSubmitting)

const generatedCommand = ref('')
const copySuccess = ref(false)

const form = ref({
  namespace: 'default',
  role: 'Read-Only',
  duration: 60,
  reason: ''
})

const roles = ['Read-Only', 'Admin', 'Network-Admin']

// Revoke Process
const isConfirmRevokeOpen = ref(false)
const sessionToRevoke = ref<JitSession | null>(null)
const isRevoking = ref(false)

let timerId: ReturnType<typeof setInterval>
const now = ref(Date.now()) // Reactivity driver for UI timers

onMounted(() => {
  jitStore.fetchSessions()
  timerId = setInterval(() => {
    now.value = Date.now()
  }, 1000)
})

onUnmounted(() => {
  clearInterval(timerId)
})

async function submitRequest() {
  try {
    const res = await jitStore.requestAccess({
      namespace: form.value.namespace,
      role: form.value.role,
      duration: form.value.duration
    });
    // Optional: UI representation
    generatedCommand.value = `export KUBECONFIG=~/.kube/cache/new-session.yaml\nkubectl auth whoami`
    const notifyStore = useNotificationStore();
    notifyStore.addAlert({
        error_code: 'JIT_CREATED',
        message: 'JIT Access acordat cu succes.',
        technical_details: `Rolul ${form.value.role} în ns ${form.value.namespace}`,
        component: 'JIT_OPERATOR',
        trace_id: Math.random().toString(36).substring(2),
        action_required: '',
        type: 'warning'
    });
  } catch (err) {
    // API throws, which gets caught in Pinia / Axios interceptors to show Global Trace Error!
  }
}

function copyCommand() {
  navigator.clipboard.writeText(generatedCommand.value)
  copySuccess.value = true
  const notifyStore = useNotificationStore();
  notifyStore.addAlert({
    error_code: 'COPIED',
    message: 'Comanda Kubeconfig copiată în clipboard.',
    technical_details: '',
    component: 'JIT_UI',
    trace_id: Math.random().toString(36).substring(2),
    action_required: '',
    type: 'warning'
  });
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
    isConfirmRevokeOpen.value = false
  } catch (err) {
    // Error handler interceptor triggered
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
  if (status === 'ACTIVE') return 'success'
  if (status === 'EXPIRED') return 'secondary'
  if (status === 'REVOKED') return 'error'
  if (status === 'PENDING') return 'warning'
  return 'secondary'
}

function getStatusIcon(status: string) {
  if (status === 'ACTIVE') return 'mdi-check-circle-outline'
  if (status === 'EXPIRED') return 'mdi-clock-time-eight-outline'
  if (status === 'REVOKED') return 'mdi-cancel'
  if (status === 'PENDING') return 'mdi-dots-horizontal-circle-outline'
  return 'mdi-help-circle-outline'
}

function getTTLPercentage(expiresAtStr: string, durationMin: number) {
  const diff = new Date(expiresAtStr).getTime() - now.value
  const total = durationMin * 60000
  return Math.max(0, Math.min(100, (diff / total) * 100))
}

function getTTLColor(expiresAtStr: string) {
  const diff = new Date(expiresAtStr).getTime() - now.value
  if (diff < 300000) return 'error' // Sub 5 minute rosu
  if (diff < 900000) return 'warning' // Sub 15 min portocaliu
  return 'success'
}

function getTTLColorClass(expiresAtStr: string) {
  const color = getTTLColor(expiresAtStr)
  return `text-${color}`
}

function copyKubeconfig(sessionId: string) {
  navigator.clipboard.writeText(`export KUBECONFIG=~/.kube/cache/${sessionId}.yaml\nkubectl config view`)
  const notifyStore = useNotificationStore()
  notifyStore.addAlert({
    error_code: 'CLIPBOARD_SUCCESS',
    message: 'Kubeconfig command copied.',
    technical_details: 'Stored in clipboard successfully',
    component: 'JIT_MODULE',
    trace_id: `SYS-${Math.random().toString(36).substring(2)}`,
    action_required: '',
    type: 'warning' // Pinia auto-dismisses warnings
  })
}
</script>

<template>
  <div>
    <h1 class="text-h5 font-weight-medium mb-4 text-primary">JIT Access Portal</h1>
    
    <v-row>
      <-> JIT Wizard Form -->
      <v-col cols="12" md="5" lg="4">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-primary">Developer Wizard</v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary mb-6">Cerere ephemeral access via TokenRequest API.</p>
            
            <v-text-field 
              v-model="form.namespace"
              density="compact" 
              label="Target Namespace" 
              variant="outlined" 
              placeholder="e.g., default"
              hide-details="auto"
              class="mb-4"
            ></v-text-field>
            
            <v-select 
              v-model="form.role"
              density="compact" 
              label="Requested Role" 
              :items="roles" 
              variant="outlined"
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
            ></v-textarea>
            
            <v-btn 
              :loading="isSubmitting"
              @click="submitRequest"
              color="primary" 
              block 
              variant="flat" 
              elevation="0" 
              class="mt-6 text-none font-weight-medium"
            >
              Request Access
            </v-btn>

            <-> Afișare comandă generată HTTP mock response -->
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
      
      <-> Active Sessions Admin -->
      <v-col cols="12" md="7" lg="8">
        <v-card class="gc-border h-100" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
          <v-card-title class="font-weight-medium pb-2 text-error">
            <v-icon start color="error" class="mr-2">mdi-shield-crown-outline</v-icon>
            Admin Command Center
          </v-card-title>
          <v-card-text>
            <p class="text-caption text-secondary mb-4">Monitorizează sesiunile active și execută procedurile Kill Switch.</p>
            
            <v-table density="comfortable" class="border rounded" hover>
              <thead>
                <tr class="bg-surface-variant">
                  <th class="text-left font-weight-medium">Identity (User)</th>
                  <th class="text-left font-weight-medium">Namespace</th>
                  <th class="text-left font-weight-medium">Role</th>
                  <th class="text-center font-weight-medium">Status</th>
                  <th class="text-center font-weight-medium" style="width: 150px">TTL</th>
                  <th class="text-right font-weight-medium">Actions</th>
                </tr>
              </thead>
              <tbody v-if="isLoading">
                <tr v-for="i in 3" :key="i">
                  <td colspan="6">
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
                    <template v-if="session.status === 'ACTIVE' || session.status === 'PENDING'">
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
                  <td class="text-right">
                    <v-btn 
                      v-if="session.status === 'ACTIVE' || session.status === 'PENDING'"
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
                        <v-list-item @click="() => {}" :disabled="session.status !== 'ACTIVE'" prepend-icon="mdi-console">
                          <v-list-item-title class="text-caption">View Logs</v-list-item-title>
                        </v-list-item>
                        <v-list-item @click="copyKubeconfig(session.id)" :disabled="session.status !== 'ACTIVE'" prepend-icon="mdi-code-json">
                          <v-list-item-title class="text-caption">Copy Kubeconfig</v-list-item-title>
                        </v-list-item>
                        <v-list-item @click="() => {}" prepend-icon="mdi-information-outline">
                          <v-list-item-title class="text-caption">Details</v-list-item-title>
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

    <-> Revoke Confirmation Dialog -->
    <v-dialog v-model="isConfirmRevokeOpen" max-width="400" persistent>
      <v-card class="gc-border" flat>
        <v-card-title class="text-error font-weight-medium pt-4 bg-error-lighten-5">
          <v-icon color="error" class="mr-2">mdi-alert</v-icon> Confirm Kill Switch
        </v-card-title>
        <v-card-text class="pt-4">
          Ești pe cale să revoci sesiunea critică:
          <div class="mt-3 pa-3 bg-surface-variant rounded border gc-border font-mono text-caption">
            <strong>ID:</strong> {{ sessionToRevoke?.id }}<br>
            <strong>User:</strong> {{ sessionToRevoke?.user }}<br>
            <strong>Namespace:</strong> {{ sessionToRevoke?.namespace }}<br>
            <strong>Role:</strong> {{ sessionToRevoke?.role }}
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
