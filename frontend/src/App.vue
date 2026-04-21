<script setup lang="ts">
import { ref, onMounted, computed, onUnmounted, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useTheme } from 'vuetify'
import { api } from './api/axios'
import { useNotificationStore } from './store/notification'
import { useDashboardStore } from './store/dashboard'

const drawer = ref(true)
const router = useRouter()
const route = useRoute()
const theme = useTheme()
const notifyStore = useNotificationStore()
const dashboardStore = useDashboardStore()

const alerts = computed(() => notifyStore.alerts)
const alertHistory = computed(() => notifyStore.history)
const summary = computed(() => dashboardStore.summary)
const errorCenterOpen = ref(false)
const backendLogs = ref<any[]>([])
const backendLogsLoading = ref(false)
const backendLogsLastRefresh = ref('')
let backendLogsTimer: ReturnType<typeof setInterval> | null = null


const userProfile = ref<any | null>(null)

onMounted(async () => {
  // Verificare Status Backend (Live)
  try {
    const res = await api.get('/auth/me'); 
    userProfile.value = res.data;
  } catch (err: any) {
    userProfile.value = { email: 'secops@licenta.local', name: 'ZTA Admin', roles: ['admin'] };
    // Interceptorul va intercepta eroarea, vom lăsa store-ul să rezolve afișarea ei
  }

  dashboardStore.fetchOverview().catch(() => undefined)
})

onUnmounted(() => {
  if (backendLogsTimer) {
    clearInterval(backendLogsTimer)
    backendLogsTimer = null
  }
})

watch(errorCenterOpen, (open) => {
  if (open) {
    refreshBackendLogs().catch(() => undefined)
    if (!backendLogsTimer) {
      backendLogsTimer = setInterval(() => {
        refreshBackendLogs().catch(() => undefined)
      }, 10000)
    }
    return
  }

  if (backendLogsTimer) {
    clearInterval(backendLogsTimer)
    backendLogsTimer = null
  }
})

const menuItems = [
  { title: 'Overview', icon: 'mdi-google-circles-extended', path: '/' },
  { title: 'JIT Access', icon: 'mdi-shield-account-outline', path: '/jit' },
  { title: 'Identities (IAM)', icon: 'mdi-account-group', path: '/iam' },
  { title: 'ZTA Builder', icon: 'mdi-cube-outline', path: '/apps' },
  { title: 'Secret Vault', icon: 'mdi-lock-pattern', path: '/secrets' },
  { title: 'Supply Chain (SCA)', icon: 'mdi-shield-link-variant', path: '/sca' },
  { title: 'Security Posture', icon: 'mdi-radar', path: '/security' },
]

function toggleTheme() {
  theme.global.name.value = theme.global.current.value.dark ? 'googleCloudTheme' : 'googleCloudDarkTheme'
}

function getInitials(name: string) {
  if (!name) return '?'
  return name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase()
}

async function refreshBackendLogs() {
  backendLogsLoading.value = true
  try {
    const response = await api.get('/system/logs', {
      params: { limit: 80 },
      skipGlobalErrorAlert: true,
    })
    backendLogs.value = response.data.items || []
    backendLogsLastRefresh.value = new Date().toISOString()
  } catch {
    backendLogs.value = []
  } finally {
    backendLogsLoading.value = false
  }
}

function formatTimestamp(value?: string) {
  if (!value) return 'timestamp unavailable'
  try {
    return new Date(value).toLocaleString()
  } catch {
    return value
  }
}
</script>

<template>
  <v-app>
    <!-- Top App Bar -->
    <v-app-bar 
      elevation="1" 
      color="surface" 
      density="compact"
      class="gc-border-bottom"
    >
      <v-app-bar-nav-icon @click="drawer = !drawer" color="secondary" />
      <v-toolbar-title class="text-subtitle-1 font-weight-medium">
        <v-icon color="primary" class="mr-2" size="large">mdi-kubernetes</v-icon>
        Zero-Trust Admin Console
      </v-toolbar-title>

      <v-spacer></v-spacer>

      <!-- Security Pulse -->
      <div class="d-flex align-center mr-4">
        <v-tooltip text="JIT requests active in cluster" location="bottom">
          <template v-slot:activator="{ props }">
            <v-chip v-bind="props" size="small" variant="flat" color="blue-darken-1" class="mr-2 px-3 font-weight-medium">
              <v-icon start size="small">mdi-shield-account</v-icon>
              {{ summary.jitRequests }} JIT Requests
            </v-chip>
          </template>
        </v-tooltip>

        <v-tooltip text="Applications with degraded posture" location="bottom">
          <template v-slot:activator="{ props }">
            <v-chip v-bind="props" size="small" variant="flat" color="orange-darken-1" class="mr-2 px-3 font-weight-medium text-black">
              <v-icon start size="small" class="text-black">mdi-alert-decagram</v-icon>
              {{ summary.degradedApplications }} Degraded Apps
            </v-chip>
          </template>
        </v-tooltip>

        <v-tooltip text="Verified supply-chain workloads" location="bottom">
          <template v-slot:activator="{ props }">
            <v-chip v-bind="props" size="small" variant="flat" color="green-darken-1" class="px-3 font-weight-medium">
              <v-icon start size="small">mdi-security-network</v-icon>
              {{ summary.verifiedApplications }} Verified
            </v-chip>
          </template>
        </v-tooltip>
      </div>

      <v-chip class="mr-4 font-weight-medium" size="small" variant="tonal" color="green-darken-1">
        <v-icon start size="small">mdi-server-network</v-icon>
        europe-west3-a
      </v-chip>

      <v-btn icon @click="toggleTheme" color="secondary">
        <v-icon>{{ theme.global.current.value.dark ? 'mdi-weather-sunny' : 'mdi-weather-night' }}</v-icon>
      </v-btn>
      <v-btn icon color="secondary">
        <v-icon>mdi-help-circle-outline</v-icon>
      </v-btn>
      <v-btn icon color="secondary" @click="errorCenterOpen = true">
        <v-badge :content="alerts.length + alertHistory.length" color="error" offset-x="2" offset-y="2">
          <v-icon>mdi-text-box-search-outline</v-icon>
        </v-badge>
      </v-btn>
      <v-avatar 
        color="primary" 
        size="32" 
        class="ml-2 mr-3 text-caption font-weight-bold" 
        :title="userProfile?.email || 'Loading...'"
      >
        {{ userProfile ? getInitials(userProfile.name) : '...' }}
      </v-avatar>
    </v-app-bar>

    <!-- Side Navigation Sidebar -->
    <v-navigation-drawer 
      v-model="drawer" 
      color="surface" 
      elevation="0" 
      class="gc-border-right"
    >
      <v-list density="compact" nav>
        <v-list-item
          v-for="(item, i) in menuItems"
          :key="i"
          :value="item"
          :to="item.path"
          active-color="primary"
          class="mb-1"
          rounded="lg"
        >
          <template v-slot:prepend>
            <v-icon :icon="item.icon" size="small"></v-icon>
          </template>
          <v-list-item-title class="text-body-2 font-weight-medium">{{ item.title }}</v-list-item-title>
        </v-list-item>
      </v-list>
    </v-navigation-drawer>

    <!-- Main Content Area -->
    <v-main class="bg-background">
      <v-container fluid class="pa-6">        
        <!-- Global Notifications Layer (Pinia Toast System) -->
        <div class="position-fixed top-0 right-0 pa-4" style="z-index: 9999; max-width: 450px;">
          <transition-group name="fade">
            <v-alert
              v-for="alert in alerts"
              :key="alert.id"
              :color="alert.type === 'error' ? 'error' : (alert.error_code.includes('SUCCESS') || alert.error_code.includes('COPIED') || alert.error_code.includes('CREATED') ? 'success' : 'warning')"
              :icon="alert.type === 'error' ? 'mdi-shield-alert' : (alert.error_code.includes('SUCCESS') || alert.error_code.includes('COPIED') || alert.error_code.includes('CREATED') ? 'mdi-check-circle' : 'mdi-alert')"
              theme="dark"
              border="start"
              border-color="white"
              elevation="4"
              class="mb-3 gc-border"
              closable
              @click:close="notifyStore.removeAlert(alert.id)"
            >
              <div class="text-subtitle-2 font-weight-bold mb-1">{{ alert.message }}</div>
              <div class="text-caption mb-2">{{ alert.action_required }}</div>
              <div class="text-caption mb-2">{{ alert.request_method || 'N/A' }} {{ alert.request_path || 'unknown-path' }} • {{ alert.status_code || 'n/a' }} • {{ formatTimestamp(alert.timestamp) }}</div>
              
              <v-expansion-panels variant="accordion" class="mt-2 text-caption">
                <v-expansion-panel
                  title="Technical Details (Trace)"
                  class="bg-transparent"
                  elevation="0"
                >
                  <v-expansion-panel-text>
                    <div class="font-mono pa-2 rounded mt-1" style="background-color: rgba(255, 255, 255, 0.15); word-break: break-all; white-space: pre-wrap; font-size: 0.85rem;">
                      Code: {{ alert.error_code }}<br>
                      Component: {{ alert.component }}<br>
                      Trace: {{ alert.trace_id }}<br>
                      Source: {{ alert.source || 'unknown' }}<br>
                      Status: {{ alert.status_code || 'n/a' }}<br>
                      Method: {{ alert.request_method || 'n/a' }}<br>
                      Path: {{ alert.request_path || 'n/a' }}<br>
                      <br>
                      {{ alert.technical_details }}
                      <template v-if="alert.details">
                        <br><br>
                        {{ JSON.stringify(alert.details, null, 2) }}
                      </template>
                    </div>
                  </v-expansion-panel-text>
                </v-expansion-panel>
              </v-expansion-panels>
            </v-alert>
          </transition-group>
        </div>
        <!-- Breadcrumbs -->
        <v-breadcrumbs 
          :items="[{ title: 'Home', disabled: false, href: '/' }, { title: String(route.name), disabled: true }]" 
          class="pa-0 mb-4 text-caption text-secondary"
        >
          <template v-slot:divider>
            <v-icon size="small">mdi-chevron-right</v-icon>
          </template>
        </v-breadcrumbs>
        
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>

        <v-dialog v-model="errorCenterOpen" max-width="1200">
          <v-card class="gc-border" flat>
            <v-card-title class="d-flex align-center justify-space-between text-primary">
              <span>Error Center</span>
              <div class="d-flex ga-2">
                <v-btn size="small" variant="outlined" color="primary" :loading="backendLogsLoading" @click="refreshBackendLogs">Refresh Backend Logs</v-btn>
                <v-btn size="small" variant="text" color="warning" @click="notifyStore.clearAlerts">Clear Active</v-btn>
                <v-btn size="small" variant="text" color="error" @click="notifyStore.clearHistory">Clear History</v-btn>
              </div>
            </v-card-title>
            <v-card-text>
              <v-row>
                <v-col cols="12" md="5">
                  <div class="text-subtitle-2 font-weight-medium mb-3">Frontend And API Error History</div>
                  <div v-if="!alertHistory.length" class="text-caption text-secondary">No captured errors yet.</div>
                  <v-expansion-panels v-else variant="accordion">
                    <v-expansion-panel v-for="item in alertHistory" :key="item.id">
                      <v-expansion-panel-title>
                        <div class="w-100 pr-4">
                          <div class="font-weight-medium">{{ item.message }}</div>
                          <div class="text-caption text-secondary">{{ item.error_code }} • {{ item.request_method || 'N/A' }} {{ item.request_path || 'n/a' }}</div>
                        </div>
                      </v-expansion-panel-title>
                      <v-expansion-panel-text>
                        <pre class="observability-block">{{ JSON.stringify(item, null, 2) }}</pre>
                      </v-expansion-panel-text>
                    </v-expansion-panel>
                  </v-expansion-panels>
                </v-col>
                <v-col cols="12" md="7">
                  <div class="d-flex align-center justify-space-between mb-3">
                    <div class="text-subtitle-2 font-weight-medium">Backend Log Stream</div>
                    <div class="text-caption text-secondary">Last refresh {{ formatTimestamp(backendLogsLastRefresh) }}</div>
                  </div>
                  <div v-if="!backendLogs.length" class="text-caption text-secondary">Backend logs have not been loaded yet.</div>
                  <div v-else class="observability-log-list">
                    <div v-for="(entry, index) in backendLogs" :key="`${entry.timestamp}-${index}`" class="observability-log-item">
                      <div class="d-flex align-center justify-space-between mb-1">
                        <v-chip size="x-small" :color="entry.level === 'ERROR' ? 'error' : (entry.level === 'WARNING' ? 'warning' : 'primary')" variant="tonal">{{ entry.level }}</v-chip>
                        <span class="text-caption text-secondary">{{ formatTimestamp(entry.timestamp) }}</span>
                      </div>
                      <div class="text-body-2 font-weight-medium">{{ entry.logger }}</div>
                      <div class="text-caption text-secondary mb-2">{{ entry.method || 'SYS' }} {{ entry.path || '' }} <span v-if="entry.status_code">• {{ entry.status_code }}</span> <span v-if="entry.trace_id">• {{ entry.trace_id }}</span></div>
                      <pre class="observability-block">{{ JSON.stringify(entry, null, 2) }}</pre>
                    </div>
                  </div>
                </v-col>
              </v-row>
            </v-card-text>
          </v-card>
        </v-dialog>
      </v-container>
    </v-main>
  </v-app>
</template>

<style>
/* Global Typography */
body {
  font-family: 'Roboto', sans-serif;
  -webkit-font-smoothing: antialiased;
}

/* Monospace for Code/YAML */
.font-mono {
  font-family: 'Roboto Mono', monospace !important;
}

/* Material 3 Google Cloud Borders */
.gc-border-bottom {
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important;
}
.gc-border-right {
  border-right: 1px solid rgba(var(--v-theme-on-surface), 0.12) !important;
}

/* Transitions */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.15s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.observability-log-list {
  display: grid;
  gap: 12px;
  max-height: 70vh;
  overflow: auto;
}

.observability-log-item,
.observability-block {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 12px;
  background: rgba(var(--v-theme-on-surface), 0.03);
}

.observability-log-item {
  padding: 12px;
}

.observability-block {
  padding: 12px;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 0.8rem;
  margin: 0;
}
</style>
