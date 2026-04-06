<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useTheme } from 'vuetify'
import { api } from './api/axios'
import { useNotificationStore } from './store/notification'

const drawer = ref(true)
const router = useRouter()
const route = useRoute()
const theme = useTheme()
const notifyStore = useNotificationStore()

const alerts = computed(() => notifyStore.alerts)


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
})

const menuItems = [
  { title: 'Overview', icon: 'mdi-google-circles-extended', path: '/' },
  { title: 'JIT Access', icon: 'mdi-shield-account-outline', path: '/jit' },
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
</script>

<template>
  <v-app>
    <-> Top App Bar -->
    <v-app-bar 
      elevation="1" 
      color="surface" 
      density="compact"
      class="gc-border-bottom"
    >
      <v-app-bar-nav-icon @click="drawer = !drawer" color="secondary" />
      <v-toolbar-title class="text-subtitle-1 font-weight-medium">
        <v-icon color="primary" class="mr-2" size="large">mdi-google-cloud</v-icon>
        Google Cloud Anthos (ZTA)
      </v-toolbar-title>

      <v-spacer></v-spacer>

      <!-- Security Pulse -->
      <div class="d-flex align-center mr-4">
        <v-tooltip text="Active IAM Sessions" location="bottom">
          <template v-slot:activator="{ props }">
            <v-chip v-bind="props" size="small" variant="flat" color="blue-darken-1" class="mr-2 px-3 font-weight-medium">
              <v-icon start size="small">mdi-shield-account</v-icon>
              3 IAM Sessions
            </v-chip>
          </template>
        </v-tooltip>

        <v-tooltip text="Workloads with Drift" location="bottom">
          <template v-slot:activator="{ props }">
            <v-chip v-bind="props" size="small" variant="flat" color="orange-darken-1" class="mr-2 px-3 font-weight-medium text-black">
              <v-icon start size="small" class="text-black">mdi-alert-decagram</v-icon>
              1 SCC Alert
            </v-chip>
          </template>
        </v-tooltip>

        <v-tooltip text="Critical Posture Alerts" location="bottom">
          <template v-slot:activator="{ props }">
            <v-chip v-bind="props" size="small" variant="flat" color="red-darken-1" class="px-3 font-weight-medium">
              <v-icon start size="small">mdi-security-network</v-icon>
              0 Posture Findings
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
      <v-avatar 
        color="primary" 
        size="32" 
        class="ml-2 mr-3 text-caption font-weight-bold" 
        :title="userProfile?.email || 'Loading...'"
      >
        {{ userProfile ? getInitials(userProfile.name) : '...' }}
      </v-avatar>
    </v-app-bar>

    <-> Side Navigation Sidebar -->
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

    <-> Main Content Area -->
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
              
              <v-expansion-panels variant="accordion" class="mt-2 text-caption">
                <v-expansion-panel
                  title="Technical Details (Trace)"
                  class="bg-transparent"
                  elevation="0"
                >
                  <v-expansion-panel-text>
                    <div class="font-mono bg-black pa-2 rounded mt-1" style="word-break: break-all; white-space: pre-wrap;">
                      Code: {{ alert.error_code }}<br>
                      Component: {{ alert.component }}<br>
                      Trace: {{ alert.trace_id }}<br>
                      <br>
                      {{ alert.technical_details }}
                    </div>
                  </v-expansion-panel-text>
                </v-expansion-panel>
              </v-expansion-panels>
            </v-alert>
          </transition-group>
        </div>
        <-> Breadcrumbs -->
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
</style>
