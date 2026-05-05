<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '../store/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const requiredPermissions = computed<string[]>(() => {
  const raw = route.query.required as string | undefined
  if (!raw) return []
  return raw.split(',').filter(Boolean)
})

const targetPath = computed<string>(() => {
  return (route.query.target as string) || '/'
})

const groupsThatGrant = computed<string[]>(() => {
  if (!auth.matrix || requiredPermissions.value.length === 0) return []
  const out = new Set<string>()
  for (const [group, perms] of Object.entries(auth.matrix.matrix || {})) {
    for (const p of requiredPermissions.value) {
      if (perms.includes(p)) {
        out.add(group)
        break
      }
    }
  }
  return Array.from(out).sort()
})

const myGroups = computed<string[]>(() => auth.identity?.groups || [])
const myEmail = computed<string>(() => auth.identity?.email || 'unknown')

function goHome() {
  router.push('/')
}

function refreshSession() {
  auth.refresh().then(() => router.push(targetPath.value))
}
</script>

<template>
  <v-container fluid>
    <v-row justify="center">
      <v-col cols="12" md="8" lg="6">
        <v-card class="gc-border" flat>
          <v-card-title class="d-flex align-center">
            <v-icon color="warning" size="32" class="mr-3">mdi-shield-lock-outline</v-icon>
            <span class="text-h6">Acces refuzat</span>
          </v-card-title>

          <v-divider />

          <v-card-text>
            <p class="text-body-1 mb-4">
              Contul <strong>{{ myEmail }}</strong> nu deține permisiunile necesare pentru a
              accesa <code>{{ targetPath }}</code>.
            </p>

            <v-alert
              v-if="requiredPermissions.length"
              type="info"
              variant="tonal"
              border="start"
              class="mb-4"
              icon="mdi-key-variant"
            >
              <div class="text-subtitle-2 font-weight-medium mb-1">Permisiuni necesare</div>
              <div class="d-flex flex-wrap ga-2">
                <v-chip
                  v-for="p in requiredPermissions"
                  :key="p"
                  size="small"
                  variant="outlined"
                  color="primary"
                >
                  {{ p }}
                </v-chip>
              </div>
            </v-alert>

            <v-alert
              v-if="groupsThatGrant.length"
              type="warning"
              variant="tonal"
              border="start"
              class="mb-4"
              icon="mdi-account-multiple-check"
            >
              <div class="text-subtitle-2 font-weight-medium mb-1">
                Solicită admiterea în unul dintre grupurile:
              </div>
              <div class="d-flex flex-wrap ga-2">
                <v-chip
                  v-for="g in groupsThatGrant"
                  :key="g"
                  size="small"
                  variant="flat"
                  color="orange-darken-2"
                >
                  {{ g }}
                </v-chip>
              </div>
              <div class="text-caption text-medium-emphasis mt-2">
                Apropiere-te de un platform-engineer; modificările trebuie făcute în FreeIPA și se
                propagă în Keycloak la următorul login.
              </div>
            </v-alert>

            <div class="text-subtitle-2 font-weight-medium mb-1">Grupurile tale curente</div>
            <div v-if="myGroups.length" class="d-flex flex-wrap ga-2 mb-4">
              <v-chip v-for="g in myGroups" :key="g" size="small" variant="outlined">
                {{ g }}
              </v-chip>
            </div>
            <div v-else class="text-caption text-medium-emphasis mb-4">
              Nu ești în niciun grup mapat. Contactează administratorul FreeIPA.
            </div>
          </v-card-text>

          <v-divider />

          <v-card-actions>
            <v-btn variant="text" @click="goHome">
              <v-icon start>mdi-arrow-left</v-icon> Mergi la Overview
            </v-btn>
            <v-spacer />
            <v-btn variant="outlined" color="primary" @click="refreshSession">
              <v-icon start>mdi-refresh</v-icon> Reîncearcă (refresh sesiune)
            </v-btn>
          </v-card-actions>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>
