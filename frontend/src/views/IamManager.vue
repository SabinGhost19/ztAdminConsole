<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '../api/axios'

interface User {
  id: string
  username: string
  email: string
  firstName: string
  lastName: string
  enabled: boolean
}

const users = ref<User[]>([])
const isLoading = ref(true)

async function fetchUsers() {
  isLoading.value = true
  try {
    const response = await api.get('/jit/iam/users')
    users.value = response.data.users || []
  } catch (error) {
    console.error('Failed to fetch IAM users', error)
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  fetchUsers()
})
</script>

<template>
  <v-container fluid>
    <div class="d-flex align-center justify-space-between mb-4">
      <h1 class="text-h5 font-weight-medium text-primary">
        <v-icon start color="primary">mdi-account-group</v-icon>
        Identity & Access Management (IAM)
      </h1>
      <v-btn color="primary" variant="tonal" prepend-icon="mdi-refresh" @click="fetchUsers" :loading="isLoading">
        Refresh Identities
      </v-btn>
    </div>

    <v-card class="gc-border" flat>
      <v-card-text>
        <p class="text-caption text-secondary mb-4">
          Utilizatorii sincronizați din FreeIPA via Keycloak LDAP Federation. Orice ajustare a resurselor sau parolelor ar trebui făcută direct în instanța FreeIPA master.
        </p>

        <v-skeleton-loader v-if="isLoading" type="table"></v-skeleton-loader>
        
        <v-table v-else density="comfortable" class="border rounded" hover>
          <thead>
            <tr class="bg-surface-variant">
              <th class="text-left font-weight-medium">ID</th>
              <th class="text-left font-weight-medium">Username</th>
              <th class="text-left font-weight-medium">Name</th>
              <th class="text-left font-weight-medium">Email</th>
              <th class="text-center font-weight-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in users" :key="user.id" class="cursor-pointer hover:bg-surface-variant transition-colors">
              <td class="font-mono text-caption text-secondary">{{ user.id }}</td>
              <td class="font-weight-medium">{{ user.username }}</td>
              <td>{{ user.firstName }} {{ user.lastName }}</td>
              <td class="text-secondary">{{ user.email }}</td>
              <td class="text-center">
                <v-chip :color="user.enabled ? 'success' : 'error'" size="small" variant="flat" class="px-3">
                  <v-icon start size="x-small">{{ user.enabled ? 'mdi-check-circle' : 'mdi-cancel' }}</v-icon>
                  {{ user.enabled ? 'Active' : 'Disabled' }}
                </v-chip>
              </td>
            </tr>
            <tr v-if="users.length === 0">
              <td colspan="5" class="text-center text-secondary py-4">Nu am găsit utilizatori sincronizați. Re-evaluați conexiunea FreeIPA-Keycloak.</td>
            </tr>
          </tbody>
        </v-table>
      </v-card-text>
    </v-card>
  </v-container>
</template>
