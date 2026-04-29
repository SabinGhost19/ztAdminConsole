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

interface Group {
  id: string
  name: string
  attributes?: Record<string, string[]>
}

interface UserWithGroups extends User {
  groups: Group[]
}

const users = ref<User[]>([])
const groups = ref<Group[]>([])
const isLoading = ref(true)
const currentTab = ref('users')
const selectedUser = ref<UserWithGroups | null>(null)
const showUserDetails = ref(false)
const showCreateGroupDialog = ref(false)
const newGroupName = ref('')
const newGroupDescription = ref('')

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

async function fetchGroups() {
  isLoading.value = true
  try {
    const response = await api.get('/jit/iam/groups')
    groups.value = response.data.groups || []
  } catch (error) {
    console.error('Failed to fetch IAM groups', error)
  } finally {
    isLoading.value = false
  }
}

async function fetchUserGroups(userId: string) {
  try {
    const response = await api.get(`/jit/iam/users/${userId}/groups`)
    return response.data.groups || []
  } catch (error) {
    console.error(`Failed to fetch groups for user ${userId}`, error)
    return []
  }
}

async function viewUserDetails(user: User) {
  const userWithGroups = { ...user, groups: [] } as UserWithGroups
  userWithGroups.groups = await fetchUserGroups(user.id)
  selectedUser.value = userWithGroups
  showUserDetails.value = true
}

async function createGroup() {
  if (!newGroupName.value.trim()) return
  
  try {
    await api.post('/jit/iam/groups', {
      name: newGroupName.value,
      description: newGroupDescription.value,
    })
    newGroupName.value = ''
    newGroupDescription.value = ''
    showCreateGroupDialog.value = false
    await fetchGroups()
  } catch (error) {
    console.error('Failed to create group', error)
  }
}

async function addUserToGroup(userId: string, groupId: string) {
  try {
    await api.put(`/jit/iam/users/${userId}/groups/${groupId}`)
    if (selectedUser.value) {
      selectedUser.value.groups = await fetchUserGroups(userId)
    }
  } catch (error) {
    console.error('Failed to add user to group', error)
  }
}

async function removeUserFromGroup(userId: string, groupId: string) {
  try {
    await api.delete(`/jit/iam/users/${userId}/groups/${groupId}`)
    if (selectedUser.value) {
      selectedUser.value.groups = await fetchUserGroups(userId)
    }
  } catch (error) {
    console.error('Failed to remove user from group', error)
  }
}

onMounted(() => {
  fetchUsers()
  fetchGroups()
})
</script>

<template>
  <v-container fluid>
    <div class="d-flex align-center justify-space-between mb-4">
      <h1 class="text-h5 font-weight-medium text-primary">
        <v-icon start color="primary">mdi-account-group</v-icon>
        Identity & Access Management (IAM)
      </h1>
      <v-btn color="primary" variant="tonal" prepend-icon="mdi-refresh" @click="currentTab === 'users' ? fetchUsers() : fetchGroups()" :loading="isLoading">
        Refresh
      </v-btn>
    </div>

    <v-card class="gc-border" flat>
      <v-card-text>
        <p class="text-caption text-secondary mb-4">
          Utilizatorii sincronizați din FreeIPA via Keycloak LDAP Federation. Gestionează grupuri și asocieri de utilizatori pentru control de acces JIT.
        </p>

        <v-tabs v-model="currentTab" class="mb-4">
          <v-tab value="users">
            <v-icon start>mdi-account</v-icon>
            Users
          </v-tab>
          <v-tab value="groups">
            <v-icon start>mdi-account-multiple</v-icon>
            Groups
          </v-tab>
        </v-tabs>

        <!-- USERS TAB -->
        <v-skeleton-loader v-if="isLoading && currentTab === 'users'" type="table"></v-skeleton-loader>
        
        <v-table v-else-if="currentTab === 'users'" density="comfortable" class="border rounded" hover>
          <thead>
            <tr class="bg-surface-variant">
              <th class="text-left font-weight-medium">Username</th>
              <th class="text-left font-weight-medium">Name</th>
              <th class="text-left font-weight-medium">Email</th>
              <th class="text-center font-weight-medium">Status</th>
              <th class="text-center font-weight-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in users" :key="user.id" class="cursor-pointer hover:bg-surface-variant transition-colors">
              <td class="font-weight-medium">{{ user.username }}</td>
              <td>{{ user.firstName }} {{ user.lastName }}</td>
              <td class="text-secondary">{{ user.email }}</td>
              <td class="text-center">
                <v-chip :color="user.enabled ? 'success' : 'error'" size="small" variant="flat" class="px-3">
                  <v-icon start size="x-small">{{ user.enabled ? 'mdi-check-circle' : 'mdi-cancel' }}</v-icon>
                  {{ user.enabled ? 'Active' : 'Disabled' }}
                </v-chip>
              </td>
              <td class="text-center">
                <v-btn size="small" variant="text" color="primary" @click="viewUserDetails(user)">
                  <v-icon>mdi-chevron-right</v-icon>
                </v-btn>
              </td>
            </tr>
            <tr v-if="users.length === 0">
              <td colspan="5" class="text-center text-secondary py-4">Nu am găsit utilizatori sincronizați.</td>
            </tr>
          </tbody>
        </v-table>

        <!-- GROUPS TAB -->
        <div v-if="currentTab === 'groups'" class="mt-4">
          <v-btn color="primary" prepend-icon="mdi-plus" @click="showCreateGroupDialog = true" class="mb-4">
            Create Group
          </v-btn>

          <v-skeleton-loader v-if="isLoading" type="card"></v-skeleton-loader>

          <div v-else class="d-grid gap-4" style="grid-template-columns: repeat(auto-fill, minmax(250px, 1fr))">
            <v-card v-for="group in groups" :key="group.id" class="gc-border">
              <v-card-title class="d-flex align-center justify-space-between">
                <span class="text-truncate">{{ group.name }}</span>
                <v-icon size="small" color="primary">mdi-account-multiple</v-icon>
              </v-card-title>
              <v-card-text>
                <p v-if="group.attributes?.description" class="text-caption text-secondary mb-0">
                  {{ group.attributes.description[0] }}
                </p>
                <p v-else class="text-caption text-secondary mb-0">No description</p>
              </v-card-text>
              <v-card-actions>
                <v-btn size="small" variant="text" color="secondary" @click="() => {}">
                  View Details
                </v-btn>
              </v-card-actions>
            </v-card>
          </div>

          <p v-if="!isLoading && groups.length === 0" class="text-center text-secondary py-4">
            No groups yet. Create one to get started.
          </p>
        </div>
      </v-card-text>
    </v-card>

    <!-- User Details Dialog -->
    <v-dialog v-model="showUserDetails" max-width="600">
      <v-card v-if="selectedUser" class="gc-border">
        <v-card-title class="d-flex align-center">
          <v-icon start color="primary">mdi-account</v-icon>
          {{ selectedUser.firstName }} {{ selectedUser.lastName }}
        </v-card-title>
        <v-card-text>
          <div class="text-caption text-secondary mb-4">
            <p class="mb-1"><strong>Username:</strong> {{ selectedUser.username }}</p>
            <p class="mb-1"><strong>Email:</strong> {{ selectedUser.email }}</p>
            <p><strong>Status:</strong> {{ selectedUser.enabled ? 'Active' : 'Disabled' }}</p>
          </div>

          <v-divider class="my-4"></v-divider>

          <h4 class="text-subtitle-2 font-weight-medium mb-3">Groups Membership</h4>
          <div class="mb-3">
            <v-chip
              v-for="group in selectedUser.groups"
              :key="group.id"
              closable
              class="me-2 mb-2"
              @click:close="removeUserFromGroup(selectedUser.id, group.id)"
            >
              {{ group.name }}
            </v-chip>
          </div>

          <v-select
            label="Add user to group"
            :items="groups"
            item-title="name"
            item-value="id"
            variant="outlined"
            density="compact"
            class="mt-2"
            @update:model-value="(groupId) => { if (groupId) addUserToGroup(selectedUser!.id, groupId as string) }"
          ></v-select>
        </v-card-text>
        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn variant="flat" @click="showUserDetails = false">Close</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- Create Group Dialog -->
    <v-dialog v-model="showCreateGroupDialog" max-width="400">
      <v-card class="gc-border">
        <v-card-title>Create New Group</v-card-title>
        <v-card-text>
          <v-text-field
            v-model="newGroupName"
            label="Group Name"
            placeholder="jit-access-demo-api"
            prepend-icon="mdi-account-multiple"
            variant="outlined"
            class="mb-4"
          ></v-text-field>
          <v-text-field
            v-model="newGroupDescription"
            label="Description"
            placeholder="Optional: Group description"
            prepend-icon="mdi-information"
            variant="outlined"
          ></v-text-field>
        </v-card-text>
        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn variant="flat" @click="showCreateGroupDialog = false">Cancel</v-btn>
          <v-btn color="primary" variant="flat" @click="createGroup">Create</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>
