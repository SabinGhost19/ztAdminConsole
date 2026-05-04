<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { api } from '../api/axios'
import { useNotificationStore } from '../store/notification'

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
const userSearch = ref('')
const groupSearch = ref('')

const showGroupDialog = ref(false)
const isEditingGroup = ref(false)
const groupForm = ref({
  id: '',
  name: '',
  description: ''
})
const showDeleteGroupDialog = ref(false)
const groupToDelete = ref<Group | null>(null)

const showUserStatusDialog = ref(false)
const pendingUserStatus = ref(true)
const notifyStore = useNotificationStore()

function notifyError(error: any, fallbackMessage: string) {
  const data = error?.response?.data || {}
  const traceId = data.trace_id || data.traceId || `UI-${Math.random().toString(36).substring(2)}`
  notifyStore.addAlert({
    error_code: data.error_code || 'IAM_UI_ERROR',
    message: data.message || fallbackMessage,
    technical_details: data.technical_details || error?.message || 'Unknown error',
    component: data.component || 'IAM_MODULE',
    trace_id: traceId,
    action_required: data.action_required || 'Verifica detaliile si reincearca.',
    status_code: data.status_code || error?.response?.status,
    request_method: data.request_method || error?.config?.method?.toUpperCase(),
    request_path: data.request_path || error?.config?.url,
    timestamp: data.timestamp || new Date().toISOString(),
    source: 'backend',
    details: data.details || null,
    type: 'error'
  })
}

async function fetchUsers() {
  isLoading.value = true
  try {
    const response = await api.get('/jit/iam/users', { skipGlobalErrorAlert: true })
    users.value = response.data.users || []
  } catch (error) {
    notifyError(error, 'Nu pot incarca lista de utilizatori.')
  } finally {
    isLoading.value = false
  }
}

async function fetchGroups() {
  isLoading.value = true
  try {
    const response = await api.get('/jit/iam/groups', { skipGlobalErrorAlert: true })
    groups.value = response.data.groups || []
  } catch (error) {
    notifyError(error, 'Nu pot incarca lista de grupuri.')
  } finally {
    isLoading.value = false
  }
}

async function fetchUserGroups(userId: string) {
  try {
    const response = await api.get(`/jit/iam/users/${userId}/groups`, { skipGlobalErrorAlert: true })
    return response.data.groups || []
  } catch (error) {
    notifyError(error, `Nu pot incarca grupurile pentru user ${userId}.`)
    return []
  }
}

async function viewUserDetails(user: User) {
  const userWithGroups = { ...user, groups: [] } as UserWithGroups
  userWithGroups.groups = await fetchUserGroups(user.id)
  selectedUser.value = userWithGroups
  showUserDetails.value = true
}

function openCreateGroupDialog() {
  isEditingGroup.value = false
  groupForm.value = { id: '', name: '', description: '' }
  showGroupDialog.value = true
}

function openEditGroupDialog(group: Group) {
  isEditingGroup.value = true
  groupForm.value = {
    id: group.id,
    name: group.name,
    description: group.attributes?.description?.[0] || ''
  }
  showGroupDialog.value = true
}

async function saveGroup() {
  if (!groupForm.value.name.trim()) return

  try {
    if (isEditingGroup.value) {
      await api.put(`/jit/iam/groups/${groupForm.value.id}`, {
        name: groupForm.value.name,
        description: groupForm.value.description,
      }, { skipGlobalErrorAlert: true })
    } else {
      await api.post('/jit/iam/groups', {
        name: groupForm.value.name,
        description: groupForm.value.description,
      }, { skipGlobalErrorAlert: true })
    }
    showGroupDialog.value = false
    await fetchGroups()
  } catch (error) {
    notifyError(error, 'Nu pot salva grupul. Verifica datele si permisiunile.')
  }
}

function promptDeleteGroup(group: Group) {
  groupToDelete.value = group
  showDeleteGroupDialog.value = true
}

async function deleteGroup() {
  if (!groupToDelete.value) return

  try {
    await api.delete(`/jit/iam/groups/${groupToDelete.value.id}`, { skipGlobalErrorAlert: true })
    await fetchGroups()
  } catch (error) {
    notifyError(error, 'Nu pot sterge grupul selectat.')
  } finally {
    showDeleteGroupDialog.value = false
    groupToDelete.value = null
  }
}

async function addUserToGroup(userId: string, groupId: string) {
  try {
    await api.put(`/jit/iam/users/${userId}/groups/${groupId}`, {}, { skipGlobalErrorAlert: true })
    if (selectedUser.value) {
      selectedUser.value.groups = await fetchUserGroups(userId)
    }
  } catch (error) {
    notifyError(error, 'Nu pot adauga userul in grupul selectat.')
  }
}

async function removeUserFromGroup(userId: string, groupId: string) {
  try {
    await api.delete(`/jit/iam/users/${userId}/groups/${groupId}`, { skipGlobalErrorAlert: true })
    if (selectedUser.value) {
      selectedUser.value.groups = await fetchUserGroups(userId)
    }
  } catch (error) {
    notifyError(error, 'Nu pot elimina userul din grup.')
  }
}

function promptUserStatusChange(enabled: boolean) {
  pendingUserStatus.value = enabled
  showUserStatusDialog.value = true
}

async function updateUserStatus() {
  if (!selectedUser.value) return

  try {
    await api.put(`/jit/iam/users/${selectedUser.value.id}/status`, {
      enabled: pendingUserStatus.value,
    }, { skipGlobalErrorAlert: true })
    selectedUser.value.enabled = pendingUserStatus.value
    const index = users.value.findIndex((item) => item.id === selectedUser.value?.id)
    if (index >= 0) {
      users.value[index].enabled = pendingUserStatus.value
    }
  } catch (error) {
    notifyError(error, 'Nu pot actualiza statusul utilizatorului.')
  } finally {
    showUserStatusDialog.value = false
  }
}

const filteredUsers = computed(() => {
  const query = userSearch.value.trim().toLowerCase()
  if (!query) return users.value
  return users.value.filter((user) => {
    const fullName = `${user.firstName || ''} ${user.lastName || ''}`.trim().toLowerCase()
    return (
      user.username?.toLowerCase().includes(query) ||
      user.email?.toLowerCase().includes(query) ||
      fullName.includes(query)
    )
  })
})

const filteredGroups = computed(() => {
  const query = groupSearch.value.trim().toLowerCase()
  if (!query) return groups.value
  return groups.value.filter((group) => {
    const description = group.attributes?.description?.[0]?.toLowerCase() || ''
    return group.name.toLowerCase().includes(query) || description.includes(query)
  })
})

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
        <div v-if="currentTab === 'users'" class="d-flex flex-wrap align-center gap-4 mb-4">
          <v-text-field
            v-model="userSearch"
            label="Search users"
            prepend-icon="mdi-magnify"
            variant="outlined"
            density="compact"
            hide-details
            style="max-width: 320px"
          ></v-text-field>
          <v-chip variant="tonal" color="primary" class="text-caption">{{ filteredUsers.length }} users</v-chip>
        </div>
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
            <tr v-for="user in filteredUsers" :key="user.id" class="cursor-pointer hover:bg-surface-variant transition-colors">
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
            <tr v-if="filteredUsers.length === 0">
              <td colspan="5" class="text-center text-secondary py-4">Nu am găsit utilizatori sincronizați.</td>
            </tr>
          </tbody>
        </v-table>

        <!-- GROUPS TAB -->
        <div v-if="currentTab === 'groups'" class="mt-4">
          <div class="d-flex flex-wrap align-center gap-4 mb-4">
            <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreateGroupDialog">
              Create Group
            </v-btn>
            <v-text-field
              v-model="groupSearch"
              label="Search groups"
              prepend-icon="mdi-magnify"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 320px"
            ></v-text-field>
            <v-chip variant="tonal" color="primary" class="text-caption">{{ filteredGroups.length }} groups</v-chip>
          </div>

          <v-skeleton-loader v-if="isLoading" type="card"></v-skeleton-loader>

          <div v-else class="d-grid gap-4" style="grid-template-columns: repeat(auto-fill, minmax(250px, 1fr))">
            <v-card v-for="group in filteredGroups" :key="group.id" class="gc-border">
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
                <v-btn size="small" variant="text" color="primary" @click="openEditGroupDialog(group)">
                  Edit
                </v-btn>
                <v-btn size="small" variant="text" color="error" @click="promptDeleteGroup(group)">
                  Delete
                </v-btn>
              </v-card-actions>
            </v-card>
          </div>

          <p v-if="!isLoading && filteredGroups.length === 0" class="text-center text-secondary py-4">
            No groups yet. Create one to get started.
          </p>
        </div>
      </v-card-text>
    </v-card>

    <!-- User Details Dialog -->
    <v-dialog v-model="showUserDetails" max-width="640">
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

          <div class="d-flex align-center gap-2 mb-2">
            <v-btn
              size="small"
              variant="tonal"
              :color="selectedUser.enabled ? 'error' : 'success'"
              @click="promptUserStatusChange(!selectedUser.enabled)"
            >
              {{ selectedUser.enabled ? 'Disable User' : 'Enable User' }}
            </v-btn>
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

    <!-- Create / Edit Group Dialog -->
    <v-dialog v-model="showGroupDialog" max-width="420">
      <v-card class="gc-border">
        <v-card-title>{{ isEditingGroup ? 'Edit Group' : 'Create New Group' }}</v-card-title>
        <v-card-text>
          <v-text-field
            v-model="groupForm.name"
            label="Group Name"
            placeholder="jit-access-demo-api"
            prepend-icon="mdi-account-multiple"
            variant="outlined"
            class="mb-4"
          ></v-text-field>
          <v-text-field
            v-model="groupForm.description"
            label="Description"
            placeholder="Optional: Group description"
            prepend-icon="mdi-information"
            variant="outlined"
          ></v-text-field>
        </v-card-text>
        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn variant="flat" @click="showGroupDialog = false">Cancel</v-btn>
          <v-btn color="primary" variant="flat" @click="saveGroup">{{ isEditingGroup ? 'Save' : 'Create' }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- Delete Group Dialog -->
    <v-dialog v-model="showDeleteGroupDialog" max-width="420">
      <v-card class="gc-border">
        <v-card-title>Delete Group</v-card-title>
        <v-card-text>
          Sigur vrei sa stergi grupul <strong>{{ groupToDelete?.name }}</strong>?
        </v-card-text>
        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn variant="flat" @click="showDeleteGroupDialog = false">Cancel</v-btn>
          <v-btn color="error" variant="flat" @click="deleteGroup">Delete</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- User Status Dialog -->
    <v-dialog v-model="showUserStatusDialog" max-width="420">
      <v-card class="gc-border">
        <v-card-title>Update User Status</v-card-title>
        <v-card-text>
          Confirma ca vrei sa {{ pendingUserStatus ? 'activezi' : 'dezactivezi' }} userul
          <strong>{{ selectedUser?.username }}</strong>.
        </v-card-text>
        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn variant="flat" @click="showUserStatusDialog = false">Cancel</v-btn>
          <v-btn color="primary" variant="flat" @click="updateUserStatus">Confirm</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>
