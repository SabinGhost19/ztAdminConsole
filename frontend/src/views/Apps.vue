<script setup lang="ts">
import { ref, computed } from 'vue'

const step = ref(1)
const isSubmitting = ref(false)

const form = ref({
  name: '',
  namespace: 'default',
  image: '',
  replicas: 1,
  ingressNamespace: '',
  egressNamespace: '',
  wafProfile: 'REST-API',
  vaultPath: ''
})

const wafProfiles = ['REST-API', 'SPA', 'GRPC', 'Strict-Baseline']

const imageError = computed(() => {
  if (!form.value.image) return ''
  if (!form.value.image.startsWith('ghcr.io/')) return 'Violation: Imaginea trebuie să fie din ghcr.io/'
  if (form.value.image.endsWith(':latest')) return 'Violation: Tag-ul "latest" este strict interzis în producție.'
  return ''
})

const isStep1Valid = computed(() => form.value.name.length > 2 && form.value.image.length > 5 && !imageError.value)

function submitDeclaration() {
  isSubmitting.value = true
  setTimeout(() => {
    isSubmitting.value = false
    step.value = 1
  }, 1500)
}
</script>

<template>
  <div>
    <h1 class="text-h5 font-weight-medium mb-4 text-primary">ZTA Application Builder</h1>
    <v-card class="gc-border" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
      <v-card-text class="pa-0">
        <v-stepper v-model="step" elevation="0" bg-color="surface" hide-actions>
          <v-stepper-header class="gc-border-bottom">
            <v-stepper-item :value="1" title="Core & Supply Chain" :complete="step > 1" value-icon="mdi-check" color="primary"></v-stepper-item>
            <v-divider></v-divider>
            <v-stepper-item :value="2" title="Network & WAF" :complete="step > 2" value-icon="mdi-check" color="primary"></v-stepper-item>
            <v-divider></v-divider>
            <v-stepper-item :value="3" title="Secret Strategy" :complete="step > 3" value-icon="mdi-check" color="primary"></v-stepper-item>
            <v-divider></v-divider>
            <v-stepper-item :value="4" title="Review & Commit" color="primary"></v-stepper-item>
          </v-stepper-header>

          <v-stepper-window>
            <v-stepper-window-item :value="1">
              <div class="pa-4">
                <h3 class="text-subtitle-1 font-weight-medium mb-4">Application Fundamentals</h3>
                <v-row>
                  <v-col cols="12" md="6">
                    <v-text-field v-model="form.name" label="App Name" variant="outlined" density="compact"></v-text-field>
                  </v-col>
                  <v-col cols="12" md="6">
                    <v-text-field v-model="form.namespace" label="Target Namespace" variant="outlined" density="compact"></v-text-field>
                  </v-col>
                  <v-col cols="12">
                    <v-text-field 
                      v-model="form.image" 
                      label="Container Image" 
                      variant="outlined" 
                      density="compact"
                      hint="Must be hosted on GHCR and signed with Cosign"
                      persistent-hint
                      :error-messages="imageError ? [imageError] : []"
                    >
                      <template v-slot:prepend-inner>
                        <v-icon :color="imageError ? 'error' : 'default'">mdi-docker</v-icon>
                      </template>
                    </v-text-field>
                    <v-alert v-if="imageError" type="error" variant="tonal" density="compact" class="mt-2 text-caption">
                      Politica Zero-Trust (Kyverno) va bloca acest deployment! Asigurați-vă că respectați regulile lanțului de aprovizionare.
                    </v-alert>
                  </v-col>
                </v-row>
                <div class="d-flex mt-6">
                  <v-spacer></v-spacer>
                  <v-btn color="primary" @click="step = 2" :disabled="!isStep1Valid" variant="flat">Continue to Network</v-btn>
                </div>
              </div>
            </v-stepper-window-item>

            <v-stepper-window-item :value="2">
              <div class="pa-4">
                <h3 class="text-subtitle-1 font-weight-medium mb-4">Microsegmentation & Coraza WAF</h3>
                <v-row>
                  <v-col cols="12" md="6">
                    <v-text-field v-model="form.ingressNamespace" label="Allow Ingress From" variant="outlined" density="compact"></v-text-field>
                  </v-col>
                  <v-col cols="12" md="6">
                    <v-text-field v-model="form.egressNamespace" label="Allow Egress To" variant="outlined" density="compact"></v-text-field>
                  </v-col>
                  <v-col cols="12">
                    <v-select v-model="form.wafProfile" :items="wafProfiles" label="Coraza WAF Profile" variant="outlined" density="compact"></v-select>
                  </v-col>
                </v-row>
                <div class="d-flex mt-6">
                  <v-btn variant="text" @click="step = 1">Back</v-btn>
                  <v-spacer></v-spacer>
                  <v-btn color="primary" @click="step = 3" variant="flat">Continue to Secrets</v-btn>
                </div>
              </div>
            </v-stepper-window-item>

            <v-stepper-window-item :value="3">
              <div class="pa-4">
                 <h3 class="text-subtitle-1 font-weight-medium mb-4">Zero-Trust Secret Delegation (ZTS)</h3>
                 <p class="text-body-2 text-secondary mb-4">Delegați managementul secretelor către HashiCorp Vault via External Secrets Operator.</p>
                 <v-text-field v-model="form.vaultPath" label="Vault Secret Path" variant="outlined" density="compact" placeholder="secret/data/production/myapp"></v-text-field>
                 <v-switch color="primary" label="Enable Auto-Rolling Restart" inset density="compact" class="ml-2"></v-switch>
                 
                 <div class="d-flex mt-6">
                  <v-btn variant="text" @click="step = 2">Back</v-btn>
                  <v-spacer></v-spacer>
                  <v-btn color="primary" @click="step = 4" variant="flat">Review Declaration</v-btn>
                </div>
              </div>
            </v-stepper-window-item>

            <v-stepper-window-item :value="4">
              <div class="pa-4">
                 <h3 class="text-subtitle-1 font-weight-medium mb-4">Review & Propose via GitOps</h3>
                 
                 <div class="bg-surface-variant pa-4 rounded gc-border font-mono text-caption overflow-auto" style="max-height: 250px;">
apiVersion: devsecops.licenta.ro/v1alpha1
kind: ZeroTrustApplication
metadata:
  name: {{ form.name || 'myapp' }}
  namespace: {{ form.namespace || 'default' }}
spec:
  image: {{ form.image || 'ghcr.io/org/app:v1' }}
  replicas: {{ form.replicas }}
  networkPolicy:
    ingressFromNamespace: {{ form.ingressNamespace || 'none' }}
    egressToNamespace: {{ form.egressNamespace || 'none' }}
  waf:
    profile: {{ form.wafProfile }}
  secrets:
    vaultPath: {{ form.vaultPath || 'none' }}
                 </div>

                 <div class="d-flex mt-6">
                  <v-btn variant="text" @click="step = 3">Edit Specs</v-btn>
                  <v-spacer></v-spacer>
                  <v-btn color="success" @click="submitDeclaration" :loading="isSubmitting" variant="flat" prepend-icon="mdi-git">Push to Main</v-btn>
                </div>
              </div>
            </v-stepper-window-item>

          </v-stepper-window>
        </v-stepper>
      </v-card-text>
    </v-card>
  </div>
</template>
