<script setup lang="ts">
import { ref } from 'vue'

const currentOriginal = ref(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-app
  namespace: demo-namespace
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: demo-app
        image: ghcr.io/org/demo-app:v1
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000`)

const currentModified = ref(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-app
  namespace: demo-namespace
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: demo-app
        image: ghcr.io/org/demo-app:v1
        securityContext:
          runAsNonRoot: false
          runAsUser: 0`)

const MONACO_EDITOR_OPTIONS = {
  automaticLayout: true,
  formatOnType: true,
  formatOnPaste: true,
  readOnly: true,
  renderSideBySide: true,
  minimap: { enabled: false }
}

function copyPatch() {
  navigator.clipboard.writeText("Patch is copied (mock)!")
}
</script>

<template>
  <div class="h-100 d-flex flex-column">
    <h1 class="text-h5 font-weight-medium mb-4 text-primary">Security Posture & Drift Analyzer</h1>

    <v-card class="gc-border d-flex flex-column flex-grow-1" style="border: 1px solid rgba(var(--v-theme-on-surface), 0.12)" flat>
      <v-toolbar color="surface" density="compact" class="gc-border-bottom" elevation="0">
        <v-icon color="warning" class="mr-2 ml-4">mdi-alert-circle-outline</v-icon>
        <v-toolbar-title class="text-subtitle-2 font-weight-bold">
          Policy Drift Detected: <span class="font-mono text-secondary ml-1">deployment/demo-app</span>
        </v-toolbar-title>
        <v-spacer></v-spacer>

        <v-chip size="small" color="error" class="mr-4 font-weight-medium">
          Sancțiune: ISOLATED (Deny-All)
        </v-chip>

        <v-btn size="small" variant="outlined" color="primary" class="mr-4" @click="copyPatch">
          <v-icon start size="small">mdi-content-copy</v-icon>
          Copy Patch
        </v-btn>
      </v-toolbar>

      <v-card-text class="pa-0 flex-grow-1 position-relative" style="min-height: 500px;">
        <div class="d-flex align-center bg-surface-variant pa-2 gc-border-bottom text-caption font-weight-medium text-secondary">
          <div class="w-50 text-center font-mono"><v-icon size="x-small" color="success" class="mr-1">mdi-lock-check</v-icon> Source of Truth (GitOps/Signed)</div>
          <div class="w-50 text-center font-mono"><v-icon size="x-small" color="error" class="mr-1">mdi-lock-open-alert</v-icon> Current Cluster State (Drift)</div>
        </div>
        
        <vue-monaco-diff-editor
          theme="vs-dark"
          originalLanguage="yaml"
          modifiedLanguage="yaml"
          :original="currentOriginal"
          :modified="currentModified"
          :options="MONACO_EDITOR_OPTIONS"
          class="w-100 h-100 position-absolute"
        />
      </v-card-text>
    </v-card>
  </div>
</template>

<style scoped>
/* Asigurăm că editorul ocupă toată zona */
.h-100 { height: 100%; }
.v-card-text { overflow: hidden; }
</style>
