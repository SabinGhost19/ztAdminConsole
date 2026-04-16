<script setup lang="ts">
defineProps<{
  groups: Array<Record<string, any>>
}>()
</script>

<template>
  <div class="sbom-shell">
    <div class="text-subtitle-2 font-weight-medium mb-3">SBOM Dependency Tree</div>
    <div v-if="!groups?.length" class="text-caption text-secondary">SBOM packages are not exposed yet by the attestation payload.</div>
    <v-expansion-panels v-else variant="accordion">
      <v-expansion-panel v-for="group in groups" :key="group.ecosystem">
        <v-expansion-panel-title>
          <div class="d-flex align-center justify-space-between w-100 pr-4">
            <span>{{ group.ecosystem }}</span>
            <v-chip size="x-small" variant="tonal">{{ group.packages?.length || 0 }} packages</v-chip>
          </div>
        </v-expansion-panel-title>
        <v-expansion-panel-text>
          <v-list density="compact">
            <v-list-item v-for="pkg in group.packages" :key="`${group.ecosystem}-${pkg.name}-${pkg.version}`">
              <v-list-item-title>{{ pkg.name }}</v-list-item-title>
              <v-list-item-subtitle>{{ pkg.version }}<span v-if="pkg.purl"> • {{ pkg.purl }}</span></v-list-item-subtitle>
            </v-list-item>
          </v-list>
        </v-expansion-panel-text>
      </v-expansion-panel>
    </v-expansion-panels>
  </div>
</template>

<style scoped>
.sbom-shell {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 16px;
  padding: 16px;
}
</style>