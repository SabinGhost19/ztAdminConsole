<script setup lang="ts">
import { computed } from 'vue'
import DescribeSection from '../common/DescribeSection.vue'
import DescribeField from '../common/DescribeField.vue'

interface BoundApp {
  metadata?: { name?: string; namespace?: string; uid?: string }
  summary?: { trustLevel?: string; securityState?: string; securityPolicyRef?: string }
}

const props = withDefaults(defineProps<{
  sca: any
  boundApps?: BoundApp[]
}>(), {
  boundApps: () => [],
})

const meta = computed(() => props.sca?.metadata || {})
const spec = computed(() => props.sca?.spec || {})
const summary = computed(() => props.sca?.summary || {})

const sbomPolicy = computed(() => spec.value.sbomPolicy || {})
const slsa = computed(() => spec.value.slsaProvenancePolicy || {})
const openVex = computed(() => spec.value.openVexPolicy || {})
const securityScan = computed(() => spec.value.securityScanPolicy || {})
const policyBinding = computed(() => spec.value.policyBinding || {})
const runtime = computed(() => spec.value.runtimeEnforcement || {})
const mh = computed(() => summary.value.strictManifestHash || {})
const customRules = computed<any[]>(() => summary.value.customRules || spec.value.customRules || [])

const coverage = computed(() => {
  const apps = props.boundApps || []
  return {
    total: apps.length,
    verified: apps.filter((a) => a.summary?.trustLevel === 'Verified').length,
    compliant: apps.filter((a) => a.summary?.securityState === 'Compliant').length,
    alert: apps.filter((a) => a.summary?.securityState === 'Alert').length,
  }
})

function yn(v: any): string { return v ? 'true' : 'false' }
function boolTone(v: any): 'ok' | 'muted' { return v ? 'ok' : 'muted' }

function pkgLabel(p: any): string {
  if (!p) return ''
  if (typeof p === 'string') return p
  return p.maxVersion ? `${p.name}@${p.maxVersion}` : String(p.name || '')
}

function actionColor(action?: string): string {
  switch (String(action || '').toLowerCase()) {
    case 'kill':
    case 'reject':
    case 'deny': return 'error'
    case 'isolate': return 'warning'
    case 'alert': return 'info'
    case 'allow': return 'success'
    default: return 'secondary'
  }
}

function createdAt(): string {
  const v = meta.value.createdAt
  if (!v) return '—'
  try { return new Date(v).toLocaleString() } catch { return String(v) }
}
</script>

<template>
  <div class="sca-describe-panel">
    <div class="describe-header">
      <v-icon size="16" color="secondary" class="mr-2">mdi-file-search-outline</v-icon>
      <span class="text-body-2 font-weight-medium">{{ meta.name }}</span>
      <span class="text-caption text-secondary ml-2">· SupplyChainAttestation</span>
    </div>

    <DescribeSection title="Identity">
      <DescribeField label="name" :value="meta.name" />
      <DescribeField label="scope" value="Cluster" />
      <DescribeField label="uid" :value="meta.uid" tone="muted" />
      <DescribeField label="created" :value="createdAt()" />
    </DescribeSection>

    <DescribeSection title="Bound workloads">
      <DescribeField label="bound" :value="coverage.total" />
      <DescribeField label="verified" :value="coverage.verified" :tone="coverage.verified ? 'ok' : 'default'" />
      <DescribeField label="compliant" :value="coverage.compliant" />
      <DescribeField label="alert" :value="coverage.alert" :tone="coverage.alert ? 'warn' : 'muted'" />
      <div v-if="boundApps.length" class="bound-list" style="grid-column: 1 / -1;">
        <div v-for="a in boundApps" :key="a.metadata?.uid || a.metadata?.name" class="bound-row">
          {{ a.metadata?.namespace }}/{{ a.metadata?.name }}
          <span class="text-secondary">— {{ a.summary?.securityState || '—' }} · {{ a.summary?.trustLevel || '—' }}</span>
        </div>
      </div>
    </DescribeSection>

    <DescribeSection title="Source Validation">
      <DescribeField label="enforceCosign" :value="yn(summary.enforceCosign)" :tone="boolTone(summary.enforceCosign)" />
      <DescribeField label="trustedIssuers" :value="(summary.trustedIssuers || []).join(', ')" />
    </DescribeSection>

    <DescribeSection title="Provenance">
      <DescribeField label="requireVoucher" :value="yn(summary.requireVoucher)" :tone="boolTone(summary.requireVoucher)" />
      <DescribeField label="enforceHmacChain" :value="yn(summary.enforceHmacChain)" :tone="boolTone(summary.enforceHmacChain)" />
      <DescribeField label="minSlsaLevel" :value="summary.minSlsaLevel" />
      <DescribeField label="trustedRepositories" :value="(summary.trustedRepositories || []).join(', ')" />
    </DescribeSection>

    <DescribeSection title="Vulnerability Policy">
      <DescribeField label="maxAllowedSeverity" :value="summary.maxAllowedSeverity" />
      <DescribeField label="failOnFixable" :value="yn(summary.failOnFixable)" :tone="boolTone(summary.failOnFixable)" />
    </DescribeSection>

    <DescribeSection title="SBOM Policy">
      <DescribeField label="enforceSBOM" :value="yn(summary.enforceSBOM)" :tone="boolTone(summary.enforceSBOM)" />
      <DescribeField label="forbiddenPackages" :value="(sbomPolicy.forbiddenPackages || []).map(pkgLabel).join(', ')" />
    </DescribeSection>

    <DescribeSection v-if="Object.keys(slsa).length" title="SLSA Provenance">
      <DescribeField label="enforceSlsa" :value="yn(slsa.enforceSlsa)" :tone="boolTone(slsa.enforceSlsa)" />
      <DescribeField label="requiredLevel" :value="slsa.requiredLevel" />
      <DescribeField label="trustedIssuers" :value="(slsa.trustedIssuers || []).join(', ')" />
      <DescribeField label="trustedBuilders" :value="(slsa.trustedBuilders || []).join(', ')" />
      <DescribeField label="allowedBuildTypes" :value="(slsa.allowedBuildTypes || []).join(', ')" />
    </DescribeSection>

    <DescribeSection v-if="Object.keys(openVex).length" title="OpenVEX">
      <DescribeField label="enforceOpenVex" :value="yn(openVex.enforceOpenVex)" :tone="boolTone(openVex.enforceOpenVex)" />
      <DescribeField label="requireStatements" :value="yn(openVex.requireStatements)" :tone="boolTone(openVex.requireStatements)" />
    </DescribeSection>

    <DescribeSection v-if="Object.keys(securityScan).length" title="Security Scan">
      <DescribeField label="enforceSecurityScan" :value="yn(securityScan.enforceSecurityScan)" :tone="boolTone(securityScan.enforceSecurityScan)" />
      <DescribeField label="requireAttestation" :value="yn(securityScan.requireAttestation)" :tone="boolTone(securityScan.requireAttestation)" />
      <DescribeField label="failOnSecrets" :value="yn(securityScan.failOnSecrets)" :tone="boolTone(securityScan.failOnSecrets)" />
      <DescribeField label="maxIacSeverity" :value="securityScan.maxIacSeverity" />
      <DescribeField label="maxSastSeverity" :value="securityScan.maxSastSeverity" />
    </DescribeSection>

    <DescribeSection title="Manifest Hash">
      <DescribeField label="enabled" :value="yn(mh.enabled)" :tone="boolTone(mh.enabled)" />
      <DescribeField label="enforcementAction" :value="mh.enforcementAction" />
      <DescribeField v-if="mh.isAuditMode" label="mode" value="audit (alert only)" tone="warn" />
    </DescribeSection>

    <DescribeSection v-if="Object.keys(policyBinding).length" title="Policy Binding">
      <DescribeField label="enabled" :value="yn(policyBinding.enabled)" :tone="boolTone(policyBinding.enabled)" />
      <DescribeField label="requireAttestationType" :value="policyBinding.requireAttestationType" />
    </DescribeSection>

    <DescribeSection title="Runtime Enforcement">
      <DescribeField label="enabled" :value="yn(runtime.enabled)" :tone="boolTone(runtime.enabled)" />
      <DescribeField label="onPolicyDrift" :value="summary.onPolicyDrift" />
      <DescribeField label="onVulnerabilityFound" :value="summary.onVulnerabilityFound" />
    </DescribeSection>

    <DescribeSection v-if="customRules.length" :title="`Custom Rules (CEL) · ${customRules.length}`" :grid="false">
      <div v-for="(rule, i) in customRules" :key="i" class="rule-row">
        <div class="rule-head">
          <span class="rule-name">{{ rule.name || 'unnamed' }}</span>
          <v-chip size="x-small" variant="tonal" :color="actionColor(rule.action)">{{ rule.action || 'Deny' }}</v-chip>
        </div>
        <div v-if="rule.description" class="rule-desc text-secondary">{{ rule.description }}</div>
        <pre class="rule-expr">{{ rule.expression || '—' }}</pre>
      </div>
    </DescribeSection>
  </div>
</template>

<style scoped>
.sca-describe-panel {
  padding: 14px 20px;
  background: rgba(var(--v-theme-on-surface), 0.02);
}
.describe-header {
  display: flex;
  align-items: center;
  padding: 4px 0 8px;
}
.bound-list { margin-top: 4px; display: grid; gap: 2px; }
.bound-row {
  font-family: 'Roboto Mono', monospace;
  font-size: 0.76rem;
  color: rgba(var(--v-theme-on-surface), 0.85);
}
.rule-row {
  padding: 8px 0;
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.06);
}
.rule-row:last-child { border-bottom: none; }
.rule-head { display: flex; align-items: center; gap: 8px; }
.rule-name { font-weight: 600; font-size: 0.82rem; }
.rule-desc { font-size: 0.74rem; margin-top: 2px; }
.rule-expr {
  margin: 6px 0 0;
  padding: 8px 10px;
  font-family: 'Roboto Mono', monospace;
  font-size: 0.76rem;
  white-space: pre-wrap;
  word-break: break-word;
  background: rgba(var(--v-theme-on-surface), 0.04);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.08);
  border-radius: 6px;
}
</style>
