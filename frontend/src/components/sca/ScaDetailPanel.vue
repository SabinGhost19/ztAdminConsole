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

    <DescribeSection title="Identity" hint="Who this policy is and how workloads reference it.">
      <DescribeField label="name" :value="meta.name"
        hint="Policy name. ZeroTrustApplication.securityPolicyRef.name binds a workload to this policy." />
      <DescribeField label="scope" value="Cluster"
        hint="SCA is cluster-scoped — a single policy can govern workloads across all namespaces." />
      <DescribeField label="uid" :value="meta.uid" tone="muted" hint="Kubernetes object UID of this policy." />
      <DescribeField label="created" :value="createdAt()" hint="When this policy was created in the cluster." />
    </DescribeSection>

    <DescribeSection title="Bound workloads" hint="ZeroTrustApplications that currently reference this policy.">
      <DescribeField label="bound" :value="coverage.total" hint="Number of workloads bound to this policy." />
      <DescribeField label="verified" :value="coverage.verified" :tone="coverage.verified ? 'ok' : 'default'"
        hint="Bound workloads whose trustLevel is Verified." />
      <DescribeField label="compliant" :value="coverage.compliant" hint="Bound workloads whose securityState is Compliant." />
      <DescribeField label="alert" :value="coverage.alert" :tone="coverage.alert ? 'warn' : 'muted'"
        hint="Bound workloads currently in Alert state." />
      <div v-if="boundApps.length" class="bound-list" style="grid-column: 1 / -1;">
        <div v-for="a in boundApps" :key="a.metadata?.uid || a.metadata?.name" class="bound-row">
          {{ a.metadata?.namespace }}/{{ a.metadata?.name }}
          <span class="text-secondary">— {{ a.summary?.securityState || '—' }} · {{ a.summary?.trustLevel || '—' }}</span>
        </div>
      </div>
    </DescribeSection>

    <DescribeSection title="Source Validation" hint="Container image signature verification (Cosign / keyless).">
      <DescribeField label="enforceCosign" :value="yn(summary.enforceCosign)" :tone="boolTone(summary.enforceCosign)"
        hint="Require a valid Cosign signature on the image before admission." />
      <DescribeField label="trustedIssuers" :items="summary.trustedIssuers || []"
        hint="OIDC / CI identities allowed to sign images (keyless Cosign), e.g. GitHub Actions OIDC." />
    </DescribeSection>

    <DescribeSection title="Provenance" hint="Build origin & delivery-chain integrity.">
      <DescribeField label="requireVoucher" :value="yn(summary.requireVoucher)" :tone="boolTone(summary.requireVoucher)"
        hint="Require a VBBI provenance voucher proving build origin and delivery chain." />
      <DescribeField label="enforceHmacChain" :value="yn(summary.enforceHmacChain)" :tone="boolTone(summary.enforceHmacChain)"
        hint="Validate the HMAC hash chain across pipeline stages (anti-tamper)." />
      <DescribeField label="minSlsaLevel" :value="summary.minSlsaLevel"
        hint="Minimum SLSA build-maturity level required (0–3)." />
      <DescribeField label="trustedRepositories" :items="summary.trustedRepositories || []"
        hint="Only these source repositories are accepted as artifact origin." />
    </DescribeSection>

    <DescribeSection title="Vulnerability Policy" hint="CVE thresholds applied to the image scan.">
      <DescribeField label="maxAllowedSeverity" :value="summary.maxAllowedSeverity"
        hint="Highest CVE severity tolerated before the policy acts." />
      <DescribeField label="failOnFixable" :value="yn(summary.failOnFixable)" :tone="boolTone(summary.failOnFixable)"
        hint="Fail even below threshold when a fix is available for the vulnerability." />
    </DescribeSection>

    <DescribeSection title="SBOM Policy" hint="Software Bill of Materials requirements.">
      <DescribeField label="enforceSBOM" :value="yn(summary.enforceSBOM)" :tone="boolTone(summary.enforceSBOM)"
        hint="Require a Software Bill of Materials to be present and valid." />
      <DescribeField label="forbiddenPackages" :items="(sbomPolicy.forbiddenPackages || []).map(pkgLabel)"
        hint="Package names (optionally version-bounded as name@maxVersion) that are disallowed." />
    </DescribeSection>

    <DescribeSection v-if="Object.keys(slsa).length" title="SLSA Provenance" hint="SLSA v1.0 provenance attestation enforcement.">
      <DescribeField label="enforceSlsa" :value="yn(slsa.enforceSlsa)" :tone="boolTone(slsa.enforceSlsa)"
        hint="Enforce a SLSA v1.0 provenance attestation (e.g. slsa-github-generator)." />
      <DescribeField label="requiredLevel" :value="slsa.requiredLevel"
        hint="Minimum SLSA level required by the provenance attestation." />
      <DescribeField label="trustedIssuers" :items="slsa.trustedIssuers || []"
        hint="Issuers allowed to sign the SLSA provenance (distinct from Cosign issuers)." />
      <DescribeField label="trustedBuilders" :items="slsa.trustedBuilders || []"
        hint="Allowed builder IDs (predicate.runDetails.builder.id)." />
      <DescribeField label="allowedBuildTypes" :items="slsa.allowedBuildTypes || []"
        hint="Allowed build types (predicate.buildDefinition.buildType)." />
    </DescribeSection>

    <DescribeSection v-if="Object.keys(openVex).length" title="OpenVEX" hint="OpenVEX v0.2.0 exploitability attestations.">
      <DescribeField label="enforceOpenVex" :value="yn(openVex.enforceOpenVex)" :tone="boolTone(openVex.enforceOpenVex)"
        hint="Enforce OpenVEX vulnerability-exploitability attestations." />
      <DescribeField label="requireStatements" :value="yn(openVex.requireStatements)" :tone="boolTone(openVex.requireStatements)"
        hint="Require at least one OpenVEX statement to be present." />
    </DescribeSection>

    <DescribeSection v-if="Object.keys(securityScan).length" title="Security Scan" hint="OSS code-scan attestation (gitleaks / checkov / semgrep).">
      <DescribeField label="enforceSecurityScan" :value="yn(securityScan.enforceSecurityScan)" :tone="boolTone(securityScan.enforceSecurityScan)"
        hint="Enforce an OSS security-scan attestation." />
      <DescribeField label="requireAttestation" :value="yn(securityScan.requireAttestation)" :tone="boolTone(securityScan.requireAttestation)"
        hint="Require the scan attestation to be present." />
      <DescribeField label="failOnSecrets" :value="yn(securityScan.failOnSecrets)" :tone="boolTone(securityScan.failOnSecrets)"
        hint="Fail if the scan detected committed secrets (gitleaks)." />
      <DescribeField label="maxIacSeverity" :value="securityScan.maxIacSeverity"
        hint="Max IaC (checkov) severity tolerated." />
      <DescribeField label="maxSastSeverity" :value="securityScan.maxSastSeverity"
        hint="Max SAST (semgrep) severity tolerated." />
    </DescribeSection>

    <DescribeSection title="Manifest Hash" hint="Deployed manifest must match the attested expected hash.">
      <DescribeField label="enabled" :value="yn(mh.enabled)" :tone="boolTone(mh.enabled)"
        hint="Enforce that the deployed manifest matches the attested expected hash." />
      <DescribeField label="enforcementAction" :value="mh.enforcementAction"
        hint="Action on hash mismatch — Reject blocks the workload; Alert only warns." />
      <DescribeField v-if="mh.isAuditMode" label="mode" value="audit (alert only)" tone="warn"
        hint="Audit mode: mismatches are alerted, not blocked." />
    </DescribeSection>

    <DescribeSection v-if="Object.keys(policyBinding).length" title="Policy Binding" hint="Which attestation predicate must be bound to the image.">
      <DescribeField label="enabled" :value="yn(policyBinding.enabled)" :tone="boolTone(policyBinding.enabled)"
        hint="Require an attestation of the expected predicate type to be present." />
      <DescribeField label="requireAttestationType" :value="policyBinding.requireAttestationType"
        hint="Predicate type the bound attestation must declare." />
    </DescribeSection>

    <DescribeSection title="Runtime Enforcement" hint="Actions taken at runtime when policy is violated.">
      <DescribeField label="enabled" :value="yn(runtime.enabled)" :tone="boolTone(runtime.enabled)"
        hint="Enable runtime enforcement actions for this policy." />
      <DescribeField label="onPolicyDrift" :value="summary.onPolicyDrift"
        hint="Action when runtime state drifts from policy — Alert, Isolate, or Kill." />
      <DescribeField label="onVulnerabilityFound" :value="summary.onVulnerabilityFound"
        hint="Action when a vulnerability is found at runtime — Alert or Kill." />
    </DescribeSection>

    <DescribeSection v-if="customRules.length" :title="`Custom Rules (CEL) · ${customRules.length}`" :grid="false"
      hint="Dynamic CEL rules evaluated against {voucher, image, zta, vex, sbom, securityScan}.">
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
