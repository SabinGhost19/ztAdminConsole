// Single source of truth for ZTA/SCA/JIT enums and shared literals that were
// previously duplicated across views. Keep these aligned with the CRD schemas
// (zta-operator/.../crd/*.yaml).

// Severity scale (vulnerabilityPolicy.maxAllowedSeverity, securityScanPolicy.*).
export const SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

// CEL custom-rule verdicts (SupplyChainAttestation.spec.customRules[].action).
export const RULE_ACTIONS = ['Allow', 'Deny', 'Alert']

// runtimeEnforcement.onPolicyDrift / onVulnerabilityFound.
export const DRIFT_ACTIONS = ['Alert', 'Isolate', 'Kill']
export const VULN_ACTIONS = ['Alert', 'Kill']

// strictManifestHash.enforcementAction.
export const MANIFEST_ACTIONS = ['Reject', 'Alert']

// ZeroTrustApplication.wafConfig.
export const WAF_MODES = ['Monitor', 'Block']
export const WAF_PROFILES = ['REST-API', 'SPA', 'GRPC', 'Strict-Baseline']

// runtimeSecurity.onCompromise.
export const ON_COMPROMISE_ACTIONS = ['Isolate', 'Kill']

// ZeroTrustSecret.targetWorkload.kind / secretData.mapping[].type.
export const WORKLOAD_KINDS = ['Deployment', 'StatefulSet', 'DaemonSet']
export const MAPPING_TYPES = ['EnvVar', 'VolumeMount']

// JIT requested K8s RBAC level.
export const JIT_ROLES = ['view', 'edit', 'admin']

// Shared defaults / policy literals.
export const DEFAULT_NAMESPACE = 'default'
export const ALLOWED_REGISTRY = 'ghcr.io/'
export const FORBIDDEN_TAG = ':latest'
export const ATTESTATION_TYPE_ZTA_POLICY = 'https://devsecops.licenta.ro/attestations/custom-zta-policy/v1'
