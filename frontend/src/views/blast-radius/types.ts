// Shared type definitions for the Blast Radius topology view.
//
// These mirror what `/api/v1/guac/blast-radius` returns from the backend
// (see app/services/guac_service.py). Kept here — not in the parent view —
// so the node components can import them without circular refs.

export interface DeploymentEntry {
  namespace?: string
  name?: string
  trustLevel?: string
  securityState?: string
  vexExempted?: boolean
}

export interface AffectedImage {
  image: string
  deployments: DeploymentEntry[]
}

export interface VulnerablePackage {
  type?: string
  name: string
  version: string
  affectedImages: AffectedImage[]
}

export interface BlastRadiusResponse {
  cve: string
  vulnerablePackages: VulnerablePackage[]
  error?: string
  guacUnavailable?: boolean
}

// The three node kinds plus the CVE root. Carried as `node.data.kind` so
// every custom node component can self-identify when looking up its data.
export type NodeKind = 'cve' | 'package' | 'image' | 'deployment'

// Verdict drives both the node accent color and the edge color upstream.
//   - critical: at least one path leads to an unexempted live deployment
//   - exempted: every live deployment for this node is VEX-exempted
//   - latent:   no live deployment (package or image only known to GUAC)
export type Verdict = 'critical' | 'exempted' | 'latent'

export interface CveNodeData {
  kind: 'cve'
  cve: string
  totalPackages: number
  inClusterCount: number
}

export interface PackageNodeData {
  kind: 'package'
  pkg: VulnerablePackage
  verdict: Verdict
  imageCount: number
  deploymentCount: number
}

export interface ImageNodeData {
  kind: 'image'
  image: AffectedImage
  verdict: Verdict
  repo: string
  digest: string
}

export interface DeploymentNodeData {
  kind: 'deployment'
  deployment: DeploymentEntry
  verdict: Verdict
}

export type BlastNodeData =
  | CveNodeData
  | PackageNodeData
  | ImageNodeData
  | DeploymentNodeData
