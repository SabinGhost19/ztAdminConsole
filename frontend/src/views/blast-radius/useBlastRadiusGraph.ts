// Transforms the backend `BlastRadiusResponse` into the Vue Flow
// (nodes, edges) shape and runs a left-to-right Dagre layout on top.
//
// The layout is deterministic: same input → same coordinates. We don't
// rely on Vue Flow's force-directed defaults because a hierarchical DAG
// (CVE → pkg → image → deployment) reads infinitely better than a
// spring-physics blob.

import dagre from '@dagrejs/dagre'
import type { Edge, Node } from '@vue-flow/core'
import { MarkerType } from '@vue-flow/core'
import type {
  AffectedImage,
  BlastNodeData,
  BlastRadiusResponse,
  DeploymentEntry,
  Verdict,
  VulnerablePackage,
} from './types'

// Approximate node dimensions used by Dagre. The real DOM size is set in
// each node component via fixed widths so this is accurate enough for
// the layout pass — drift of a few pixels is invisible.
// Must mirror the fixed widths/heights declared in each node component.
// Dagre lays out on rectangles, so any drift here produces overlaps.
const NODE_DIMS: Record<string, { width: number; height: number }> = {
  cve:        { width: 240, height: 64 },
  package:    { width: 240, height: 64 },
  image:      { width: 320, height: 64 },
  deployment: { width: 260, height: 64 },
}

function deploymentVerdict(dep: DeploymentEntry): Verdict {
  return dep.vexExempted ? 'exempted' : 'critical'
}

function imageVerdict(img: AffectedImage): Verdict {
  const live = img.deployments ?? []
  if (live.length === 0) return 'latent'
  if (live.every(d => d.vexExempted)) return 'exempted'
  return 'critical'
}

function packageVerdict(pkg: VulnerablePackage): Verdict {
  const imgs = pkg.affectedImages ?? []
  if (imgs.length === 0 || imgs.every(i => (i.deployments ?? []).length === 0)) {
    return 'latent'
  }
  // Bubble up the worst verdict any live image carries.
  let exempted = true
  for (const img of imgs) {
    const v = imageVerdict(img)
    if (v === 'critical') return 'critical'
    if (v === 'latent') continue
    if (v !== 'exempted') exempted = false
  }
  return exempted ? 'exempted' : 'critical'
}

function splitImageRef(image: string): { repo: string; digest: string } {
  if (!image) return { repo: '', digest: '' }
  if (image.includes('@')) {
    const [repo, digest] = image.split('@', 2)
    return { repo, digest }
  }
  return { repo: image, digest: '' }
}

// The flow is Google Blue regardless of verdict — state is carried by the
// node accent rail, not by the edge colour. Latent paths are drawn in a
// muted gray and dashed so the eye routes around inactive branches.
const FLOW_BLUE = '#1a73e8'   // Google Blue 600
const FLOW_GRAY = '#bdc1c6'   // Google Gray 400

function edgeColor(verdict: Verdict): string {
  return verdict === 'latent' ? FLOW_GRAY : FLOW_BLUE
}

export interface BuildGraphArgs {
  response: BlastRadiusResponse
  onlyInCluster: boolean
}

export interface BuiltGraph {
  nodes: Node<BlastNodeData>[]
  edges: Edge[]
  packageCount: number
  inClusterCount: number
}

/**
 * Build the Vue Flow graph for a Blast Radius response.
 *
 * - Filters by `onlyInCluster` BEFORE layout so the canvas isn't full of
 *   latent ghosts when the auditor flips the toggle off.
 * - Computes verdicts bottom-up: deployment → image → package → cve.
 * - Hands the structure to Dagre with `rankdir: LR` to get a clean
 *   left-to-right flow.
 */
export function buildBlastRadiusGraph(args: BuildGraphArgs): BuiltGraph {
  const { response, onlyInCluster } = args
  const allPackages = response.vulnerablePackages ?? []
  const inClusterCount = allPackages.filter(p =>
    (p.affectedImages ?? []).some(i => (i.deployments ?? []).length > 0),
  ).length

  const packages = onlyInCluster
    ? allPackages.filter(p =>
        (p.affectedImages ?? []).some(i => (i.deployments ?? []).length > 0),
      )
    : allPackages

  const nodes: Node<BlastNodeData>[] = []
  const edges: Edge[] = []

  const cveId = 'cve'
  nodes.push({
    id: cveId,
    type: 'cveNode',
    position: { x: 0, y: 0 },
    data: {
      kind: 'cve',
      cve: response.cve,
      totalPackages: allPackages.length,
      inClusterCount,
    },
  })

  packages.forEach((pkg, pIdx) => {
    const pkgId = `pkg-${pIdx}`
    const verdict = packageVerdict(pkg)
    const deploymentCount = (pkg.affectedImages ?? []).reduce(
      (acc, img) => acc + (img.deployments?.length ?? 0),
      0,
    )
    nodes.push({
      id: pkgId,
      type: 'packageNode',
      position: { x: 0, y: 0 },
      data: {
        kind: 'package',
        pkg,
        verdict,
        imageCount: (pkg.affectedImages ?? []).length,
        deploymentCount,
      },
    })
    edges.push({
      id: `${cveId}-${pkgId}`,
      source: cveId,
      target: pkgId,
      type: 'smoothstep',
      animated: verdict === 'critical',
      style: {
        stroke: edgeColor(verdict),
        strokeWidth: verdict === 'critical' ? 2 : 1.5,
        strokeDasharray: verdict === 'latent' ? '6 4' : undefined,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor(verdict) },
    })
    ;(pkg.affectedImages ?? []).forEach((img, iIdx) => {
      const imgId = `${pkgId}-img-${iIdx}`
      const imgVerdict = imageVerdict(img)
      const { repo, digest } = splitImageRef(img.image)
      nodes.push({
        id: imgId,
        type: 'imageNode',
        position: { x: 0, y: 0 },
        data: { kind: 'image', image: img, verdict: imgVerdict, repo, digest },
      })
      edges.push({
        id: `${pkgId}-${imgId}`,
        source: pkgId,
        target: imgId,
        type: 'smoothstep',
        animated: imgVerdict === 'critical',
        style: {
          stroke: edgeColor(imgVerdict),
          strokeWidth: imgVerdict === 'critical' ? 2 : 1.5,
          strokeDasharray: imgVerdict === 'latent' ? '6 4' : undefined,
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor(imgVerdict) },
      })
      ;(img.deployments ?? []).forEach((dep, dIdx) => {
        const depId = `${imgId}-dep-${dIdx}`
        const depVerdict = deploymentVerdict(dep)
        nodes.push({
          id: depId,
          type: 'deploymentNode',
          position: { x: 0, y: 0 },
          data: { kind: 'deployment', deployment: dep, verdict: depVerdict },
        })
        edges.push({
          id: `${imgId}-${depId}`,
          source: imgId,
          target: depId,
          type: 'smoothstep',
          animated: depVerdict === 'critical',
          style: {
            stroke: edgeColor(depVerdict),
            strokeWidth: depVerdict === 'critical' ? 2 : 1.5,
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor(depVerdict) },
        })
      })
    })
  })

  layoutWithDagre(nodes, edges)
  return { nodes, edges, packageCount: allPackages.length, inClusterCount }
}

function layoutWithDagre(nodes: Node<BlastNodeData>[], edges: Edge[]): void {
  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'LR', ranksep: 90, nodesep: 30, marginx: 20, marginy: 20 })
  g.setDefaultEdgeLabel(() => ({}))

  for (const n of nodes) {
    const dims = NODE_DIMS[n.data?.kind ?? 'package']
    g.setNode(n.id, { width: dims.width, height: dims.height })
  }
  for (const e of edges) g.setEdge(e.source, e.target)
  dagre.layout(g)

  for (const n of nodes) {
    const pos = g.node(n.id)
    const dims = NODE_DIMS[n.data?.kind ?? 'package']
    // Dagre returns the node *center*; Vue Flow wants top-left.
    n.position = { x: pos.x - dims.width / 2, y: pos.y - dims.height / 2 }
  }
}
