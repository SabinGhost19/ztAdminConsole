<script setup lang="ts">
// Blast Radius topology — Google Cloud Console aesthetic.
//
// Composition:
//   - Top toolbar (GCP-style icon buttons + filter chips + counters)
//   - VueFlow canvas with draggable nodes, MiniMap, Controls
//   - Floating contextual overlay (replaces side drawer)
//
// All node positions are deterministic from the response via Dagre;
// once laid out, nodes are user-draggable so the auditor can rearrange
// without losing the initial reading order.

import { computed, ref, shallowRef, watch } from 'vue'
import { Background, BackgroundVariant } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import {
  type Edge,
  type Node,
  type NodeMouseEvent,
  useVueFlow,
  VueFlow,
} from '@vue-flow/core'
import type { VirtualElement } from '@floating-ui/vue'
import '@vue-flow/core/dist/style.css'
import '@vue-flow/core/dist/theme-default.css'
import '@vue-flow/controls/dist/style.css'
import '@vue-flow/minimap/dist/style.css'

import CveNode from './CveNode.vue'
import PackageNode from './PackageNode.vue'
import ImageNode from './ImageNode.vue'
import DeploymentNode from './DeploymentNode.vue'
import BlastRadiusOverlay from './BlastRadiusOverlay.vue'
import { buildBlastRadiusGraph } from './useBlastRadiusGraph'
import type { BlastNodeData, BlastRadiusResponse, Verdict } from './types'
import './nodes.css'

const props = defineProps<{
  response: BlastRadiusResponse | null
  onlyInCluster: boolean
}>()

const emit = defineEmits<{
  (e: 'update:onlyInCluster', v: boolean): void
}>()

const nodeTypes = {
  cveNode: CveNode,
  packageNode: PackageNode,
  imageNode: ImageNode,
  deploymentNode: DeploymentNode,
} as Record<string, unknown>

const nodes = ref<Node<BlastNodeData>[]>([])
const edges = ref<Edge[]>([])
const packageCount = ref(0)
const inClusterCount = ref(0)

// VueFlow gives us a programmatic instance for fitView/zoom controls
// and for translating screen coordinates to canvas coordinates (used
// by the floating overlay).
const { fitView, zoomIn, zoomOut, project, viewport } = useVueFlow()

watch(
  () => [props.response, props.onlyInCluster] as const,
  ([resp, only]) => {
    if (!resp) {
      nodes.value = []; edges.value = []
      packageCount.value = 0; inClusterCount.value = 0
      return
    }
    const built = buildBlastRadiusGraph({ response: resp, onlyInCluster: !!only })
    nodes.value = built.nodes
    edges.value = built.edges
    packageCount.value = built.packageCount
    inClusterCount.value = built.inClusterCount
    // Wait for the DOM to settle before fitting the view.
    requestAnimationFrame(() => fitView({ padding: 0.18, duration: 200 }))
  },
  { immediate: true, deep: true },
)

// Verdict counts per package category. Shown as chips in the toolbar
// and as the "filter by verdict" affordance.
const verdictCounts = computed(() => {
  const out: Record<Verdict, number> = { critical: 0, exempted: 0, latent: 0 }
  for (const p of props.response?.vulnerablePackages ?? []) {
    const imgs = p.affectedImages ?? []
    if (imgs.length === 0 || imgs.every(i => (i.deployments ?? []).length === 0)) {
      out.latent++
    } else if (imgs.every(i => (i.deployments ?? []).every(d => d.vexExempted))) {
      out.exempted++
    } else {
      out.critical++
    }
  }
  return out
})

/* --------------------------------------------------------------------
 * Hover-driven path highlighting (ancestors + descendants).
 * ------------------------------------------------------------------*/
const activeNodeIds = ref<Set<string>>(new Set())
const activeEdgeIds = ref<Set<string>>(new Set())

function traverse(id: string, forward: boolean): { nodes: Set<string>; edges: Set<string> } {
  const ns = new Set<string>([id]); const es = new Set<string>()
  let frontier: Set<string> = new Set([id])
  while (frontier.size) {
    const next = new Set<string>()
    for (const e of edges.value) {
      const match = forward ? frontier.has(e.source) : frontier.has(e.target)
      if (!match) continue
      const adj = forward ? e.target : e.source
      es.add(e.id)
      if (!ns.has(adj)) { ns.add(adj); next.add(adj) }
    }
    frontier = next
  }
  return { nodes: ns, edges: es }
}

function onNodeEnter(evt: NodeMouseEvent) {
  const id = evt.node.id
  const up = traverse(id, false)
  const down = traverse(id, true)
  activeNodeIds.value = new Set([...up.nodes, ...down.nodes])
  activeEdgeIds.value = new Set([...up.edges, ...down.edges])
}
function onNodeLeave() {
  activeNodeIds.value = new Set()
  activeEdgeIds.value = new Set()
}
const hasHover = computed(() => activeNodeIds.value.size > 0)

function nodeClass(n: Node): string {
  const cls: string[] = []
  if (activeNodeIds.value.has(n.id)) cls.push('br-node--active')
  if (selectedNodeId.value === n.id) cls.push('br-node--selected')
  return cls.join(' ')
}
function edgeClass(e: Edge): string {
  return activeEdgeIds.value.has(e.id) ? 'br-edge--active' : ''
}

/* --------------------------------------------------------------------
 * Floating overlay anchoring.
 *
 * Floating UI takes a "virtual element" (an object exposing
 * getBoundingClientRect) as the reference. On click we capture the
 * node's DOM element via the event and store it; the overlay then
 * positions itself relative to that rectangle and re-projects on
 * viewport changes.
 * ------------------------------------------------------------------*/
const selectedNodeId = ref<string | null>(null)
const selectedNodeData = shallowRef<BlastNodeData | null>(null)
const anchor = shallowRef<VirtualElement | null>(null)
const overlayOpen = ref(false)

function onNodeClick(evt: NodeMouseEvent) {
  const data = (evt.node.data ?? null) as BlastNodeData | null
  if (!data) return
  selectedNodeId.value = evt.node.id
  selectedNodeData.value = data
  const el = (evt.event.target as HTMLElement)?.closest('.vue-flow__node') as HTMLElement | null
  if (!el) return
  // Wrap the live DOM element so Floating UI re-evaluates on scroll/zoom.
  anchor.value = {
    getBoundingClientRect: () => el.getBoundingClientRect(),
    contextElement: el,
  }
  overlayOpen.value = true
}

function closeOverlay() {
  overlayOpen.value = false
  selectedNodeId.value = null
  selectedNodeData.value = null
  anchor.value = null
}
function onPaneClick() { closeOverlay() }

/* --------------------------------------------------------------------
 * Toolbar actions.
 * ------------------------------------------------------------------*/
function doFitView() { void fitView({ padding: 0.18, duration: 240 }) }
function doZoomIn() { void zoomIn({ duration: 160 }) }
function doZoomOut() { void zoomOut({ duration: 160 }) }

/* --------------------------------------------------------------------
 * Empty-state conditions.
 * ------------------------------------------------------------------*/
const showFilteredEmpty = computed(() =>
  props.response && props.onlyInCluster && packageCount.value > 0 && inClusterCount.value === 0,
)
const showNoCveEmpty = computed(() =>
  props.response && packageCount.value === 0,
)
</script>

<template>
  <div class="br-canvas-wrap">
    <!-- ============================================================ -->
    <!-- Toolbar — GCP Console icon-buttons + chip filters             -->
    <!-- ============================================================ -->
    <div class="br-toolbar">
      <div class="br-toolbar__group">
        <button
          :class="['br-chip', { 'br-chip--active': onlyInCluster }]"
          @click="emit('update:onlyInCluster', !onlyInCluster)"
          :title="onlyInCluster ? 'Showing only packages with live deployments' : 'Showing every vulnerable package'"
        >
          <span class="material-symbols-outlined" style="font-size: 16px;">
            {{ onlyInCluster ? 'filter_alt' : 'filter_alt_off' }}
          </span>
          In-cluster only
        </button>
      </div>

      <div class="br-toolbar__divider" />

      <div class="br-toolbar__group">
        <span class="br-overlay__chip br-overlay__chip--critical" v-if="verdictCounts.critical">
          {{ verdictCounts.critical }} critical
        </span>
        <span class="br-overlay__chip br-overlay__chip--exempted" v-if="verdictCounts.exempted">
          {{ verdictCounts.exempted }} exempted
        </span>
        <span class="br-overlay__chip br-overlay__chip--latent" v-if="verdictCounts.latent">
          {{ verdictCounts.latent }} latent
        </span>
      </div>

      <div class="br-toolbar__spacer" />

      <span class="br-counter" v-if="response">
        {{ inClusterCount }} of {{ packageCount }} packages
      </span>

      <div class="br-toolbar__divider" />

      <div class="br-toolbar__group">
        <button class="br-icon-btn" @click="doZoomOut" title="Zoom out" aria-label="Zoom out">
          <span class="material-symbols-outlined">remove</span>
        </button>
        <button class="br-icon-btn" @click="doZoomIn" title="Zoom in" aria-label="Zoom in">
          <span class="material-symbols-outlined">add</span>
        </button>
        <button class="br-icon-btn" @click="doFitView" title="Fit graph to view" aria-label="Fit view">
          <span class="material-symbols-outlined">fit_screen</span>
        </button>
      </div>
    </div>

    <!-- ============================================================ -->
    <!-- Canvas                                                        -->
    <!-- ============================================================ -->
    <div :class="['br-canvas', { 'br-canvas--has-hover': hasHover }]">
      <VueFlow
        :nodes="nodes"
        :edges="edges"
        :node-types="(nodeTypes as any)"
        :node-class="nodeClass"
        :edge-class="edgeClass"
        :nodes-draggable="true"
        :nodes-connectable="false"
        :elements-selectable="true"
        :pan-on-scroll="false"
        :zoom-on-scroll="true"
        :min-zoom="0.2"
        :max-zoom="2.4"
        :default-edge-options="{ type: 'smoothstep' }"
        @node-mouse-enter="onNodeEnter"
        @node-mouse-leave="onNodeLeave"
        @node-click="onNodeClick"
        @pane-click="onPaneClick"
      >
        <Background
          :variant="BackgroundVariant.Dots"
          :gap="24"
          :size="1.2"
          pattern-color="rgba(255, 255, 255, 0.06)"
        />
        <Controls
          :show-zoom="false"
          :show-fit-view="false"
          :show-interactive="false"
          position="bottom-left"
        />
        <MiniMap
          pannable
          zoomable
          :node-stroke-width="2"
          :mask-color="'rgba(14, 17, 22, 0.65)'"
          :node-color="(n) => {
            const v = (n.data as BlastNodeData | undefined)
            if (!v) return 'rgba(255,255,255,0.4)'
            if ('verdict' in v) {
              if (v.verdict === 'critical') return '#f87171'
              if (v.verdict === 'exempted') return '#34d399'
              return '#71717a'
            }
            return '#f87171'
          }"
        />
      </VueFlow>

      <!-- Empty-state overlays painted above the (empty) canvas -->
      <div v-if="showNoCveEmpty" class="br-empty">
        <span class="material-symbols-outlined br-empty__icon" style="color: var(--br-accent-exempted);">
          verified
        </span>
        <div class="br-empty__title">No vulnerable packages in graph</div>
        <div class="br-empty__body">
          GUAC reports no package affected by <strong>{{ response?.cve }}</strong>.
        </div>
      </div>

      <div v-else-if="showFilteredEmpty" class="br-empty">
        <span class="material-symbols-outlined br-empty__icon" style="color: var(--br-accent-latent);">
          filter_alt_off
        </span>
        <div class="br-empty__title">No live deployment affected</div>
        <div class="br-empty__body">
          {{ packageCount }} vulnerable packages are known to GUAC, but none currently
          runs in the cluster.
        </div>
        <button class="br-empty__action" @click="emit('update:onlyInCluster', false)">
          Show latent packages
        </button>
      </div>
    </div>

    <!-- Floating contextual overlay -->
    <BlastRadiusOverlay
      :open="overlayOpen"
      :selected="selectedNodeData"
      :anchor="anchor"
      @close="closeOverlay"
    />
  </div>
</template>

<style scoped>
.br-canvas-wrap {
  display: flex;
  flex-direction: column;
  width: 100%;
}
</style>
