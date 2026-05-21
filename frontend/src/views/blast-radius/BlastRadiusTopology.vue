<script setup lang="ts">
// Canvas + custom-node renderer for the Blast Radius topology.
//
// The parent (BlastRadius.vue) owns the data and the toggle; this component
// just turns that into a left-to-right Vue Flow graph and lets the user
// hover/click around. State that escapes the canvas:
//   - `nodeSelected`  event with the data of the clicked node (for drawer)

import { computed, markRaw, ref, watch } from 'vue'
import { Background } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import {
  type Edge,
  type Node,
  type NodeMouseEvent,
  VueFlow,
} from '@vue-flow/core'
import '@vue-flow/core/dist/style.css'
import '@vue-flow/core/dist/theme-default.css'
import '@vue-flow/controls/dist/style.css'

import CveNode from './CveNode.vue'
import PackageNode from './PackageNode.vue'
import ImageNode from './ImageNode.vue'
import DeploymentNode from './DeploymentNode.vue'
import { buildBlastRadiusGraph } from './useBlastRadiusGraph'
import type { BlastNodeData, BlastRadiusResponse } from './types'
import './nodes.css'

const props = defineProps<{
  response: BlastRadiusResponse | null
  onlyInCluster: boolean
}>()

const emit = defineEmits<{
  (e: 'nodeSelected', data: BlastNodeData): void
  (e: 'disableFilter'): void
}>()

// Vue Flow types `node-types` as a record of `NodeComponent` instances and
// chokes on the SFC-inferred type of a plain import. `markRaw` on a record
// of components matches the API and prevents Vue from wrapping them in a
// reactive proxy (which would be unnecessary churn anyway).
const nodeTypes = markRaw({
  cveNode: CveNode,
  packageNode: PackageNode,
  imageNode: ImageNode,
  deploymentNode: DeploymentNode,
}) as Record<string, unknown>

const nodes = ref<Node<BlastNodeData>[]>([])
const edges = ref<Edge[]>([])
const packageCount = ref(0)
const inClusterCount = ref(0)

watch(
  () => [props.response, props.onlyInCluster] as const,
  ([resp, only]) => {
    if (!resp) {
      nodes.value = []
      edges.value = []
      packageCount.value = 0
      inClusterCount.value = 0
      return
    }
    const built = buildBlastRadiusGraph({
      response: resp,
      onlyInCluster: !!only,
    })
    nodes.value = built.nodes
    edges.value = built.edges
    packageCount.value = built.packageCount
    inClusterCount.value = built.inClusterCount
  },
  { immediate: true, deep: true },
)

// Hover-highlight: find every node/edge on the path between the hovered
// node and the CVE root, mark them as active, dim the rest via CSS.
const activeNodeIds = ref<Set<string>>(new Set())
const activeEdgeIds = ref<Set<string>>(new Set())

function ancestorsOf(id: string): { nodes: Set<string>; edges: Set<string> } {
  const ns = new Set<string>([id])
  const es = new Set<string>()
  // Walk up: at each step find the edge whose target is the current id.
  let frontier: Set<string> = new Set([id])
  while (frontier.size > 0) {
    const next = new Set<string>()
    for (const e of edges.value) {
      if (frontier.has(e.target)) {
        es.add(e.id)
        if (!ns.has(e.source)) {
          ns.add(e.source)
          next.add(e.source)
        }
      }
    }
    frontier = next
  }
  return { nodes: ns, edges: es }
}

function descendantsOf(id: string): { nodes: Set<string>; edges: Set<string> } {
  const ns = new Set<string>([id])
  const es = new Set<string>()
  let frontier: Set<string> = new Set([id])
  while (frontier.size > 0) {
    const next = new Set<string>()
    for (const e of edges.value) {
      if (frontier.has(e.source)) {
        es.add(e.id)
        if (!ns.has(e.target)) {
          ns.add(e.target)
          next.add(e.target)
        }
      }
    }
    frontier = next
  }
  return { nodes: ns, edges: es }
}

function handleNodeMouseEnter(evt: NodeMouseEvent) {
  const id = evt.node.id
  const up = ancestorsOf(id)
  const down = descendantsOf(id)
  activeNodeIds.value = new Set([...up.nodes, ...down.nodes])
  activeEdgeIds.value = new Set([...up.edges, ...down.edges])
}

function handleNodeMouseLeave() {
  activeNodeIds.value = new Set()
  activeEdgeIds.value = new Set()
}

function handleNodeClick(evt: NodeMouseEvent) {
  const data = (evt.node.data ?? null) as BlastNodeData | null
  if (data) emit('nodeSelected', data)
}

const hasHover = computed(() => activeNodeIds.value.size > 0)

// Class binding wired through the `:node-class` / `:edge-class` props on
// <VueFlow>. Returning '' is the no-op default.
function nodeClass(n: Node): string {
  return activeNodeIds.value.has(n.id) ? 'br-node--active' : ''
}
function edgeClass(e: Edge): string {
  return activeEdgeIds.value.has(e.id) ? 'br-edge--active' : ''
}

const showFilteredEmpty = computed(() => {
  return (
    props.response &&
    props.onlyInCluster &&
    packageCount.value > 0 &&
    inClusterCount.value === 0
  )
})

const showNoCveEmpty = computed(() => {
  return props.response && packageCount.value === 0
})
</script>

<template>
  <div :class="['br-graph', { 'br-graph--has-hover': hasHover }]">
    <VueFlow
      :nodes="nodes"
      :edges="edges"
      :node-types="(nodeTypes as any)"
      :node-class="nodeClass"
      :edge-class="edgeClass"
      :nodes-draggable="false"
      :nodes-connectable="false"
      :elements-selectable="true"
      :fit-view-on-init="true"
      :min-zoom="0.2"
      :max-zoom="2"
      @node-mouse-enter="handleNodeMouseEnter"
      @node-mouse-leave="handleNodeMouseLeave"
      @node-click="handleNodeClick"
    >
      <Background pattern-color="rgba(255,255,255,0.06)" :gap="22" />
      <Controls />
    </VueFlow>

    <!-- Overlay empty states. Rendered on top of an (empty) canvas so the
         controls still feel anchored. -->
    <div v-if="showNoCveEmpty" class="br-empty">
      <v-icon size="48" color="success">mdi-shield-check-outline</v-icon>
      <p class="text-h6 mt-3">Niciun pachet vulnerabil în GUAC</p>
      <p class="text-medium-emphasis text-body-2">
        Graful nu cunoaște niciun pachet afectat de {{ response?.cve }}.
      </p>
    </div>

    <div v-else-if="showFilteredEmpty" class="br-empty">
      <v-icon size="44" color="warning">mdi-filter-outline</v-icon>
      <p class="text-h6 mt-3">Niciun deployment afectat activ</p>
      <p class="text-medium-emphasis text-body-2 mb-3">
        {{ packageCount }} pachete vulnerabile sunt cunoscute, dar niciunul nu
        rulează acum în cluster.
      </p>
      <v-btn color="primary" variant="tonal" @click="emit('disableFilter')">
        Afișează pachetele latente din GUAC
      </v-btn>
    </div>
  </div>
</template>

<style scoped>
.br-graph {
  position: relative;
  width: 100%;
  height: 70vh;
  min-height: 480px;
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 8px;
  overflow: hidden;
}

.br-empty {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  pointer-events: none; /* let canvas controls remain clickable */
}
.br-empty .v-btn { pointer-events: auto; }
</style>
