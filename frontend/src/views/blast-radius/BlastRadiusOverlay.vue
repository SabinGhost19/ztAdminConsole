<script setup lang="ts">
// Floating contextual card that replaces the side drawer. Built on
// @floating-ui/vue, which is the recommended modern positioning
// primitive (used by Material Web, Chrome DevTools, and Radix).
//
// Anchoring: the parent provides a virtual element pinned to the
// selected node's bounding box (translated to screen coordinates).
// Floating UI takes care of:
//   - preferred placement (right of node, fall back to left or below)
//   - automatic flipping on viewport overflow
//   - arrow positioning
// Dismiss is handled by the parent via Esc / canvas click.

import { computed, ref, watch } from 'vue'
import {
  arrow,
  autoUpdate,
  flip,
  offset,
  shift,
  useFloating,
  type Placement,
  type VirtualElement,
} from '@floating-ui/vue'
import type { BlastNodeData } from './types'

const props = defineProps<{
  open: boolean
  selected: BlastNodeData | null
  anchor: VirtualElement | null
}>()

const emit = defineEmits<{
  (e: 'close'): void
}>()

const floatingEl = ref<HTMLDivElement | null>(null)
const arrowEl = ref<HTMLDivElement | null>(null)
const reference = computed<VirtualElement | null>(() => props.anchor)

const { floatingStyles, placement, middlewareData, update } = useFloating(
  reference,
  floatingEl,
  {
    placement: 'right' as Placement,
    open: computed(() => props.open),
    whileElementsMounted: autoUpdate,
    middleware: [
      offset(12),
      flip({ fallbackPlacements: ['left', 'bottom-start', 'top-start'] }),
      shift({ padding: 12 }),
      arrow({ element: arrowEl }),
    ],
  },
)

const arrowStyle = computed(() => {
  const data = middlewareData.value.arrow
  if (!data) return {}
  const side = placement.value.split('-')[0]
  const opposite: Record<string, string> = {
    top: 'bottom', bottom: 'top', left: 'right', right: 'left',
  }
  return {
    left:   data.x != null ? `${data.x}px` : '',
    top:    data.y != null ? `${data.y}px` : '',
    [opposite[side] ?? 'right']: '-5px',
  }
})

// Verdict-driven accent for the head rail.
const verdictClass = computed(() => {
  const s = props.selected
  if (!s) return ''
  if ('verdict' in s) return `br-overlay--${s.verdict}`
  if (s.kind === 'cve') return 'br-overlay--critical'
  return ''
})

const kindLabel = computed(() => {
  switch (props.selected?.kind) {
    case 'cve':        return 'Vulnerability'
    case 'package':    return 'Package'
    case 'image':      return 'OCI Image'
    case 'deployment': return 'Kubernetes Deployment'
    default: return ''
  }
})

const title = computed(() => {
  const s = props.selected
  if (!s) return ''
  switch (s.kind) {
    case 'cve':        return s.cve
    case 'package':    return `${s.pkg.name}@${s.pkg.version || 'unknown'}`
    case 'image':      return s.repo || s.image.image
    case 'deployment': return `${s.deployment.namespace}/${s.deployment.name}`
  }
})

watch(
  () => [props.anchor, props.open] as const,
  () => { if (props.open) void update() },
)

function handleKey(e: KeyboardEvent) {
  if (e.key === 'Escape') emit('close')
}
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open && selected && anchor"
      ref="floatingEl"
      :class="['br-overlay', verdictClass]"
      :style="floatingStyles"
      role="dialog"
      aria-live="polite"
      tabindex="-1"
      @keydown="handleKey"
    >
      <div class="br-overlay__head">
        <div class="br-overlay__rail" />
        <div class="d-flex flex-column" style="min-width: 0;">
          <span class="br-overlay__kind">{{ kindLabel }}</span>
          <span class="br-overlay__title">{{ title }}</span>
        </div>
        <button class="br-overlay__close" @click="emit('close')" aria-label="Close">
          <span class="material-symbols-outlined" style="font-size: 18px;">close</span>
        </button>
      </div>

      <!-- CVE node body -->
      <div v-if="selected.kind === 'cve'" class="br-overlay__body">
        <div class="br-overlay__row">
          <span class="br-overlay__label">Identifier</span>
          <span class="br-overlay__value br-overlay__value--mono">{{ selected.cve }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Packages in cluster</span>
          <span class="br-overlay__value">{{ selected.inClusterCount }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Packages in graph</span>
          <span class="br-overlay__value">{{ selected.totalPackages }}</span>
        </div>
      </div>

      <!-- Package node body -->
      <div v-else-if="selected.kind === 'package'" class="br-overlay__body">
        <div class="br-overlay__row">
          <span class="br-overlay__label">Ecosystem</span>
          <span class="br-overlay__value">{{ selected.pkg.type || '—' }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Version</span>
          <span class="br-overlay__value br-overlay__value--mono">{{ selected.pkg.version || '?' }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Affected images</span>
          <span class="br-overlay__value">{{ selected.imageCount }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Live deployments</span>
          <span class="br-overlay__value">{{ selected.deploymentCount }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Verdict</span>
          <span class="br-overlay__value">
            <span :class="['br-overlay__chip', `br-overlay__chip--${selected.verdict}`]">
              {{ selected.verdict }}
            </span>
          </span>
        </div>
      </div>

      <!-- Image node body -->
      <div v-else-if="selected.kind === 'image'" class="br-overlay__body">
        <div class="br-overlay__section-title">Reference</div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Repository</span>
          <span class="br-overlay__value br-overlay__value--mono">{{ selected.repo }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Digest</span>
          <span class="br-overlay__value br-overlay__value--mono">{{ selected.digest || '—' }}</span>
        </div>
        <div class="br-overlay__section-title">Impact</div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Deployments</span>
          <span class="br-overlay__value">{{ selected.image.deployments?.length ?? 0 }}</span>
        </div>
      </div>

      <!-- Deployment node body -->
      <div v-else-if="selected.kind === 'deployment'" class="br-overlay__body">
        <div class="br-overlay__row">
          <span class="br-overlay__label">Namespace</span>
          <span class="br-overlay__value br-overlay__value--mono">{{ selected.deployment.namespace }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Name</span>
          <span class="br-overlay__value br-overlay__value--mono">{{ selected.deployment.name }}</span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Trust level</span>
          <span class="br-overlay__value">
            <span class="br-overlay__chip br-overlay__chip--neutral">
              {{ selected.deployment.trustLevel || '?' }}
            </span>
          </span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">Security state</span>
          <span class="br-overlay__value">
            <span class="br-overlay__chip br-overlay__chip--neutral">
              {{ selected.deployment.securityState || '?' }}
            </span>
          </span>
        </div>
        <div class="br-overlay__row">
          <span class="br-overlay__label">VEX</span>
          <span class="br-overlay__value">
            <span :class="['br-overlay__chip', selected.deployment.vexExempted ? 'br-overlay__chip--exempted' : 'br-overlay__chip--critical']">
              {{ selected.deployment.vexExempted ? 'exempted' : 'action required' }}
            </span>
          </span>
        </div>
      </div>

      <div ref="arrowEl" class="br-overlay__arrow" :style="arrowStyle" />
    </div>
  </Teleport>
</template>
