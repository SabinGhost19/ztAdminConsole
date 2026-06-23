import { ref, watch, onUnmounted, type Ref } from 'vue'

/** Formats an ISO timestamp into a compact "x ago" English label. */
export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return 'unknown'
  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000))
  if (seconds < 5) return 'just now'
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

/**
 * Reactive "x ago" label that ticks on an interval and recomputes immediately
 * when the source timestamp changes (e.g. after a manual refresh). The interval
 * is cleaned up on unmount.
 */
export function useRelativeTime(source: () => string | null | undefined, intervalMs = 10000): Ref<string> {
  const label = ref(formatRelative(source()))
  const update = () => { label.value = formatRelative(source()) }

  const timer = setInterval(update, intervalMs)
  watch(source, update)

  onUnmounted(() => clearInterval(timer))
  return label
}
