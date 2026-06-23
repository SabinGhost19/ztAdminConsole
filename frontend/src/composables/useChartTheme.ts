import { computed } from 'vue'
import { useTheme } from 'vuetify'

/**
 * Centralises ApexCharts theming so every chart on the dashboard recolours
 * consistently with the active Vuetify theme (googleCloudTheme / dark) and
 * reacts to runtime theme toggles. Returns primitives instead of a single
 * merged ApexOptions blob to avoid fragile deep-merges per chart.
 */
export function useChartTheme() {
  const theme = useTheme()

  const isDark = computed(() => theme.current.value.dark)
  const colors = computed(() => theme.current.value.colors as Record<string, string>)
  const foreColor = computed(() => (isDark.value ? '#E8EAED' : '#3C4043'))
  const gridColor = computed(() => (isDark.value ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)'))
  const onAccent = computed(() => (isDark.value ? '#121212' : '#FFFFFF'))

  /** Maps a domain status key (trust level, ZTA phase, JIT state) to a theme colour. */
  const statusColor = (key: string): string => {
    const c = colors.value
    const map: Record<string, string> = {
      // healthy / good
      Verified: c.success, Compliant: c.success, Running: c.success, Ready: c.success,
      Active: c.success, ACTIVE: c.success, APPROVED: c.success,
      // in-flight / warning
      Degraded: c.warning, Pending: c.warning, PENDING: c.warning, Provisioning: c.warning,
      PENDING_APPROVAL: c.warning, Warning: c.warning, RATE_LIMITED: c.warning, QUOTA_EXCEEDED: c.warning,
      // bad / terminal
      Untrusted: c.error, Failed: c.error, EXPIRED: c.error, REVOKED: c.error,
      TAMPERED: c.error, REJECTED: c.error, BlockedBySecurity: c.error,
    }
    return map[key] || c.primary
  }

  return { theme, isDark, colors, foreColor, gridColor, onAccent, statusColor }
}
