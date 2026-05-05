/**
 * Resolve Keycloak runtime configuration.
 *
 * Resolution order:
 *   1. /auth-config.json baked into the running container by the Helm chart
 *      ConfigMap. This is the production path and the only place a cluster
 *      operator can change.
 *   2. /api/v1/auth/config served by the backend itself. Useful for local
 *      development where a static file is not mounted.
 *   3. Hard-coded defaults aligned with platform-identity Keycloak Ingress.
 *      Last resort - logs a console warning.
 *
 * The function is idempotent and caches its result so the SPA pays the
 * fetch cost only once per page load.
 */

export interface AuthRuntimeConfig {
  url: string
  realm: string
  clientId: string
  audience: string
  issuer: string
  bypass: boolean
}

const FALLBACK: AuthRuntimeConfig = {
  url: 'https://keycloak.licenta.ro',
  realm: 'ZeroTrust-Realm',
  clientId: 'zero-trust-dashboard',
  audience: 'zero-trust-dashboard',
  issuer: 'https://keycloak.licenta.ro/realms/ZeroTrust-Realm',
  bypass: false,
}

let cached: AuthRuntimeConfig | null = null

function adapt(raw: any): AuthRuntimeConfig {
  const auth = raw?.authentication ?? raw ?? {}
  return {
    url: String(auth.url || FALLBACK.url),
    realm: String(auth.realm || FALLBACK.realm),
    clientId: String(auth.client_id || auth.clientId || FALLBACK.clientId),
    audience: String(auth.audience || FALLBACK.audience),
    issuer: String(auth.issuer || FALLBACK.issuer),
    bypass: Boolean(auth.bypass),
  }
}

export async function resolveAuthConfig(): Promise<AuthRuntimeConfig> {
  if (cached) return cached

  // 1) static ConfigMap mount
  try {
    const response = await fetch('/auth-config.json', { cache: 'no-store' })
    if (response.ok) {
      const data = await response.json()
      cached = adapt(data)
      return cached
    }
  } catch {
    // fall through
  }

  // 2) backend echo
  try {
    const response = await fetch('/api/v1/auth/config', { cache: 'no-store' })
    if (response.ok) {
      const data = await response.json()
      cached = adapt(data)
      return cached
    }
  } catch {
    // fall through
  }

  // 3) defaults
  // eslint-disable-next-line no-console
  console.warn('[auth] falling back to compiled defaults; you should mount /auth-config.json')
  cached = FALLBACK
  return cached
}

export function getCachedAuthConfig(): AuthRuntimeConfig | null {
  return cached
}
