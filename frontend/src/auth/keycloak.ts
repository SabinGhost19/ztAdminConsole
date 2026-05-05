/**
 * Keycloak singleton.
 *
 * The app calls `bootstrapAuth()` once during boot. This loads the
 * runtime config (Helm-provided ConfigMap), instantiates a Keycloak
 * adapter, and either:
 *   - performs a login-required init when bypass is OFF, or
 *   - returns a fake authenticated session when bypass is ON.
 *
 * Once initialised, the rest of the application interacts with the
 * `useAuthStore()` Pinia store which mirrors the Keycloak state and
 * exposes the `can()` / `hasGroup()` helpers.
 */

import Keycloak, { type KeycloakInitOptions } from 'keycloak-js'

import { resolveAuthConfig, type AuthRuntimeConfig } from './config'

let keycloak: Keycloak | null = null
let bypass = false
let runtimeConfig: AuthRuntimeConfig | null = null

const REFRESH_LEEWAY_SECONDS = 30
const REFRESH_TICK_MS = 15_000

export function getKeycloak(): Keycloak | null {
  return keycloak
}

export function isBypass(): boolean {
  return bypass
}

export function getRuntimeConfig(): AuthRuntimeConfig | null {
  return runtimeConfig
}

export async function bootstrapAuth(): Promise<{
  authenticated: boolean
  bypass: boolean
  config: AuthRuntimeConfig
}> {
  const cfg = await resolveAuthConfig()
  runtimeConfig = cfg

  if (cfg.bypass) {
    bypass = true
    return { authenticated: true, bypass: true, config: cfg }
  }

  const kc = new Keycloak({
    url: cfg.url,
    realm: cfg.realm,
    clientId: cfg.clientId,
  })

  const initOptions: KeycloakInitOptions = {
    onLoad: 'check-sso',
    pkceMethod: 'S256',
    checkLoginIframe: false,
    silentCheckSsoRedirectUri: `${window.location.origin}/silent-check-sso.html`,
  }

  const authenticated = await kc.init(initOptions)
  keycloak = kc

  if (authenticated) {
    setupRefreshLoop(kc)
  }

  return { authenticated, bypass: false, config: cfg }
}

export async function login(redirectUri?: string): Promise<void> {
  if (bypass) return
  if (!keycloak) throw new Error('Keycloak not initialised')
  await keycloak.login({
    redirectUri: redirectUri || window.location.href,
  })
}

export async function logout(redirectUri?: string): Promise<void> {
  if (bypass) {
    window.location.reload()
    return
  }
  if (!keycloak) return
  await keycloak.logout({
    redirectUri: redirectUri || window.location.origin,
  })
}

export function getToken(): string | undefined {
  if (bypass) return undefined
  return keycloak?.token
}

export async function ensureFreshToken(minValiditySeconds = 30): Promise<string | undefined> {
  if (bypass) return undefined
  if (!keycloak) return undefined
  try {
    await keycloak.updateToken(minValiditySeconds)
  } catch {
    // refresh failed (probably session expired) - kick to login
    await keycloak.login({ redirectUri: window.location.href })
    return undefined
  }
  return keycloak.token
}

function setupRefreshLoop(kc: Keycloak) {
  // Background tick to renew tokens before they expire so that long-lived
  // dashboards don't suddenly start getting 401s.
  window.setInterval(() => {
    kc.updateToken(REFRESH_LEEWAY_SECONDS).catch(() => {
      // If a refresh fails here, the next API call will trigger an
      // ensureFreshToken() and re-login the user.
    })
  }, REFRESH_TICK_MS)
}
