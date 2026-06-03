import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

import { useAuthStore } from '../store/auth'

declare module 'vue-router' {
  interface RouteMeta {
    /** A user must own AT LEAST ONE of these permissions. */
    requiresPermission?: string[]
    /** Access bypass: when true the route is reachable to anyone (login or
     *  not). Currently only the Unauthorized splash screen uses it. */
    public?: boolean
    /** Visible name shown in error pages. */
    title?: string
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Overview',
    component: () => import('../views/Overview.vue'),
    meta: {
      requiresPermission: ['overview:read'],
      title: 'Cluster Overview',
    },
  },
  {
    path: '/jit',
    name: 'JIT Access',
    component: () => import('../views/JitAccess.vue'),
    meta: {
      // either request your own access OR oversee others
      requiresPermission: ['jit:request', 'jit:read', 'jit:approve'],
      title: 'JIT Access',
    },
  },
  {
    path: '/iam',
    name: 'Identity & Access Management',
    component: () => import('../views/IamManager.vue'),
    meta: {
      requiresPermission: ['iam:read'],
      title: 'Identity & Access Management',
    },
  },
  {
    path: '/apps',
    name: 'Applications',
    component: () => import('../views/Apps.vue'),
    meta: {
      requiresPermission: ['apps:read'],
      title: 'ZTA Applications',
    },
  },
  {
    path: '/secrets',
    name: 'Secrets Vault',
    component: () => import('../views/Secrets.vue'),
    meta: {
      requiresPermission: ['secrets:read'],
      title: 'Secrets Vault',
    },
  },
  {
    path: '/sca',
    name: 'Supply Chain Attestation',
    component: () => import('../views/Sca.vue'),
    meta: {
      requiresPermission: ['sca:read'],
      title: 'Supply Chain (SCA)',
    },
  },
  {
    path: '/security',
    name: 'Security & Posture',
    component: () => import('../views/Security.vue'),
    meta: {
      requiresPermission: ['security:read'],
      title: 'Security & Posture',
    },
  },
  {
    path: '/blast-radius',
    name: 'Blast Radius (GUAC)',
    component: () => import('../views/BlastRadius.vue'),
    meta: {
      requiresPermission: ['security:read'],
      title: 'Blast Radius (GUAC)',
    },
  },
  {
    path: '/security-scans',
    name: 'Security Scans',
    component: () => import('../views/SecurityScans.vue'),
    meta: {
      requiresPermission: ['security:read'],
      title: 'Security Scans (gitleaks/checkov/semgrep)',
    },
  },
  {
    path: '/break-glass',
    name: 'Break-Glass (eBPF Honeypot)',
    component: () => import('../views/BreakGlass.vue'),
    meta: {
      requiresPermission: ['breakglass:read'],
      title: 'Break-Glass (eBPF)',
    },
  },
  {
    path: '/unauthorized',
    name: 'Unauthorized',
    component: () => import('../views/Unauthorized.vue'),
    meta: { public: true, title: 'Acces refuzat' },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (!auth.ready) {
    await auth.bootstrap()
  }

  if (to.meta?.public) return true

  // If auth bootstrap failed (Keycloak config/network/init), avoid calling
  // auth.login() blindly because that throws "Keycloak not initialised".
  if (auth.initError && !auth.bypass) {
    // eslint-disable-next-line no-console
    console.error('[auth][router] bootstrap failed; blocking protected route', {
      initError: auth.initError,
      target: to.fullPath,
    })
    return {
      name: 'Unauthorized',
      query: {
        reason: 'auth-init-failed',
        detail: auth.initError,
        target: String(to.fullPath),
      },
    }
  }

  if (!auth.authenticated && !auth.bypass) {
    await auth.login()
    return false
  }

  const required = to.meta?.requiresPermission
  if (required && required.length > 0) {
    const granted = required.some((p) => auth.can(p))
    if (!granted) {
      return {
        name: 'Unauthorized',
        query: {
          required: required.join(','),
          target: String(to.fullPath),
        },
      }
    }
  }
  return true
})

export default router
