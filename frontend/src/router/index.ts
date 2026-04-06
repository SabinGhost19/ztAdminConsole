import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'Overview',
    component: () => import('../views/Overview.vue')
  },
  {
    path: '/jit',
    name: 'JIT Access',
    component: () => import('../views/JitAccess.vue')
  },
  {
    path: '/apps',
    name: 'Applications',
    component: () => import('../views/Apps.vue')
  },
  {
    path: '/secrets',
    name: 'Secrets Vault',
    component: () => import('../views/Secrets.vue')
  },
  {
    path: '/sca',
    name: 'Supply Chain Attestation',
    component: () => import('../views/Sca.vue')
  },
  {
    path: '/security',
    name: 'Security & Posture',
    component: () => import('../views/Security.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router