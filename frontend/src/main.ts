import { createApp } from 'vue'
import { createPinia } from 'pinia'

import App from './App.vue'
import router from './router'
import vuetify from './plugins/vuetify'
import { useNotificationStore } from './store/notification'
import { useAuthStore } from './store/auth'

// The browser fires a benign "ResizeObserver loop ..." error whenever a
// ResizeObserver callback mutates layout within the same frame. Per the CSSOM
// View spec this is a recoverable notification, NOT a real failure (the browser
// settles on the next frame), and it is emitted constantly by ResizeObserver-
// heavy libraries (Vuetify's resize logic, ApexCharts responsive resize,
// Monaco's automaticLayout). It must never reach the user-facing error toast.
function isBenignResizeObserverError(message?: string | null): boolean {
  return !!message && message.includes('ResizeObserver loop')
}

async function start() {
  const app = createApp(App)
  const pinia = createPinia()
  app.use(pinia)
  app.use(vuetify)

  const notificationStore = useNotificationStore(pinia)

  window.addEventListener('error', (event) => {
    if (isBenignResizeObserverError(event.message)) {
      // Swallow it: don't toast, don't propagate, suppress default logging.
      event.preventDefault()
      event.stopImmediatePropagation()
      return
    }
    notificationStore.addAlert({
      error_code: 'FRONTEND_RUNTIME_ERROR',
      message: event.message || 'A frontend runtime error occurred.',
      technical_details: `${event.filename || 'unknown-file'}:${event.lineno || 0}:${event.colno || 0}`,
      component: 'FRONTEND_WINDOW',
      trace_id: `FE-${Math.random().toString(36).substring(2)}`,
      action_required: 'Inspect the browser console and correlate with the backend trace if relevant.',
      timestamp: new Date().toISOString(),
      source: 'frontend',
      details: event.error ? { stack: event.error.stack } : null,
      type: 'error',
    })
  })

  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason
    const reasonMessage = typeof reason === 'string' ? reason : (reason && reason.message) || ''
    if (isBenignResizeObserverError(reasonMessage)) {
      event.preventDefault()
      return
    }
    notificationStore.addAlert({
      error_code: 'FRONTEND_UNHANDLED_PROMISE',
      message: 'An unhandled async rejection occurred in the frontend.',
      technical_details: typeof reason === 'string' ? reason : JSON.stringify(reason, null, 2),
      component: 'FRONTEND_PROMISE',
      trace_id: `FE-${Math.random().toString(36).substring(2)}`,
      action_required: 'Inspect async handlers and browser console output.',
      timestamp: new Date().toISOString(),
      source: 'frontend',
      details: reason && reason.stack ? { stack: reason.stack } : null,
      type: 'error',
    })
  })

  // Bootstrap Keycloak BEFORE the router is plugged in so that the very
  // first route guard already has a definitive auth verdict and the
  // axios interceptor never runs without a token.
  const authStore = useAuthStore(pinia)
  await authStore.bootstrap()

  app.use(router)
  app.mount('#app')
}

start().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('Failed to bootstrap dashboard SPA:', err)
  const root = document.getElementById('app')
  if (root) {
    root.innerHTML = `
      <div style="font-family: sans-serif; padding: 2rem; max-width: 720px; margin: 0 auto;">
        <h1 style="color:#b00020">Dashboard nu a putut porni</h1>
        <p>Autentificarea Keycloak a eșuat. Verifică DNS-ul către <code>keycloak.licenta.ro</code>
           sau valoarea <code>/auth-config.json</code> servită de container.</p>
        <pre style="background:#fafafa; padding:1rem; overflow:auto;">${(err && err.stack) || err}</pre>
      </div>
    `
  }
})
