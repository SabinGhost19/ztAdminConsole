import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import vuetify from './plugins/vuetify'
import { useNotificationStore } from './store/notification'

const app = createApp(App)

const pinia = createPinia()
app.use(pinia)
app.use(router)
app.use(vuetify)

const notificationStore = useNotificationStore(pinia)

window.addEventListener('error', (event) => {
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

app.mount('#app')