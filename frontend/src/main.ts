import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import vuetify from './plugins/vuetify'
import { install as VueMonacoEditorPlugin } from '@guolao/vue-monaco-editor'

const app = createApp(App)

const pinia = createPinia()
app.use(pinia)
app.use(router)
app.use(vuetify)
app.use(VueMonacoEditorPlugin, {
  paths: {
    vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.40.0/min/vs'
  }
})

app.mount('#app')