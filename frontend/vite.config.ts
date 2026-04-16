import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [
    vue(),
  ],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) {
            return undefined
          }
          if (id.includes('vuetify')) {
            return 'vuetify'
          }
          if (id.includes('axios') || id.includes('pinia') || id.includes('vue-router')) {
            return 'data-client'
          }
          if (id.includes('@mdi/font')) {
            return 'icons'
          }
          if (id.includes('vue')) {
            return 'vue-core'
          }
          return 'vendor'
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    port: 3000,
    proxy: {
      '/api/v1': {
        target: 'http://localhost:8000',
        changeOrigin: true
      }
    }
  }
})