/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

declare module 'vue-monaco-diff-editor' {
  const component: any
  export default component
}

declare module 'vuetify/styles';

declare module '@mdi/font/css/materialdesignicons.css';
