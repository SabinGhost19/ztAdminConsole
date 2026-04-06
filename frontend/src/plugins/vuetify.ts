import 'vuetify/styles'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { aliases, mdi } from 'vuetify/iconsets/mdi'
import '@mdi/font/css/materialdesignicons.css'

const googleCloudTheme = {
  dark: false,
  colors: {
    background: '#F8F9FA',
    surface: '#FFFFFF',
    primary: '#1A73E8',
    secondary: '#5F6368',
    success: '#34A853',
    warning: '#FBBC05',
    error: '#EA4335',
    info: '#4285F4',
  },
}

const googleCloudDarkTheme = {
  dark: true,
  colors: {
    background: '#121212',
    surface: '#1E1E1E',
    primary: '#8AB4F8',
    secondary: '#9AA0A6',
    success: '#81C995',
    warning: '#FDE293',
    error: '#F28B82',
    info: '#8AB4F8',
  },
}

export default createVuetify({
  components,
  directives,
  icons: {
    defaultSet: 'mdi',
    aliases,
    sets: {
      mdi,
    },
  },
  theme: {
    defaultTheme: 'googleCloudDarkTheme',
    themes: {
      googleCloudTheme,
      googleCloudDarkTheme,
    },
  },
  defaults: {
    global: {
      ripple: false,
    },
    VBtn: {
      style: [{ textTransform: 'none', letterSpacing: 'normal', fontFamily: 'Roboto, sans-serif' }]
    },
  }
})