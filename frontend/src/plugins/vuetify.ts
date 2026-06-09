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
    // surface-variant drives `bg-surface-variant` (table headers, selected/hover rows).
    // Must be a LIGHT tint in the light theme so it reads correctly (Vuetify's default
    // is a fixed dark #424242, which is why these surfaces looked inverted).
    'surface-variant': '#E8EAED',
    'on-surface-variant': '#3C4043',
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
    // Slightly-elevated dark grey so `bg-surface-variant` sits just above the surface
    // (instead of Vuetify's default #424242, which looks washed-out against #1E1E1E).
    'surface-variant': '#303134',
    'on-surface-variant': '#E8EAED',
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