import 'axios'

declare module 'axios' {
  interface AxiosRequestConfig {
    skipGlobalErrorAlert?: boolean
  }

  interface InternalAxiosRequestConfig {
    skipGlobalErrorAlert?: boolean
  }
}