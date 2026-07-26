import axios from 'axios'
import { useAuthStore } from '../store/auth'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? '',
  timeout: 30_000,
})

// Attach access token to every request
api.interceptors.request.use(cfg => {
  const token = useAuthStore.getState().accessToken
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

// On 401: attempt token refresh, then retry once
api.interceptors.response.use(
  res => res,
  async err => {
    const original = err.config
    if (err.response?.status === 401 && !original._retry) {
      original._retry = true
      const refresh = useAuthStore.getState().refreshToken
      if (!refresh) {
        useAuthStore.getState().clearAuth()
        window.location.href = '/login'
        return Promise.reject(err)
      }
      try {
        const { data } = await axios.post('/api/v1/auth/refresh', { refresh_token: refresh })
        useAuthStore.getState().setTokens(
          data.access_token,
          refresh,
          useAuthStore.getState().operator!,
        )
        original.headers.Authorization = `Bearer ${data.access_token}`
        return api(original)
      } catch {
        useAuthStore.getState().clearAuth()
        window.location.href = '/login'
        return Promise.reject(err)
      }
    }
    return Promise.reject(err)
  },
)

// SSE event stream for a campaign. Token is passed as a query param because
// browsers cannot set Authorization headers on EventSource connections.
export function campaignEventSource(campaignId: string): EventSource {
  const token = useAuthStore.getState().accessToken ?? ''
  const base  = import.meta.env.VITE_API_URL ?? ''
  return new EventSource(
    `${base}/api/v1/events?campaign_id=${encodeURIComponent(campaignId)}&token=${encodeURIComponent(token)}`,
  )
}
