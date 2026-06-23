import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface Operator {
  id:       string
  username: string
  role:     string
}

interface AuthState {
  accessToken:  string | null
  refreshToken: string | null
  operator:     Operator | null
  setTokens: (access: string, refresh: string, operator: Operator) => void
  clearAuth:  () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      accessToken:  null,
      refreshToken: null,
      operator:     null,
      setTokens: (access, refresh, operator) =>
        set({ accessToken: access, refreshToken: refresh, operator }),
      clearAuth: () =>
        set({ accessToken: null, refreshToken: null, operator: null }),
    }),
    { name: 'dm-auth' },
  ),
)
