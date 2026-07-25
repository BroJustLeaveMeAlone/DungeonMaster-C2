import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './store/auth'
import { LoginPage }    from './pages/LoginPage'
import { DashboardPage }from './pages/DashboardPage'
import { SessionPage }  from './pages/SessionPage'
import { CampaignPage } from './pages/CampaignPage'
import { BuildPage }    from './pages/BuildPage'
import { ManualPage }   from './pages/ManualPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/*"     element={<AuthGuard />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

function AuthGuard() {
  const token = useAuthStore(s => s.accessToken)
  if (!token) return <Navigate to="/login" replace />

  return (
    <Routes>
      <Route path="/"                                     element={<DashboardPage />} />
      <Route path="/campaigns/:id"                        element={<CampaignPage />} />
      <Route path="/campaigns/:id/sessions/:sessionId"    element={<SessionPage />} />
      <Route path="/sessions/:sessionId"                  element={<SessionPage />} />
      <Route path="/builds"                               element={<BuildPage />} />
      <Route path="/manual"                               element={<ManualPage />} />
      <Route path="*"                         element={<Navigate to="/" replace />} />
    </Routes>
  )
}
