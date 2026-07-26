import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/auth'
import axios from 'axios'

export function LoginPage() {
  const navigate  = useNavigate()
  const setTokens = useAuthStore(s => s.setTokens)
  const [form, setForm]       = useState({ username: '', password: '', totp_code: '' })
  const [error, setError]     = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const base = import.meta.env.VITE_API_URL ?? ''
      const { data } = await axios.post(`${base}/api/v1/auth/login`, form)
      setTokens(data.access_token, data.refresh_token, {
        id:       data.operator_id,
        username: form.username,
        role:     data.role,
      })
      navigate('/')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error
      setError(msg ?? 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden dm-grid-bg">
      {/* Radial vignette over dot grid */}
      <div className="absolute inset-0 pointer-events-none" style={{
        background: 'radial-gradient(ellipse 72% 72% at 50% 50%, transparent 30%, var(--dm-bg) 100%)',
      }} />

      <div className="relative z-10 w-full max-w-sm">
        {/* Wordmark */}
        <div className="text-center mb-7 select-none">
          <div style={{ color: 'var(--dm-text-lo)', fontSize: '0.62rem', letterSpacing: '0.35em', marginBottom: '0.4rem' }}>
            AMIT CORP // RTSD
          </div>
          <div style={{ color: 'var(--dm-accent)', fontSize: '1.25rem', fontWeight: 700, letterSpacing: '0.38em' }}>
            DUNGEONMASTER
          </div>
          <div style={{ color: 'var(--dm-text-lo)', fontSize: '0.6rem', letterSpacing: '0.2em', marginTop: '0.3rem' }}>
            C2 FRAMEWORK — OPERATOR ACCESS
          </div>
        </div>

        {/* Login panel */}
        <div className="dm-panel" style={{ borderTop: '2px solid var(--dm-accent-lo)' }}>
          <div className="flex items-center justify-between px-5 py-2.5" style={{ borderBottom: '1px solid var(--dm-border)' }}>
            <span className="dm-section" style={{ flex: 1 }}>Authentication Required</span>
          </div>

          <form onSubmit={handleSubmit} className="p-5 space-y-4">
            {error && (
              <div style={{
                color: 'var(--dm-red)',
                background: 'var(--dm-red-bg)',
                border: '1px solid rgba(255,58,76,0.25)',
                padding: '0.45rem 0.7rem',
                fontSize: '0.75rem',
              }}>
                ✕&nbsp;&nbsp;{error}
              </div>
            )}

            <div>
              <label className="dm-label">Operator ID</label>
              <input
                type="text"
                autoComplete="username"
                autoFocus
                className="dm-input"
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
              />
            </div>

            <div>
              <label className="dm-label">Passphrase</label>
              <input
                type="password"
                autoComplete="current-password"
                className="dm-input"
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              />
            </div>

            <div>
              <label className="dm-label">TOTP Token</label>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                placeholder="000000"
                className="dm-input"
                value={form.totp_code}
                onChange={e => setForm(f => ({ ...f, totp_code: e.target.value }))}
              />
            </div>

            <button
              type="submit"
              disabled={loading || !form.username || !form.password}
              className="dm-btn"
              style={{ marginTop: '0.75rem' }}
            >
              {loading ? '// authenticating...' : 'Authenticate'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
