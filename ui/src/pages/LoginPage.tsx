import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/auth'
import axios from 'axios'

export function LoginPage() {
  const navigate  = useNavigate()
  const setTokens = useAuthStore(s => s.setTokens)
  const [form, setForm]     = useState({ username: '', password: '', totp_code: '' })
  const [error, setError]   = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const base = import.meta.env.VITE_API_URL ?? 'http://localhost:8080'
      const { data } = await axios.post(`${base}/api/v1/auth/login`, form)
      setTokens(data.access_token, data.refresh_token, {
        id:       data.operator_id,
        username: form.username,
        role:     data.role,
      })
      navigate('/')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error
      setError(msg ?? 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const inputCls = 'w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm font-mono outline-none focus:border-green-500 transition-colors'

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: '#0d1117' }}>
      <div className="w-full max-w-sm">
        <h1 className="text-center mb-8 tracking-widest font-bold font-mono" style={{ color: '#3fb950', fontSize: '1.1rem' }}>
          DUNGEONMASTER
        </h1>

        <form
          onSubmit={handleSubmit}
          className="rounded-xl p-8 space-y-4 border border-gray-800"
          style={{ background: '#161b22' }}
        >
          {error && (
            <div className="text-red-400 text-sm border border-red-800 rounded px-3 py-2" style={{ background: '#1a0a0a' }}>
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs text-gray-500 mb-1 uppercase tracking-wider">Username</label>
            <input
              type="text"
              autoComplete="username"
              value={form.username}
              onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
              className={inputCls}
            />
          </div>

          <div>
            <label className="block text-xs text-gray-500 mb-1 uppercase tracking-wider">Password</label>
            <input
              type="password"
              autoComplete="current-password"
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              className={inputCls}
            />
          </div>

          <div>
            <label className="block text-xs text-gray-500 mb-1 uppercase tracking-wider">TOTP Code</label>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={form.totp_code}
              onChange={e => setForm(f => ({ ...f, totp_code: e.target.value }))}
              className={inputCls}
            />
          </div>

          <button
            type="submit"
            disabled={loading || !form.username || !form.password}
            className="w-full text-white font-mono text-sm rounded py-2 transition-colors disabled:opacity-40"
            style={{ background: loading ? '#1a4a1a' : '#196b24' }}
          >
            {loading ? 'Authenticating…' : 'Enter'}
          </button>
        </form>
      </div>
    </div>
  )
}
