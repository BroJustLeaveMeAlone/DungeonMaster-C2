import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAuthStore } from '../store/auth'

interface Session {
  id:           string
  campaign_id:  string
  hostname:     string
  username:     string
  os:           string
  is_alive:     boolean
  is_elevated:  boolean
  last_seen:    string
}

interface Campaign {
  id:          string
  name:        string
  client_name: string
  is_active:   boolean
}

const CAMPAIGN_INIT = { name: '', client_name: '', objective: '', scope_cidrs: '', scope_domains: '' }

export function DashboardPage() {
  const operator  = useAuthStore(s => s.operator)
  const clearAuth = useAuthStore(s => s.clearAuth)
  const qc        = useQueryClient()

  const [showCreate,   setShowCreate]   = useState(false)
  const [createForm,   setCreateForm]   = useState(CAMPAIGN_INIT)
  const [creating,     setCreating]     = useState(false)
  const [createError,  setCreateError]  = useState('')

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    setCreating(true)
    setCreateError('')
    try {
      await api.post('/api/v1/campaigns', {
        name:          createForm.name,
        client_name:   createForm.client_name,
        objective:     createForm.objective,
        scope_cidrs:   createForm.scope_cidrs.split(',').map(s => s.trim()).filter(Boolean),
        scope_domains: createForm.scope_domains.split(',').map(s => s.trim()).filter(Boolean),
      })
      void qc.invalidateQueries({ queryKey: ['campaigns'] })
      setShowCreate(false)
      setCreateForm(CAMPAIGN_INIT)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error
      setCreateError(msg ?? 'Failed to create campaign')
    } finally {
      setCreating(false)
    }
  }

  const inputCls  = 'w-full border border-gray-700 rounded px-3 py-2 text-sm font-mono outline-none focus:border-green-600 transition-colors'
  const inputStyle = { background: '#21262d', color: '#c9d1d9' }
  const labelCls  = 'block text-xs text-gray-600 mb-1 uppercase tracking-wider'

  const { data: campaigns = [] } = useQuery<Campaign[]>({
    queryKey: ['campaigns'],
    queryFn:  () => api.get('/api/v1/campaigns?active_only=true').then(r => r.data),
  })

  const { data: sessions = [] } = useQuery<Session[]>({
    queryKey:       ['sessions'],
    queryFn:        () => api.get('/api/v1/sessions?alive_only=true').then(r => r.data),
    refetchInterval: 10_000,
  })

  return (
    <div className="min-h-screen" style={{ background: '#0d1117' }}>
      <nav className="border-b border-gray-800 px-6 py-3 flex items-center justify-between">
        <span className="font-mono font-bold tracking-widest text-sm" style={{ color: '#3fb950' }}>
          DUNGEONMASTER
        </span>
        <div className="flex items-center gap-4">
          <Link to="/builds" className="text-xs text-gray-500 hover:text-gray-300 transition-colors font-mono">
            builds
          </Link>
          <span className="text-gray-600 text-xs font-mono">
            {operator?.username} / {operator?.role}
          </span>
          <button
            onClick={clearAuth}
            className="text-xs text-gray-600 hover:text-red-400 transition-colors font-mono"
          >
            logout
          </button>
        </div>
      </nav>

      <div className="p-6 space-y-8">
        {/* Campaigns */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs text-gray-600 uppercase tracking-widest">Active Campaigns</h2>
            <button
              onClick={() => { setShowCreate(true); setCreateError('') }}
              className="text-xs font-mono transition-colors px-2 py-1 rounded border border-gray-800 hover:border-green-800"
              style={{ color: '#3fb950', background: '#0d1117' }}
            >
              + new
            </button>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {campaigns.map(c => (
              <Link
                key={c.id}
                to={`/campaigns/${c.id}`}
                className="border border-gray-800 rounded-lg px-4 py-3 hover:border-green-800 transition-colors"
                style={{ background: '#161b22' }}
              >
                <div className="font-mono text-sm text-white">{c.name}</div>
                <div className="text-xs text-gray-500 mt-1">{c.client_name}</div>
              </Link>
            ))}
            {campaigns.length === 0 && (
              <p className="text-gray-700 text-sm col-span-3">No active campaigns.</p>
            )}
          </div>
        </section>

        {/* Campaign create modal */}
        {showCreate && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center"
            style={{ background: 'rgba(0,0,0,0.75)' }}
            onClick={e => { if (e.target === e.currentTarget) setShowCreate(false) }}
          >
            <div className="w-full max-w-md rounded-lg border border-gray-700 p-6" style={{ background: '#161b22' }}>
              <h2 className="text-xs text-gray-600 uppercase tracking-widest mb-5">New Campaign</h2>
              <form onSubmit={handleCreate} className="space-y-4">
                {createError && (
                  <div className="text-red-400 text-xs border border-red-900 rounded px-3 py-2 font-mono" style={{ background: '#1a0a0a' }}>
                    {createError}
                  </div>
                )}
                <div>
                  <label className={labelCls}>Campaign Name</label>
                  <input
                    required className={inputCls} style={inputStyle}
                    value={createForm.name}
                    onChange={e => setCreateForm(f => ({ ...f, name: e.target.value }))}
                  />
                </div>
                <div>
                  <label className={labelCls}>Client</label>
                  <input
                    required className={inputCls} style={inputStyle}
                    value={createForm.client_name}
                    onChange={e => setCreateForm(f => ({ ...f, client_name: e.target.value }))}
                  />
                </div>
                <div>
                  <label className={labelCls}>Objective</label>
                  <input
                    className={inputCls} style={inputStyle}
                    value={createForm.objective}
                    onChange={e => setCreateForm(f => ({ ...f, objective: e.target.value }))}
                  />
                </div>
                <div>
                  <label className={labelCls}>Scope CIDRs <span className="normal-case text-gray-700">(comma-separated)</span></label>
                  <input
                    className={inputCls} style={inputStyle}
                    placeholder="192.168.1.0/24, 10.0.0.0/8"
                    value={createForm.scope_cidrs}
                    onChange={e => setCreateForm(f => ({ ...f, scope_cidrs: e.target.value }))}
                  />
                </div>
                <div>
                  <label className={labelCls}>Scope Domains <span className="normal-case text-gray-700">(comma-separated)</span></label>
                  <input
                    className={inputCls} style={inputStyle}
                    placeholder="corp.local, example.com"
                    value={createForm.scope_domains}
                    onChange={e => setCreateForm(f => ({ ...f, scope_domains: e.target.value }))}
                  />
                </div>
                <div className="flex gap-3 pt-1">
                  <button
                    type="submit" disabled={creating}
                    className="flex-1 text-white font-mono text-sm rounded py-2 transition-colors disabled:opacity-40"
                    style={{ background: creating ? '#1a3a1a' : '#196b24' }}
                  >
                    {creating ? 'Creating…' : 'Create Campaign'}
                  </button>
                  <button
                    type="button" onClick={() => setShowCreate(false)}
                    className="text-gray-500 hover:text-gray-300 font-mono text-sm px-4 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Live sessions */}
        <section>
          <h2 className="text-xs text-gray-600 uppercase tracking-widest mb-3">
            Live Sessions{' '}
            <span style={{ color: '#3fb950' }}>{sessions.length}</span>
          </h2>

          <div className="overflow-x-auto">
            <table className="w-full text-sm font-mono">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider border-b border-gray-800" style={{ color: '#484f58' }}>
                  <th className="pb-2 pr-4 font-normal">Host</th>
                  <th className="pb-2 pr-4 font-normal">User</th>
                  <th className="pb-2 pr-4 font-normal">OS</th>
                  <th className="pb-2 pr-4 font-normal">Elevated</th>
                  <th className="pb-2 pr-4 font-normal">Last Seen</th>
                  <th className="pb-2 font-normal"></th>
                </tr>
              </thead>
              <tbody>
                {sessions.map(s => (
                  <tr
                    key={s.id}
                    className="border-b border-gray-900 transition-colors"
                    style={{ color: '#c9d1d9' }}
                  >
                    <td className="py-2 pr-4 text-white font-bold">{s.hostname}</td>
                    <td className="py-2 pr-4 text-gray-400">{s.username}</td>
                    <td className="py-2 pr-4 text-gray-500">{s.os}</td>
                    <td className="py-2 pr-4">
                      {s.is_elevated
                        ? <span style={{ color: '#f85149' }}>SYSTEM</span>
                        : <span className="text-gray-700">—</span>}
                    </td>
                    <td className="py-2 pr-4 text-gray-600 text-xs">
                      {new Date(s.last_seen).toLocaleTimeString()}
                    </td>
                    <td className="py-2">
                      <Link
                        to={s.campaign_id
                          ? `/campaigns/${s.campaign_id}/sessions/${s.id}`
                          : `/sessions/${s.id}`}
                        className="text-xs hover:text-green-300 transition-colors"
                        style={{ color: '#3fb950' }}
                      >
                        interact →
                      </Link>
                    </td>
                  </tr>
                ))}
                {sessions.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-6 text-gray-700 text-center text-xs">
                      No live sessions
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  )
}
