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

  const [showCreate,  setShowCreate]  = useState(false)
  const [createForm,  setCreateForm]  = useState(CAMPAIGN_INIT)
  const [creating,    setCreating]    = useState(false)
  const [createError, setCreateError] = useState('')

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

  const { data: campaigns = [] } = useQuery<Campaign[]>({
    queryKey: ['campaigns'],
    queryFn:  () => api.get('/api/v1/campaigns?active_only=true').then(r => r.data),
  })

  const { data: sessions = [] } = useQuery<Session[]>({
    queryKey:        ['sessions'],
    queryFn:         () => api.get('/api/v1/sessions?alive_only=true').then(r => r.data),
    refetchInterval: 10_000,
  })

  return (
    <div className="min-h-screen flex flex-col" style={{ background: 'var(--dm-bg)' }}>

      {/* Nav */}
      <nav style={{ borderBottom: '1px solid var(--dm-border)', borderTop: '2px solid var(--dm-accent-lo)' }}>
        <div className="flex items-center justify-between px-6 py-2.5">
          <span style={{ color: 'var(--dm-accent)', fontWeight: 700, fontSize: '0.82rem', letterSpacing: '0.3em' }}>
            DUNGEONMASTER
          </span>
          <div className="flex items-center gap-5">
            <Link
              to="/builds"
              style={{ color: 'var(--dm-text-mid)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none', transition: 'color 0.1s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
            >
              Builds
            </Link>
            <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.68rem', letterSpacing: '0.06em' }}>
              {operator?.username} / {operator?.role}
            </span>
            <button
              onClick={clearAuth}
              className="dm-action dm-danger"
              style={{ fontSize: '0.68rem', letterSpacing: '0.06em' }}
            >
              Logout
            </button>
          </div>
        </div>
      </nav>

      <div className="flex-1 p-6 space-y-8">

        {/* Campaigns */}
        <section>
          <div className="flex items-center justify-between mb-4">
            <div className="dm-section flex-1">Active Campaigns</div>
            <button
              onClick={() => { setShowCreate(true); setCreateError('') }}
              style={{
                marginLeft: '1rem',
                color: 'var(--dm-accent-lo)',
                background: 'none',
                border: '1px solid var(--dm-border)',
                fontFamily: 'inherit',
                fontSize: '0.68rem',
                letterSpacing: '0.1em',
                padding: '0.2rem 0.65rem',
                cursor: 'pointer',
                transition: 'border-color 0.12s, color 0.12s',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = 'var(--dm-accent-lo)'
                e.currentTarget.style.color = 'var(--dm-accent)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = 'var(--dm-border)'
                e.currentTarget.style.color = 'var(--dm-accent-lo)'
              }}
            >
              + NEW
            </button>
          </div>

          {campaigns.length === 0 ? (
            <p style={{ color: 'var(--dm-text-lo)', fontSize: '0.78rem' }}>No active campaigns.</p>
          ) : (
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {campaigns.map(c => (
                <Link key={c.id} to={`/campaigns/${c.id}`} className="dm-card" style={{ padding: '0.875rem 1rem' }}>
                  <div style={{ color: 'var(--dm-text-hi)', fontWeight: 600, fontSize: '0.82rem', marginBottom: '0.25rem' }}>
                    {c.name}
                  </div>
                  <div style={{ color: 'var(--dm-text-mid)', fontSize: '0.72rem' }}>{c.client_name}</div>
                </Link>
              ))}
            </div>
          )}
        </section>

        {/* Live sessions */}
        <section>
          <div className="dm-section mb-4">
            Live Sessions&nbsp;
            <span style={{ color: 'var(--dm-accent)', fontWeight: 600 }}>{sessions.length}</span>
          </div>

          <div style={{ background: 'var(--dm-surface)', border: '1px solid var(--dm-border)' }}>
            <table className="w-full" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--dm-border)' }}>
                  {['Host', 'User', 'OS', 'Priv', 'Last Seen', ''].map(h => (
                    <th key={h} style={{
                      textAlign: 'left',
                      fontWeight: 400,
                      fontSize: '0.6rem',
                      letterSpacing: '0.15em',
                      textTransform: 'uppercase',
                      color: 'var(--dm-text-lo)',
                      padding: '0.5rem 1rem',
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sessions.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ padding: '1.5rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.78rem', textAlign: 'center' }}>
                      No live sessions
                    </td>
                  </tr>
                ) : sessions.map((s, i) => (
                  <tr
                    key={s.id}
                    style={{
                      borderTop: i > 0 ? '1px solid var(--dm-border)' : undefined,
                    }}
                  >
                    <td style={{ padding: '0.6rem 1rem' }}>
                      <div className="flex items-center gap-2">
                        <span
                          className={s.is_alive ? 'dm-alive' : undefined}
                          style={{
                            width: '6px', height: '6px',
                            borderRadius: '50%',
                            flexShrink: 0,
                            background: s.is_alive ? 'var(--dm-accent)' : 'var(--dm-text-lo)',
                          }}
                        />
                        <span style={{ color: 'var(--dm-text-hi)', fontWeight: 600, fontSize: '0.82rem' }}>
                          {s.hostname}
                        </span>
                      </div>
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-mid)', fontSize: '0.8rem' }}>
                      {s.username}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-mid)', fontSize: '0.78rem' }}>
                      {s.os}
                    </td>
                    <td style={{ padding: '0.6rem 1rem' }}>
                      {s.is_elevated
                        ? <span className="dm-badge" style={{ color: 'var(--dm-red)', borderColor: 'rgba(255,58,76,0.3)' }}>SYSTEM</span>
                        : <span style={{ color: 'var(--dm-text-lo)' }}>—</span>
                      }
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.72rem' }}>
                      {new Date(s.last_seen).toLocaleTimeString()}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', textAlign: 'right' }}>
                      <Link
                        to={s.campaign_id ? `/campaigns/${s.campaign_id}/sessions/${s.id}` : `/sessions/${s.id}`}
                        style={{
                          color: 'var(--dm-accent-lo)',
                          textDecoration: 'none',
                          fontSize: '0.72rem',
                          letterSpacing: '0.06em',
                          transition: 'color 0.1s',
                          paddingRight: '0.5rem',
                        }}
                        onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-accent)')}
                        onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-accent-lo)')}
                      >
                        interact →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {/* New campaign modal */}
      {showCreate && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.82)' }}
          onClick={e => { if (e.target === e.currentTarget) setShowCreate(false) }}
        >
          <div className="w-full max-w-md dm-panel" style={{ borderTop: '2px solid var(--dm-accent-lo)' }}>
            <div className="flex items-center justify-between px-5 py-2.5" style={{ borderBottom: '1px solid var(--dm-border)' }}>
              <span className="dm-section" style={{ flex: 1 }}>New Campaign</span>
              <button
                onClick={() => setShowCreate(false)}
                className="dm-action"
                style={{ marginLeft: '0.75rem', fontSize: '0.9rem' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreate} className="p-5 space-y-4">
              {createError && (
                <div style={{
                  color: 'var(--dm-red)',
                  background: 'var(--dm-red-bg)',
                  border: '1px solid rgba(255,58,76,0.25)',
                  padding: '0.45rem 0.7rem',
                  fontSize: '0.75rem',
                }}>
                  ✕&nbsp;&nbsp;{createError}
                </div>
              )}

              <div>
                <label className="dm-label">Campaign Name</label>
                <input required className="dm-input" value={createForm.name}
                  onChange={e => setCreateForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">Client</label>
                <input required className="dm-input" value={createForm.client_name}
                  onChange={e => setCreateForm(f => ({ ...f, client_name: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">Objective</label>
                <input className="dm-input" value={createForm.objective}
                  onChange={e => setCreateForm(f => ({ ...f, objective: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">
                  Scope CIDRs
                  <span style={{ textTransform: 'none', color: 'var(--dm-text-dim)', marginLeft: '0.4rem' }}>(comma-separated)</span>
                </label>
                <input className="dm-input" placeholder="192.168.1.0/24, 10.0.0.0/8"
                  value={createForm.scope_cidrs}
                  onChange={e => setCreateForm(f => ({ ...f, scope_cidrs: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">
                  Scope Domains
                  <span style={{ textTransform: 'none', color: 'var(--dm-text-dim)', marginLeft: '0.4rem' }}>(comma-separated)</span>
                </label>
                <input className="dm-input" placeholder="corp.local, example.com"
                  value={createForm.scope_domains}
                  onChange={e => setCreateForm(f => ({ ...f, scope_domains: e.target.value }))} />
              </div>

              <div className="flex gap-3 pt-1">
                <button type="submit" disabled={creating} className="dm-btn">
                  {creating ? '// creating...' : 'Create Campaign'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                  className="dm-action"
                  style={{ padding: '0 1rem', fontSize: '0.72rem' }}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
