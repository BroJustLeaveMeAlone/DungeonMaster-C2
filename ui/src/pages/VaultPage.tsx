import { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'

interface Credential {
  id: string
  session_id: string
  campaign_id: string
  hostname: string
  username: string
  domain: string
  secret: string
  kind: string
  source: string
  notes: string
  created_at: string
}

const KIND_COLOR: Record<string, string> = {
  password: 'var(--dm-blue)',
  hash:     'var(--dm-red)',
  token:    'var(--dm-accent)',
  cookie:   'var(--dm-amber)',
  kerberos: 'var(--dm-purple)',
  other:    'var(--dm-text-lo)',
}

function relativeTime(ts: string): string {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (diff < 60)    return `${diff}s ago`
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

const MODAL_INIT = {
  kind:        'password',
  username:    '',
  domain:      '',
  hostname:    '',
  secret:      '',
  source:      'manual',
  notes:       '',
  campaign_id: '',
  session_id:  '',
}

export function VaultPage() {
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch]           = useState('')
  const [kindFilter, setKindFilter]   = useState('')
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set())
  const [confirmIds, setConfirmIds]   = useState<Set<string>>(new Set())
  const [showModal, setShowModal]     = useState(false)
  const [modalForm, setModalForm]     = useState(MODAL_INIT)
  const [modalError, setModalError]   = useState('')
  const [submitting, setSubmitting]   = useState(false)
  const qc = useQueryClient()
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => setSearch(searchInput), 300)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [searchInput])

  const { data: creds = [] } = useQuery<Credential[]>({
    queryKey: ['vault', search, kindFilter],
    queryFn:  () => api.get('/api/v1/vault/credentials', {
      params: {
        ...(search     ? { search }          : {}),
        ...(kindFilter ? { kind: kindFilter } : {}),
      },
    }).then(r => r.data),
  })

  function toggleReveal(id: string) {
    setRevealedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function handleDelete(id: string) {
    if (!confirmIds.has(id)) {
      setConfirmIds(prev => new Set(prev).add(id))
      setTimeout(() => {
        setConfirmIds(prev => {
          const next = new Set(prev)
          next.delete(id)
          return next
        })
      }, 2000)
      return
    }
    try {
      await api.delete(`/api/v1/vault/credentials/${id}`)
      void qc.invalidateQueries({ queryKey: ['vault'] })
    } catch {
      // deletion error is silent — the row stays visible until next refetch
    }
  }

  async function handleExport() {
    try {
      const res = await api.get('/api/v1/vault/credentials/export', { responseType: 'blob' })
      const url = URL.createObjectURL(res.data as Blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'vault_credentials.csv'
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // ignore
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!modalForm.username || !modalForm.secret) {
      setModalError('Username and secret are required')
      return
    }
    setSubmitting(true)
    setModalError('')
    try {
      await api.post('/api/v1/vault/credentials', modalForm)
      void qc.invalidateQueries({ queryKey: ['vault'] })
      setShowModal(false)
      setModalForm(MODAL_INIT)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error
      setModalError(msg ?? 'Create failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col" style={{ background: 'var(--dm-bg)' }}>

      {/* Nav */}
      <nav style={{ borderBottom: '1px solid var(--dm-border)', borderTop: '2px solid var(--dm-accent-lo)' }}>
        <div className="flex items-center justify-between px-6 py-2.5">
          <Link to="/" style={{ color: 'var(--dm-accent)', fontWeight: 700, fontSize: '0.82rem', letterSpacing: '0.3em', textDecoration: 'none' }}>
            DUNGEONMASTER
          </Link>
          <div className="flex items-center gap-5">
            <Link
              to="/"
              style={{ color: 'var(--dm-text-mid)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none', transition: 'color 0.1s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
            >
              Dashboard
            </Link>
            <Link
              to="/builds"
              style={{ color: 'var(--dm-text-mid)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none', transition: 'color 0.1s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
            >
              Builds
            </Link>
            <Link
              to="/vault"
              style={{ color: 'var(--dm-accent)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none' }}
            >
              Vault
            </Link>
            <Link
              to="/lure-gen"
              style={{ color: 'var(--dm-text-mid)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none', transition: 'color 0.1s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
            >
              Lure Gen
            </Link>
          </div>
        </div>
      </nav>

      {/* Toolbar */}
      <div
        className="flex items-center gap-3 px-6 py-3"
        style={{ borderBottom: '1px solid var(--dm-border)' }}
      >
        <input
          className="dm-input"
          placeholder="Search username, hostname, domain..."
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          style={{ flex: 1, maxWidth: '360px' }}
        />
        <select
          className="dm-input"
          value={kindFilter}
          onChange={e => setKindFilter(e.target.value)}
          style={{ width: '140px' }}
        >
          <option value="">All Kinds</option>
          <option value="password">password</option>
          <option value="hash">hash</option>
          <option value="token">token</option>
          <option value="cookie">cookie</option>
          <option value="kerberos">kerberos</option>
          <option value="other">other</option>
        </select>
        <button className="dm-action dm-go" onClick={handleExport}>
          Export CSV
        </button>
        <button className="dm-btn" onClick={() => { setShowModal(true); setModalError('') }}>
          + Add Credential
        </button>
      </div>

      {/* Credentials table */}
      <div className="flex-1 overflow-y-auto">
        {creds.length === 0 ? (
          <p style={{ padding: '1.5rem', color: 'var(--dm-text-lo)', fontSize: '0.78rem' }}>
            No credentials yet. Run collect/browser-creds or collect/vault on a session, or add manually.
          </p>
        ) : (
          <table className="w-full" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--dm-border)' }}>
                {['Kind', 'Username', 'Domain @ Hostname', 'Secret', 'Source', 'Campaign', 'Time', ''].map(h => (
                  <th key={h} style={{
                    textAlign: 'left',
                    fontWeight: 400,
                    fontSize: '0.6rem',
                    letterSpacing: '0.15em',
                    textTransform: 'uppercase',
                    color: 'var(--dm-text-lo)',
                    padding: '0.6rem 1rem',
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {creds.map((c, i) => {
                const revealed   = revealedIds.has(c.id)
                const confirming = confirmIds.has(c.id)
                const location   = c.domain ? `${c.domain} @ ${c.hostname}` : c.hostname
                return (
                  <tr
                    key={c.id}
                    style={{ borderTop: i > 0 ? '1px solid var(--dm-border)' : undefined }}
                  >
                    <td style={{ padding: '0.6rem 1rem' }}>
                      <span
                        className="dm-badge"
                        style={{ color: KIND_COLOR[c.kind] ?? 'var(--dm-text-lo)' }}
                      >
                        {c.kind}
                      </span>
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-hi)', fontWeight: 600, fontSize: '0.8rem' }}>
                      {c.username}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-mid)', fontSize: '0.78rem' }}>
                      {location}
                    </td>
                    <td
                      style={{
                        padding: '0.6rem 1rem',
                        cursor: 'pointer',
                        color: revealed ? 'var(--dm-amber)' : 'var(--dm-text-lo)',
                        fontFamily: revealed ? 'monospace' : undefined,
                        fontSize: '0.78rem',
                        userSelect: revealed ? 'text' : 'none',
                      }}
                      onClick={() => toggleReveal(c.id)}
                    >
                      {revealed ? c.secret : '••••••••'}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.72rem' }}>
                      {c.source}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.72rem' }}>
                      {c.campaign_id ? c.campaign_id.slice(0, 8) : 'manual'}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.72rem', whiteSpace: 'nowrap' }}>
                      {relativeTime(c.created_at)}
                    </td>
                    <td style={{ padding: '0.6rem 1rem' }}>
                      <button
                        className="dm-action dm-danger"
                        onClick={() => handleDelete(c.id)}
                        style={{ fontSize: '0.68rem', padding: '2px 6px' }}
                      >
                        {confirming ? 'Sure?' : '✕'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Add Credential modal */}
      {showModal && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 50,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
          onClick={e => { if (e.target === e.currentTarget) { setShowModal(false); setModalError('') } }}
        >
          <div style={{
            background: 'var(--dm-surface)', border: '1px solid var(--dm-border)',
            padding: '1.5rem', width: '100%', maxWidth: '420px',
          }}>
            <div style={{ color: 'var(--dm-text-hi)', fontWeight: 700, fontSize: '0.82rem', letterSpacing: '0.12em', marginBottom: '1rem' }}>
              ADD CREDENTIAL
            </div>
            {modalError && (
              <div style={{ color: 'var(--dm-red)', fontSize: '0.72rem', marginBottom: '0.75rem' }}>
                ✕&nbsp;{modalError}
              </div>
            )}
            <form onSubmit={handleCreate}>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="dm-label">Kind</label>
                    <select className="dm-input" value={modalForm.kind}
                      onChange={e => setModalForm(f => ({ ...f, kind: e.target.value }))}>
                      <option value="password">password</option>
                      <option value="hash">hash</option>
                      <option value="token">token</option>
                      <option value="cookie">cookie</option>
                      <option value="kerberos">kerberos</option>
                      <option value="other">other</option>
                    </select>
                  </div>
                  <div>
                    <label className="dm-label">Source</label>
                    <select className="dm-input" value={modalForm.source}
                      onChange={e => setModalForm(f => ({ ...f, source: e.target.value }))}>
                      <option value="manual">manual</option>
                      <option value="lsass">lsass</option>
                      <option value="browser">browser</option>
                      <option value="dpapi">dpapi</option>
                      <option value="kerberoast">kerberoast</option>
                      <option value="other">other</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="dm-label">Username *</label>
                  <input className="dm-input" value={modalForm.username}
                    onChange={e => setModalForm(f => ({ ...f, username: e.target.value }))} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="dm-label">Domain</label>
                    <input className="dm-input" value={modalForm.domain}
                      onChange={e => setModalForm(f => ({ ...f, domain: e.target.value }))} />
                  </div>
                  <div>
                    <label className="dm-label">Hostname</label>
                    <input className="dm-input" value={modalForm.hostname}
                      onChange={e => setModalForm(f => ({ ...f, hostname: e.target.value }))} />
                  </div>
                </div>
                <div>
                  <label className="dm-label">Secret *</label>
                  <input className="dm-input" value={modalForm.secret}
                    onChange={e => setModalForm(f => ({ ...f, secret: e.target.value }))} />
                </div>
                <div>
                  <label className="dm-label">Notes</label>
                  <input className="dm-input" value={modalForm.notes}
                    onChange={e => setModalForm(f => ({ ...f, notes: e.target.value }))} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="dm-label">Campaign ID</label>
                    <input className="dm-input" value={modalForm.campaign_id}
                      onChange={e => setModalForm(f => ({ ...f, campaign_id: e.target.value }))} />
                  </div>
                  <div>
                    <label className="dm-label">Session ID</label>
                    <input className="dm-input" value={modalForm.session_id}
                      onChange={e => setModalForm(f => ({ ...f, session_id: e.target.value }))} />
                  </div>
                </div>
              </div>
              <div className="flex gap-3 mt-4">
                <button type="submit" className="dm-btn" disabled={submitting}>
                  {submitting ? '// saving...' : 'Save'}
                </button>
                <button
                  type="button"
                  onClick={() => { setShowModal(false); setModalError('') }}
                  style={{
                    background: 'none', border: '1px solid var(--dm-border)',
                    color: 'var(--dm-text-lo)', fontSize: '0.75rem',
                    padding: '0.45rem 0.9rem', cursor: 'pointer',
                  }}
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
