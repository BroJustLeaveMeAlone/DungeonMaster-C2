import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../api/client'

interface Build {
  id:           string
  campaign_id:  string
  status:       string
  target_os:    string
  target_arch:  string
  artifact_url: string
  sha256:       string
  created_at:   string
  completed_at: string | null
}

interface Listener {
  id:        string
  name:      string
  bind_host: string
  bind_port: number
  type:      string
}

interface Profile {
  name:      string
  poll_path: string
}

interface Campaign {
  id:   string
  name: string
}

const FEATURE_OPTIONS = [
  { id: 'inject-apc',     label: 'APC Injection',     group: 'Inject' },
  { id: 'inject-classic', label: 'Classic Inject',    group: 'Inject' },
  { id: 'inject-hollow',  label: 'Hollow',            group: 'Inject' },
  { id: 'inject-hijack',  label: 'Thread Hijack',     group: 'Inject' },
  { id: 'inject-stomp',   label: 'Module Stomp',      group: 'Inject' },
  { id: 'process-hollow', label: 'Process Hollow',    group: 'Inject' },
  { id: 'dll-sideload',   label: 'DLL Sideload',      group: 'Inject' },
  { id: 'unhook',         label: 'NTDLL Unhook',      group: 'Evasion' },
  { id: 'ppid-spoof',     label: 'PPID Spoof',        group: 'Evasion' },
  { id: 'heap-encrypt',   label: 'Heap Encrypt',      group: 'Evasion' },
  { id: 'stack-spoof',    label: 'Stack Spoof',       group: 'Evasion' },
  { id: 'sleep-encrypt',  label: 'Sleep Encrypt',     group: 'Evasion' },
  { id: 'udrl',           label: 'uDRL',              group: 'Loader' },
  { id: 'self-delete',    label: 'Self-Delete',       group: 'Loader' },
  { id: 'channel-tcp',    label: 'TCP Channel',       group: 'Channel' },
  { id: 'channel-smb',    label: 'SMB Channel',       group: 'Channel' },
]

const FORM_INIT = {
  campaign_id:    '',
  listener_id:    '',
  profile_name:   '',
  target_os:      'windows',
  target_arch:    'x64',
  sleep_seconds:  30,
  jitter_pct:     20,
  tls_skip_verify: false,
  sleep_encrypt:  false,
  ephemeral:      false,
  sign_subject:   '',
  features:       [] as string[],
}

const DELIVER_FORMATS: Record<string, string[]> = {
  windows: ['hta', 'ps1', 'js'],
  linux:   ['sh'],
  macos:   ['app', 'sh'],
}

function statusColor(s: string) {
  if (s === 'complete')  return 'var(--dm-accent)'
  if (s === 'failed')    return 'var(--dm-red)'
  if (s === 'building')  return 'var(--dm-amber)'
  return 'var(--dm-text-lo)'
}

function statusLabel(s: string) {
  if (s === 'complete') return '● DONE'
  if (s === 'failed')   return '✕ FAILED'
  if (s === 'building') return '⟳ BUILDING'
  return '◌ QUEUED'
}

export function BuildPage() {
  const qc = useQueryClient()
  const [showForm, setShowForm]     = useState(false)
  const [form, setForm]             = useState(FORM_INIT)
  const [createError, setCreateError] = useState('')
  const [deliverOpen, setDeliverOpen] = useState<string | null>(null)

  const { data: builds = [] } = useQuery<Build[]>({
    queryKey: ['builds'],
    queryFn:  () => api.get('/api/v1/builds').then(r => r.data),
    refetchInterval: (query) => {
      const data = query.state.data as Build[] | undefined
      if (!data) return 5_000
      return data.some(b => b.status === 'pending' || b.status === 'building') ? 3_000 : 15_000
    },
  })

  const { data: listeners = [] } = useQuery<Listener[]>({
    queryKey: ['listeners'],
    queryFn:  () => api.get('/api/v1/listeners').then(r => r.data),
  })

  const { data: profiles = [] } = useQuery<Profile[]>({
    queryKey: ['profiles'],
    queryFn:  () => api.get('/api/v1/profiles').then(r => r.data),
  })

  const { data: campaigns = [] } = useQuery<Campaign[]>({
    queryKey: ['campaigns'],
    queryFn:  () => api.get('/api/v1/campaigns?active_only=true').then(r => r.data),
  })

  const createBuild = useMutation({
    mutationFn: () => api.post('/api/v1/builds', { config: form }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['builds'] })
      setShowForm(false)
      setForm(FORM_INIT)
      setCreateError('')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error
      setCreateError(msg ?? 'Build request failed')
    },
  })

  function toggleFeature(id: string) {
    setForm(f => ({
      ...f,
      features: f.features.includes(id)
        ? f.features.filter(x => x !== id)
        : [...f.features, id],
    }))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setCreateError('')
    if (!form.listener_id) { setCreateError('Select a listener'); return }
    createBuild.mutate()
  }

  function deliverURL(buildId: string, fmt: string) {
    return `/api/v1/builds/${buildId}/deliver?format=${fmt}`
  }

  const featureGroups = FEATURE_OPTIONS.reduce<Record<string, typeof FEATURE_OPTIONS>>((acc, f) => {
    if (!acc[f.group]) acc[f.group] = []
    acc[f.group].push(f)
    return acc
  }, {})

  return (
    <div className="min-h-screen flex flex-col" style={{ background: 'var(--dm-bg)' }}>

      <nav style={{ borderBottom: '1px solid var(--dm-border)', borderTop: '2px solid var(--dm-accent-lo)' }}>
        <div className="flex items-center justify-between px-6 py-2.5">
          <div className="flex items-center gap-4">
            <Link
              to="/"
              style={{ color: 'var(--dm-text-lo)', fontSize: '0.7rem', textDecoration: 'none', transition: 'color 0.1s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-lo)')}
            >
              ← DUNGEONMASTER
            </Link>
            <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.7rem' }}>/</span>
            <span style={{ color: 'var(--dm-text-hi)', fontWeight: 700, fontSize: '0.82rem', letterSpacing: '0.2em' }}>
              BUILDS
            </span>
          </div>
          <button
            onClick={() => { setShowForm(true); setCreateError('') }}
            className="dm-btn"
            style={{ fontSize: '0.68rem' }}
          >
            + New Build
          </button>
        </div>
      </nav>

      <div className="flex-1 p-6">
        <div style={{ background: 'var(--dm-surface)', border: '1px solid var(--dm-border)' }}>
          <table className="w-full" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--dm-border)' }}>
                {['Status', 'Target', 'SHA256', 'Created', 'Actions'].map(h => (
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
              {builds.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: '1.5rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.78rem', textAlign: 'center' }}>
                    No builds yet.
                  </td>
                </tr>
              ) : builds.map((b, i) => (
                <tr key={b.id} style={{ borderTop: i > 0 ? '1px solid var(--dm-border)' : undefined }}>
                  <td style={{ padding: '0.6rem 1rem' }}>
                    <span style={{ color: statusColor(b.status), fontSize: '0.72rem', fontWeight: 600, letterSpacing: '0.08em' }}>
                      {statusLabel(b.status)}
                    </span>
                  </td>
                  <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-mid)', fontSize: '0.78rem' }}>
                    {b.target_os}/{b.target_arch}
                  </td>
                  <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.68rem', fontFamily: 'monospace' }}>
                    {b.sha256 ? b.sha256.slice(0, 12) + '…' : '—'}
                  </td>
                  <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.72rem' }}>
                    {new Date(b.created_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '0.6rem 1rem' }}>
                    {b.status === 'complete' && (
                      <div className="flex items-center gap-3">
                        {b.artifact_url && (
                          <a
                            href={b.artifact_url}
                            target="_blank"
                            rel="noreferrer"
                            style={{ color: 'var(--dm-accent-lo)', fontSize: '0.72rem', textDecoration: 'none', transition: 'color 0.1s' }}
                            onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-accent)')}
                            onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-accent-lo)')}
                          >
                            ↓ artifact
                          </a>
                        )}
                        <div style={{ position: 'relative' }}>
                          <button
                            className="dm-action"
                            style={{ fontSize: '0.68rem' }}
                            onClick={() => setDeliverOpen(deliverOpen === b.id ? null : b.id)}
                          >
                            deliver ▾
                          </button>
                          {deliverOpen === b.id && (
                            <div style={{
                              position: 'absolute',
                              right: 0,
                              top: '100%',
                              marginTop: '4px',
                              background: 'var(--dm-surface)',
                              border: '1px solid var(--dm-border)',
                              zIndex: 50,
                              minWidth: '90px',
                            }}>
                              {(DELIVER_FORMATS[b.target_os] ?? ['hta']).map(fmt => (
                                <a
                                  key={fmt}
                                  href={deliverURL(b.id, fmt)}
                                  download
                                  onClick={() => setDeliverOpen(null)}
                                  style={{
                                    display: 'block',
                                    padding: '0.35rem 0.75rem',
                                    color: 'var(--dm-text-mid)',
                                    fontSize: '0.72rem',
                                    textDecoration: 'none',
                                    letterSpacing: '0.06em',
                                    transition: 'background 0.1s, color 0.1s',
                                  }}
                                  onMouseEnter={e => {
                                    e.currentTarget.style.background = 'var(--dm-border)'
                                    e.currentTarget.style.color = 'var(--dm-text-hi)'
                                  }}
                                  onMouseLeave={e => {
                                    e.currentTarget.style.background = ''
                                    e.currentTarget.style.color = 'var(--dm-text-mid)'
                                  }}
                                >
                                  .{fmt}
                                </a>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showForm && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center"
          style={{ background: 'rgba(0,0,0,0.82)', overflowY: 'auto', padding: '2rem 1rem' }}
          onClick={e => { if (e.target === e.currentTarget) setShowForm(false) }}
        >
          <div className="w-full max-w-lg dm-panel" style={{ borderTop: '2px solid var(--dm-accent-lo)' }}>
            <div className="flex items-center justify-between px-5 py-2.5" style={{ borderBottom: '1px solid var(--dm-border)' }}>
              <span className="dm-section" style={{ flex: 1 }}>New Build</span>
              <button onClick={() => setShowForm(false)} className="dm-action" style={{ marginLeft: '0.75rem', fontSize: '0.9rem' }}>✕</button>
            </div>

            <form onSubmit={handleSubmit} className="p-5 space-y-4">
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

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="dm-label">Listener *</label>
                  <select
                    required
                    className="dm-input"
                    value={form.listener_id}
                    onChange={e => setForm(f => ({ ...f, listener_id: e.target.value }))}
                  >
                    <option value="">— select —</option>
                    {listeners.map(l => (
                      <option key={l.id} value={l.id}>
                        {l.name} ({l.bind_host}:{l.bind_port})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="dm-label">Campaign</label>
                  <select
                    className="dm-input"
                    value={form.campaign_id}
                    onChange={e => setForm(f => ({ ...f, campaign_id: e.target.value }))}
                  >
                    <option value="">— none —</option>
                    {campaigns.map(c => (
                      <option key={c.id} value={c.id}>{c.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="dm-label">C2 Profile</label>
                <select
                  className="dm-input"
                  value={form.profile_name}
                  onChange={e => setForm(f => ({ ...f, profile_name: e.target.value }))}
                >
                  <option value="">— default —</option>
                  {profiles.map(p => (
                    <option key={p.name} value={p.name}>{p.name}</option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="dm-label">Target OS</label>
                  <select
                    className="dm-input"
                    value={form.target_os}
                    onChange={e => setForm(f => ({ ...f, target_os: e.target.value, target_arch: 'x64' }))}
                  >
                    <option value="windows">Windows</option>
                    <option value="linux">Linux</option>
                    <option value="macos">macOS</option>
                  </select>
                </div>
                {form.target_os === 'macos' ? (
                  <div>
                    <label className="dm-label">Arch</label>
                    <select
                      className="dm-input"
                      value={form.target_arch}
                      onChange={e => setForm(f => ({ ...f, target_arch: e.target.value }))}
                    >
                      <option value="x64">x64 (Intel)</option>
                      <option value="arm64">arm64 (M-series)</option>
                    </select>
                  </div>
                ) : (
                  <div />
                )}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="dm-label">Sleep (secs)</label>
                  <input
                    type="number" min={1} max={86400}
                    className="dm-input"
                    value={form.sleep_seconds}
                    onChange={e => setForm(f => ({ ...f, sleep_seconds: Number(e.target.value) }))}
                  />
                </div>
                <div>
                  <label className="dm-label">Jitter (%)</label>
                  <input
                    type="number" min={0} max={50}
                    className="dm-input"
                    value={form.jitter_pct}
                    onChange={e => setForm(f => ({ ...f, jitter_pct: Number(e.target.value) }))}
                  />
                </div>
              </div>

              <div>
                <label className="dm-label">Sign Subject <span style={{ textTransform: 'none', color: 'var(--dm-text-dim)' }}>(optional)</span></label>
                <input
                  className="dm-input"
                  placeholder="/C=US/O=Acme Corp/CN=Acme Software"
                  value={form.sign_subject}
                  onChange={e => setForm(f => ({ ...f, sign_subject: e.target.value }))}
                />
              </div>

              <div>
                <div className="dm-label" style={{ marginBottom: '0.5rem' }}>Features</div>
                {Object.entries(featureGroups).map(([group, opts]) => (
                  <div key={group} style={{ marginBottom: '0.5rem' }}>
                    <div style={{ color: 'var(--dm-text-lo)', fontSize: '0.6rem', letterSpacing: '0.12em', marginBottom: '0.25rem' }}>
                      {group.toUpperCase()}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {opts.map(opt => {
                        const active = form.features.includes(opt.id)
                        return (
                          <button
                            key={opt.id}
                            type="button"
                            onClick={() => toggleFeature(opt.id)}
                            style={{
                              fontSize: '0.68rem',
                              letterSpacing: '0.06em',
                              padding: '0.2rem 0.55rem',
                              background: active ? 'rgba(0,255,136,0.08)' : 'none',
                              border: `1px solid ${active ? 'var(--dm-accent)' : 'var(--dm-border)'}`,
                              color: active ? 'var(--dm-accent)' : 'var(--dm-text-mid)',
                              cursor: 'pointer',
                              fontFamily: 'inherit',
                              transition: 'all 0.1s',
                            }}
                          >
                            {opt.label}
                          </button>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>

              <div className="flex gap-4">
                {([
                  { key: 'tls_skip_verify', label: 'TLS Skip Verify' },
                  { key: 'sleep_encrypt',   label: 'Sleep Encrypt' },
                  { key: 'ephemeral',       label: 'Ephemeral' },
                ] as const).map(({ key, label }) => {
                  const val = form[key] as boolean
                  return (
                    <label key={key} className="flex items-center gap-1.5" style={{ cursor: 'pointer', fontSize: '0.72rem', color: val ? 'var(--dm-text-hi)' : 'var(--dm-text-lo)' }}>
                      <input
                        type="checkbox"
                        checked={val}
                        onChange={e => setForm(f => ({ ...f, [key]: e.target.checked }))}
                        style={{ accentColor: 'var(--dm-accent)', cursor: 'pointer' }}
                      />
                      {label}
                    </label>
                  )
                })}
              </div>

              <div className="flex gap-3 pt-1">
                <button type="submit" disabled={createBuild.isPending} className="dm-btn">
                  {createBuild.isPending ? '// queuing...' : 'Queue Build'}
                </button>
                <button type="button" onClick={() => setShowForm(false)} className="dm-action" style={{ padding: '0 1rem', fontSize: '0.72rem' }}>
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
