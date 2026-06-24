import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'

interface Campaign { id: string; name: string }
interface Listener { id: string; name: string; bind_host: string; bind_port: number; type: string }
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
      ['etw-patch',    'ETW patching'],
      ['amsi-patch',   'AMSI bypass'],
      ['unhook',       'ntdll unhooking'],
      ['heap-encrypt', 'Heap sleep masking'],
      ['stack-spoof',  'Stack spoofing'],
    ],
  },
  {
    label: 'Loader / Lifecycle',
    features: [
      ['udrl',           'Reflective loader (UDRL)'],
      ['staged-payload', 'Staged payload (requires udrl)'],
      ['self-delete',    'Agent self-delete on cleanup'],
    ],
  },
]

const INITIAL = {
  campaign_id:   '',
  listener_id:   '',
  target_os:     'windows',
  target_arch:   'x64',
  sleep_seconds: 30,
  jitter_pct:    20,
  ephemeral:     true,
  features:      [] as string[],
}
type FormState = typeof INITIAL

export function BuildPage() {
  const [form, setForm]               = useState<FormState>(INITIAL)
  const [building, setBuilding]       = useState(false)
  const [lastBuildId, setLastBuildId] = useState('')
  const [error, setError]             = useState('')
  const qc = useQueryClient()

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
                    required
                    className="dm-select"
                    value={form.campaign_id}
                    onChange={e => setForm(f => ({ ...f, campaign_id: e.target.value }))}
                  >
                    <option value="">Select campaign…</option>
                    {campaigns.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                  </select>
                </div>
                <div>
                  <label className="dm-label">Listener</label>
                  <select
                    className="dm-select"
                    value={form.listener_id}
                    onChange={e => setForm(f => ({ ...f, listener_id: e.target.value }))}
                  >
                    <option value="">Select listener…</option>
                    {listeners.map(l => (
                      <option key={l.id} value={l.id}>
                        {l.name} — {l.type} {l.bind_host}:{l.bind_port}
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
              <label className="flex items-center gap-2.5 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={form.ephemeral}
                  onChange={() => setForm(f => ({ ...f, ephemeral: !f.ephemeral }))}
                  style={{ accentColor: 'var(--dm-accent-lo)', width: '13px', height: '13px', flexShrink: 0, cursor: 'pointer' }}
                />
                <span style={{ color: 'var(--dm-text-mid)', fontSize: '0.75rem' }}>Ephemeral (no persistence)</span>
              </label>
            </div>

            {/* Features */}
            {FEATURE_GROUPS.map(group => (
              <div key={group.label} style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--dm-border)' }}>
                <div className="dm-section mb-3">{group.label}</div>
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
            ))}

            <div style={{ padding: '1rem 1.25rem' }}>
              <button
                type="submit"
                disabled={building || !form.campaign_id}
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
                        <a
                          href={b.artifact_url}
                          style={{ color: 'var(--dm-blue)', fontSize: '0.72rem', textDecoration: 'none', transition: 'color 0.1s' }}
                          onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-accent)')}
                          onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-blue)')}
                        >
                          ↓ download
                        </a>
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
    </div>
  )
}
