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

const STATUS_COLORS: Record<string, string> = {
  queued:   '#d29922',
  building: '#d29922',
  complete: '#3fb950',
  failed:   '#f85149',
}

const INITIAL = {
  campaign_id:    '',
  listener_id:    '',
  target_os:      'windows',
  target_arch:    'x64',
  sleep_seconds:  30,
  jitter_pct:     20,
  ephemeral:      true,
  process_hollow: false,
  parent_spoof:   false,
  etw_patch:      false,
  amsi_patch:     false,
}

type FormState = typeof INITIAL

export function BuildPage() {
  const [form, setForm]           = useState<FormState>(INITIAL)
  const [building, setBuilding]   = useState(false)
  const [lastBuildId, setLastBuildId] = useState('')
  const [error, setError]         = useState('')
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

  function toggle(key: keyof FormState) {
    setForm(f => ({ ...f, [key]: !f[key] }))
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

  const inputCls = 'w-full border border-gray-700 rounded px-3 py-2 text-sm font-mono outline-none focus:border-green-600 transition-colors'
  const inputStyle = { background: '#21262d', color: '#c9d1d9' }
  const labelCls = 'block text-xs text-gray-600 mb-1 uppercase tracking-wider'

  return (
    <div className="min-h-screen p-6" style={{ background: '#0d1117' }}>
      <div className="flex items-center gap-4 mb-6">
        <Link to="/" className="text-gray-600 hover:text-gray-300 text-xs font-mono transition-colors">← dashboard</Link>
        <h1 className="text-xs text-gray-600 uppercase tracking-widest">Payload Builder</h1>
      </div>

      <div className="flex flex-col lg:flex-row gap-10 max-w-5xl">
      <form onSubmit={handleBuild} className="w-full lg:max-w-lg flex-shrink-0 space-y-5">
        {error && (
          <div className="text-red-400 text-sm border border-red-900 rounded px-3 py-2 font-mono" style={{ background: '#1a0a0a' }}>
            {error}
          </div>
        )}
        {lastBuildId && (
          <div className="text-green-400 text-sm border border-green-900 rounded px-3 py-2 font-mono" style={{ background: '#0a1a0a' }}>
            <div>Build queued — <span className="text-gray-500 text-xs">{lastBuildId}</span></div>
            <div className="text-gray-600 text-xs mt-0.5">Track status in history →</div>
          </div>
        )}

        {/* Campaign */}
        <div>
          <label className={labelCls}>Campaign</label>
          <select
            value={form.campaign_id}
            onChange={e => setForm(f => ({ ...f, campaign_id: e.target.value }))}
            className={inputCls}
            style={inputStyle}
            required
          >
            <option value="">Select campaign…</option>
            {campaigns.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>

        {/* Listener */}
        <div>
          <label className={labelCls}>Listener</label>
          <select
            value={form.listener_id}
            onChange={e => setForm(f => ({ ...f, listener_id: e.target.value }))}
            className={inputCls}
            style={inputStyle}
          >
            <option value="">Select listener…</option>
            {listeners.map(l => (
              <option key={l.id} value={l.id}>
                {l.name} — {l.type} {l.bind_host}:{l.bind_port}
              </option>
            ))}
          </select>
        </div>

        {/* OS / Arch */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelCls}>Target OS</label>
            <select
              value={form.target_os}
              onChange={e => setForm(f => ({ ...f, target_os: e.target.value }))}
              className={inputCls}
              style={inputStyle}
            >
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
            </select>
          </div>
          <div>
            <label className={labelCls}>Arch</label>
            <select
              value={form.target_arch}
              onChange={e => setForm(f => ({ ...f, target_arch: e.target.value }))}
              className={inputCls}
              style={inputStyle}
            >
              <option value="x64">x64</option>
              <option value="x86">x86</option>
              <option value="arm64">ARM64</option>
            </select>
          </div>
        </div>

        {/* Sleep / Jitter */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelCls}>Sleep (sec)</label>
            <input
              type="number" min={1} max={3600}
              value={form.sleep_seconds}
              onChange={e => setForm(f => ({ ...f, sleep_seconds: +e.target.value }))}
              className={inputCls}
              style={inputStyle}
            />
          </div>
          <div>
            <label className={labelCls}>Jitter (%)</label>
            <input
              type="number" min={0} max={50}
              value={form.jitter_pct}
              onChange={e => setForm(f => ({ ...f, jitter_pct: +e.target.value }))}
              className={inputCls}
              style={inputStyle}
            />
          </div>
        </div>

        {/* Evasion flags */}
        <div>
          <label className={labelCls}>Evasion Flags</label>
          <div className="space-y-2 mt-1">
            {([
              ['process_hollow', 'Process Hollowing'],
              ['parent_spoof',   'Parent PID Spoofing'],
              ['etw_patch',      'ETW Patch'],
              ['amsi_patch',     'AMSI Patch'],
              ['ephemeral',      'Ephemeral (no persistence)'],
            ] as [keyof FormState, string][]).map(([key, label]) => (
              <label key={key} className="flex items-center gap-3 text-sm text-gray-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={!!form[key]}
                  onChange={() => toggle(key)}
                  className="h-4 w-4 rounded border border-gray-700"
                  style={{ accentColor: '#3fb950' }}
                />
                <span className="font-mono text-xs text-gray-400">{label}</span>
              </label>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={building || !form.campaign_id}
          className="w-full text-white font-mono text-sm rounded py-2.5 transition-colors disabled:opacity-40"
          style={{ background: building ? '#1a3a1a' : '#196b24' }}
        >
          {building ? 'Queueing…' : 'Build Payload'}
        </button>
      </form>

      {/* Build history */}
      <div className="flex-1 min-w-0">
        <h2 className="text-xs text-gray-600 uppercase tracking-widest mb-3">Build History</h2>
        {builds.length === 0 ? (
          <p className="text-gray-700 text-sm font-mono">No builds yet.</p>
        ) : (
          <div className="space-y-2">
            {builds.map(b => (
              <div
                key={b.id}
                className="border rounded-lg px-4 py-3 font-mono text-xs transition-colors"
                style={{
                  background:   b.id === lastBuildId ? '#0d1f0d' : '#161b22',
                  borderColor:  b.id === lastBuildId ? '#196b24' : '#21262d',
                }}
              >
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="font-bold uppercase tracking-wider" style={{ color: STATUS_COLORS[b.status] ?? '#8b949e' }}>
                    {b.status}
                  </span>
                  <span className="text-gray-400">{b.target_os}/{b.target_arch}</span>
                  {b.campaign_id && campaignMap[b.campaign_id] && (
                    <span className="text-gray-600">{campaignMap[b.campaign_id]}</span>
                  )}
                  <span className="text-gray-700 ml-auto text-right">
                    {new Date(b.created_at).toLocaleTimeString()}
                  </span>
                </div>
                <div className="text-gray-700 mt-1 truncate">{b.id}</div>
                {b.status === 'complete' && b.artifact_url && (
                  <a href={b.artifact_url} className="text-blue-400 hover:text-blue-300 transition-colors mt-1.5 block">
                    ↓ download artifact
                  </a>
                )}
                {b.status === 'failed' && (
                  <span className="text-red-800 mt-1 block">build failed — check server logs</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
      </div>
    </div>
  )
}
