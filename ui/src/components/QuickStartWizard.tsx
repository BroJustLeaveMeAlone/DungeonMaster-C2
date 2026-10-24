import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'

interface Listener {
  id:        string
  name:      string
  type:      string
  bind_host: string
  bind_port: number
}

interface QuickStartWizardProps {
  onClose: () => void
  onDone:  () => void
}

type Mode = 'quick' | 'guided'

type StepStatus = 'pending' | 'running' | 'done' | 'error'

interface ExecStep {
  label:  string
  status: StepStatus
  error:  string
}

const PROFILES = [
  {
    id:    'stealth-external',
    title: 'STEALTH EXTERNAL',
    desc:  'Starting from outside via phishing. Realistic APT simulation.',
    specs: 'Sleep 60s · Jitter 20% · Evasion: full',
    build: { sleep_seconds: 60, jitter_pct: 20, features: ['inject-classic','unhook','heap-encrypt','ppid-spoof'], sign: false, tls_skip_verify: false },
  },
  {
    id:    'internal-assessment',
    title: 'INTERNAL ASSESSMENT',
    desc:  'Already on the network. Fast beacon, maximum visibility.',
    specs: 'Sleep 10s · Jitter 10% · Evasion: none',
    build: { sleep_seconds: 10, jitter_pct: 10, features: [] as string[], sign: false, tls_skip_verify: false },
  },
  {
    id:    'assumed-breach',
    title: 'ASSUMED BREACH',
    desc:  'You have a foothold. Simulate post-breach attacker behavior.',
    specs: 'Sleep 30s · Jitter 20% · Evasion: light',
    build: { sleep_seconds: 30, jitter_pct: 20, features: ['unhook','ppid-spoof'], sign: false, tls_skip_verify: false },
  },
  {
    id:    'lab-quick-test',
    title: 'LAB / QUICK TEST',
    desc:  'Dev and testing. Fastest beacon, skip TLS verification.',
    specs: 'Sleep 5s · Jitter 0% · Evasion: none',
    build: { sleep_seconds: 5, jitter_pct: 0, features: [] as string[], sign: false, tls_skip_verify: true },
  },
]

const FEATURES = ['inject-classic','unhook','heap-encrypt','ppid-spoof','stomping']

const STEP_INDICATOR: Record<StepStatus, { symbol: string; color: string; pulse: boolean }> = {
  pending: { symbol: '○', color: 'var(--dm-text-lo)',  pulse: false },
  running: { symbol: '●', color: 'var(--dm-amber)',    pulse: true  },
  done:    { symbol: '✓', color: 'var(--dm-accent)',   pulse: false },
  error:   { symbol: '✕', color: 'var(--dm-red)',      pulse: false },
}

function errMsg(err: unknown): string {
  return (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'Request failed'
}

export function QuickStartWizard({ onClose, onDone }: QuickStartWizardProps) {
  const [mode,    setMode]    = useState<Mode | null>(null)
  const [step,    setStep]    = useState(0)

  const [selectedProfile, setSelectedProfile] = useState<string | null>(null)

  const [quickForm, setQuickForm] = useState({
    campaignName:  '',
    clientName:    '',
    os:            'windows',
    arch:          'amd64',
    targetDomain:  '',
    listenerMode:  'auto' as 'auto' | 'existing',
    listenerId:    '',
  })

  const [guidedCampaign, setGuidedCampaign] = useState({
    name: '', client_name: '', objective: '', scope_cidrs: '', scope_domains: '',
  })
  const [guidedListener, setGuidedListener] = useState({
    mode: 'new' as 'new' | 'existing',
    name: '', protocol: 'http', host: '', port: '4444', listenerId: '',
  })
  const [guidedPayload, setGuidedPayload] = useState({
    os: 'windows', arch: 'amd64', sleep_seconds: '30', jitter_pct: '10',
    features: [] as string[], sign: false, tls_skip_verify: false,
  })

  const [execSteps, setExecSteps] = useState<ExecStep[]>([])
  const [doneData, setDoneData]   = useState<{ campaignId: string; campaignName: string; profileId: string } | null>(null)
  const [retryFrom, setRetryFrom] = useState<number | null>(null)

  const { data: listeners = [] } = useQuery<Listener[]>({
    queryKey: ['listeners'],
    queryFn:  () => api.get('/api/v1/listeners').then(r => r.data),
  })

  async function runExecution(
    campaignPayload: { name: string; client_name: string; objective?: string; scope_cidrs?: string[]; scope_domains?: string[] },
    listenerConfig:  { auto: true; name: string; bind_host: string; bind_port: number; type: string } | { auto: false; id: string },
    buildConfig: {
      os: string; arch: string; sleep_seconds: number; jitter_pct: number;
      features: string[]; sign: boolean; tls_skip_verify: boolean
    },
    profileId: string,
    fromStep = 0,
  ) {
    const steps: ExecStep[] = [
      { label: 'Creating campaign...', status: 'pending', error: '' },
      { label: 'Setting up listener...', status: 'pending', error: '' },
      { label: 'Queuing payload build...', status: 'pending', error: '' },
    ]
    if (fromStep === 0) {
      setExecSteps(steps)
    } else {
      setExecSteps(prev =>
        prev.map((s, i) => i >= fromStep ? { ...s, status: 'pending', error: '' } : s)
      )
    }

    let campaignId = ''
    let listenerId = ''

    const markRunning = (i: number) =>
      setExecSteps(prev => prev.map((s, idx) => idx === i ? { ...s, status: 'running', error: '' } : s))
    const markDone    = (i: number) =>
      setExecSteps(prev => prev.map((s, idx) => idx === i ? { ...s, status: 'done'    } : s))
    const markError   = (i: number, msg: string) =>
      setExecSteps(prev => prev.map((s, idx) => idx === i ? { ...s, status: 'error', error: msg } : s))

    if (fromStep <= 0) {
      markRunning(0)
      try {
        const res = await api.post('/api/v1/campaigns', campaignPayload)
        campaignId = res.data.id
        markDone(0)
      } catch (e) {
        markError(0, errMsg(e))
        setRetryFrom(0)
        return
      }
    }

    if (fromStep <= 1) {
      markRunning(1)
      try {
        if (listenerConfig.auto) {
          const res = await api.post('/api/v1/listeners', {
            name:      listenerConfig.name,
            bind_host: listenerConfig.bind_host,
            bind_port: listenerConfig.bind_port,
            type:      listenerConfig.type,
          })
          listenerId = res.data.id
        } else {
          listenerId = listenerConfig.id
        }
        markDone(1)
      } catch (e) {
        markError(1, errMsg(e))
        setRetryFrom(1)
        return
      }
    }

    if (fromStep <= 2) {
      markRunning(2)
      try {
        await api.post('/api/v1/builds', {
          config: {
            campaign_id:     campaignId,
            listener_id:     listenerId,
            target_os:       buildConfig.os,
            target_arch:     buildConfig.arch,
            sleep_seconds:   buildConfig.sleep_seconds,
            jitter_pct:      buildConfig.jitter_pct,
            features:        buildConfig.features,
            tls_skip_verify: buildConfig.tls_skip_verify,
          },
        })
        markDone(2)
        setDoneData({ campaignId, campaignName: campaignPayload.name, profileId })
        onDone()
      } catch (e) {
        markError(2, errMsg(e))
        setRetryFrom(2)
      }
    }
  }

  function launchQuick() {
    const profile = PROFILES.find(p => p.id === selectedProfile)!
    const listenerConfig = quickForm.listenerMode === 'auto'
      ? { auto: true as const, name: 'qs-' + quickForm.campaignName, bind_host: window.location.hostname, bind_port: 4443, type: 'https' }
      : { auto: false as const, id: quickForm.listenerId }

    setStep(3)
    void runExecution(
      { name: quickForm.campaignName, client_name: quickForm.clientName },
      listenerConfig,
      { ...profile.build, os: quickForm.os, arch: quickForm.arch },
      selectedProfile!,
    )
  }

  function launchGuided() {
    const listenerConfig = guidedListener.mode === 'new'
      ? {
          auto:      true as const,
          name:      guidedListener.name || 'qs-' + guidedCampaign.name,
          bind_host: guidedListener.host || window.location.hostname,
          bind_port: Number(guidedListener.port) || 4443,
          type:      guidedListener.protocol || 'https',
        }
      : { auto: false as const, id: guidedListener.listenerId }

    setStep(5)
    void runExecution(
      {
        name:          guidedCampaign.name,
        client_name:   guidedCampaign.client_name,
        objective:     guidedCampaign.objective || undefined,
        scope_cidrs:   guidedCampaign.scope_cidrs.split(',').map(s => s.trim()).filter(Boolean),
        scope_domains: guidedCampaign.scope_domains.split(',').map(s => s.trim()).filter(Boolean),
      },
      listenerConfig,
      {
        os:              guidedPayload.os,
        arch:            guidedPayload.arch,
        sleep_seconds:   Number(guidedPayload.sleep_seconds),
        jitter_pct:      Number(guidedPayload.jitter_pct),
        features:        guidedPayload.features,
        sign:            guidedPayload.sign,
        tls_skip_verify: guidedPayload.tls_skip_verify,
      },
      'guided',
    )
  }

  const overlayClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.target === e.currentTarget) onClose()
  }

  const profile = PROFILES.find(p => p.id === selectedProfile)

  const totalSteps = mode === 'quick' ? 3 : 4

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.88)' }}
      onClick={overlayClick}
    >
      <div
        className="w-full dm-panel"
        style={{
          maxWidth:    '42rem',
          borderTop:   '2px solid var(--dm-accent-lo)',
          maxHeight:   '90vh',
          overflowY:   'auto',
          display:     'flex',
          flexDirection: 'column',
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-5 py-2.5"
          style={{ borderBottom: '1px solid var(--dm-border)', flexShrink: 0 }}
        >
          <div className="flex items-center gap-3">
            <span className="dm-section" style={{ flex: 'none' }}>Quick Start</span>
            {mode && step < (mode === 'quick' ? 4 : 6) && !doneData && (
              <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.62rem', letterSpacing: '0.1em' }}>
                {mode === 'quick' ? `step ${step} / ${totalSteps}` : `step ${step} / ${totalSteps}`}
              </span>
            )}
          </div>
          <button onClick={onClose} className="dm-action" style={{ fontSize: '0.9rem' }}>✕</button>
        </div>

        <div style={{ padding: '1.5rem', flex: 1 }}>

          {/* ── Step 0: Mode selection ── */}
          {step === 0 && (
            <div>
              <p style={{ color: 'var(--dm-text-mid)', fontSize: '0.78rem', marginBottom: '1.5rem' }}>
                How do you want to set up this engagement?
              </p>
              <div className="grid gap-3" style={{ gridTemplateColumns: '1fr 1fr' }}>
                {[
                  {
                    id:    'quick',
                    title: 'QUICK PATH',
                    desc:  'Choose a preset engagement profile. Only enter what\'s absolutely required — everything else is decided for you.',
                  },
                  {
                    id:    'guided',
                    title: 'GUIDED SETUP',
                    desc:  'Full control. Step-by-step through campaign, listener, payload, and delivery configuration.',
                  },
                ].map(opt => (
                  <button
                    key={opt.id}
                    onClick={() => { setMode(opt.id as Mode); setStep(1) }}
                    style={{
                      background:  'var(--dm-bg)',
                      border:      '1px solid var(--dm-border)',
                      padding:     '1.25rem',
                      cursor:      'pointer',
                      textAlign:   'left',
                      transition:  'border-color 0.12s',
                      fontFamily:  'inherit',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--dm-accent-lo)')}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--dm-border)')}
                  >
                    <div style={{ color: 'var(--dm-accent)', fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.2em', marginBottom: '0.6rem' }}>
                      {opt.title}
                    </div>
                    <div style={{ color: 'var(--dm-text-mid)', fontSize: '0.76rem', lineHeight: 1.5 }}>
                      {opt.desc}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* ── QUICK: Step 1 — Profile selection ── */}
          {mode === 'quick' && step === 1 && (
            <div>
              <p style={{ color: 'var(--dm-text-mid)', fontSize: '0.78rem', marginBottom: '1.25rem' }}>
                Select an engagement profile.
              </p>
              <div className="grid gap-3" style={{ gridTemplateColumns: '1fr 1fr' }}>
                {PROFILES.map(p => (
                  <button
                    key={p.id}
                    onClick={() => { setSelectedProfile(p.id); setStep(2) }}
                    style={{
                      background:   'var(--dm-bg)',
                      border:       `1px solid ${selectedProfile === p.id ? 'var(--dm-accent)' : 'var(--dm-border)'}`,
                      padding:      '1rem',
                      cursor:       'pointer',
                      textAlign:    'left',
                      transition:   'border-color 0.12s',
                      fontFamily:   'inherit',
                    }}
                    onMouseEnter={e => {
                      if (selectedProfile !== p.id) e.currentTarget.style.borderColor = 'var(--dm-accent-lo)'
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.borderColor = selectedProfile === p.id ? 'var(--dm-accent)' : 'var(--dm-border)'
                    }}
                  >
                    <div style={{ color: 'var(--dm-accent)', fontSize: '0.6rem', fontWeight: 700, letterSpacing: '0.18em', marginBottom: '0.4rem' }}>
                      {p.title}
                    </div>
                    <div style={{ color: 'var(--dm-text-mid)', fontSize: '0.74rem', lineHeight: 1.45, marginBottom: '0.6rem' }}>
                      {p.desc}
                    </div>
                    <div style={{ color: 'var(--dm-text-lo)', fontSize: '0.62rem', letterSpacing: '0.04em' }}>
                      {p.specs}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* ── QUICK: Step 2 — Minimal inputs ── */}
          {mode === 'quick' && step === 2 && profile && (
            <div className="space-y-4">
              <div style={{
                background:  'var(--dm-bg)',
                border:      '1px solid var(--dm-border)',
                borderLeft:  '2px solid var(--dm-accent-lo)',
                padding:     '0.55rem 0.8rem',
                fontSize:    '0.7rem',
                color:       'var(--dm-text-mid)',
                marginBottom: '0.5rem',
              }}>
                Profile: <span style={{ color: 'var(--dm-accent)' }}>{profile.title}</span>
                &nbsp;·&nbsp;{profile.specs}
              </div>

              <div>
                <label className="dm-label">Campaign Name</label>
                <input
                  required
                  className="dm-input"
                  value={quickForm.campaignName}
                  onChange={e => setQuickForm(f => ({ ...f, campaignName: e.target.value }))}
                />
              </div>
              <div>
                <label className="dm-label">Client Name</label>
                <input
                  required
                  className="dm-input"
                  value={quickForm.clientName}
                  onChange={e => setQuickForm(f => ({ ...f, clientName: e.target.value }))}
                />
              </div>

              <div className="grid gap-3" style={{ gridTemplateColumns: '1fr 1fr' }}>
                <div>
                  <label className="dm-label">Target OS</label>
                  <select
                    className="dm-select"
                    value={quickForm.os}
                    onChange={e => setQuickForm(f => ({ ...f, os: e.target.value }))}
                  >
                    <option value="windows">windows</option>
                    <option value="macos">macos</option>
                    <option value="linux">linux</option>
                  </select>
                </div>
                <div>
                  <label className="dm-label">Target Arch</label>
                  <select
                    className="dm-select"
                    value={quickForm.arch}
                    onChange={e => setQuickForm(f => ({ ...f, arch: e.target.value }))}
                  >
                    <option value="amd64">amd64</option>
                    <option value="arm64">arm64</option>
                  </select>
                </div>
              </div>

              {selectedProfile === 'stealth-external' && (
                <div>
                  <label className="dm-label">Target Domain (for phishing lure)</label>
                  <input
                    className="dm-input"
                    value={quickForm.targetDomain}
                    onChange={e => setQuickForm(f => ({ ...f, targetDomain: e.target.value }))}
                  />
                </div>
              )}

              <div>
                <label className="dm-label">Listener</label>
                <div className="flex gap-4" style={{ marginTop: '0.35rem' }}>
                  {(['auto','existing'] as const).map(opt => (
                    <label key={opt} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', fontSize: '0.76rem', color: 'var(--dm-text-mid)' }}>
                      <input
                        type="radio"
                        name="listenerMode"
                        value={opt}
                        checked={quickForm.listenerMode === opt}
                        onChange={() => setQuickForm(f => ({ ...f, listenerMode: opt }))}
                        style={{ accentColor: 'var(--dm-accent)' }}
                      />
                      {opt === 'auto' ? 'Auto-create new listener' : 'Use existing'}
                    </label>
                  ))}
                </div>
                {quickForm.listenerMode === 'existing' && (
                  <select
                    className="dm-select"
                    style={{ marginTop: '0.5rem' }}
                    value={quickForm.listenerId}
                    onChange={e => setQuickForm(f => ({ ...f, listenerId: e.target.value }))}
                  >
                    <option value="">— select listener —</option>
                    {listeners.map(l => (
                      <option key={l.id} value={l.id}>
                        {l.name} ({l.type}://{l.bind_host}:{l.bind_port})
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <div className="flex gap-3 pt-1">
                <button
                  className="dm-btn"
                  style={{ flex: 1 }}
                  disabled={!quickForm.campaignName || !quickForm.clientName || (quickForm.listenerMode === 'existing' && !quickForm.listenerId)}
                  onClick={launchQuick}
                >
                  Launch →
                </button>
                <button
                  className="dm-action"
                  style={{ padding: '0 1rem', fontSize: '0.72rem' }}
                  onClick={() => setStep(1)}
                >
                  ← Back
                </button>
              </div>
            </div>
          )}

          {/* ── GUIDED: Step 1 — Campaign ── */}
          {mode === 'guided' && step === 1 && (
            <div className="space-y-4">
              <div>
                <label className="dm-label">Campaign Name</label>
                <input required className="dm-input" value={guidedCampaign.name}
                  onChange={e => setGuidedCampaign(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">Client</label>
                <input required className="dm-input" value={guidedCampaign.client_name}
                  onChange={e => setGuidedCampaign(f => ({ ...f, client_name: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">Objective</label>
                <input className="dm-input" value={guidedCampaign.objective}
                  onChange={e => setGuidedCampaign(f => ({ ...f, objective: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">
                  Scope CIDRs
                  <span style={{ textTransform: 'none', color: 'var(--dm-text-dim)', marginLeft: '0.4rem' }}>(comma-separated)</span>
                </label>
                <input className="dm-input" placeholder="192.168.1.0/24, 10.0.0.0/8"
                  value={guidedCampaign.scope_cidrs}
                  onChange={e => setGuidedCampaign(f => ({ ...f, scope_cidrs: e.target.value }))} />
              </div>
              <div>
                <label className="dm-label">
                  Scope Domains
                  <span style={{ textTransform: 'none', color: 'var(--dm-text-dim)', marginLeft: '0.4rem' }}>(comma-separated)</span>
                </label>
                <input className="dm-input" placeholder="corp.local, example.com"
                  value={guidedCampaign.scope_domains}
                  onChange={e => setGuidedCampaign(f => ({ ...f, scope_domains: e.target.value }))} />
              </div>
              <button
                className="dm-btn"
                disabled={!guidedCampaign.name || !guidedCampaign.client_name}
                onClick={() => setStep(2)}
              >
                Next → Listener
              </button>
            </div>
          )}

          {/* ── GUIDED: Step 2 — Listener ── */}
          {mode === 'guided' && step === 2 && (
            <div className="space-y-4">
              <div>
                <label className="dm-label">Listener</label>
                <div className="flex gap-4" style={{ marginTop: '0.35rem', marginBottom: '0.75rem' }}>
                  {(['new','existing'] as const).map(opt => (
                    <label key={opt} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', fontSize: '0.76rem', color: 'var(--dm-text-mid)' }}>
                      <input
                        type="radio"
                        name="guidedListenerMode"
                        value={opt}
                        checked={guidedListener.mode === opt}
                        onChange={() => setGuidedListener(f => ({ ...f, mode: opt }))}
                        style={{ accentColor: 'var(--dm-accent)' }}
                      />
                      {opt === 'new' ? 'Create new listener' : 'Use existing listener'}
                    </label>
                  ))}
                </div>

                {guidedListener.mode === 'new' && (
                  <div className="space-y-3">
                    <div>
                      <label className="dm-label">Name</label>
                      <input className="dm-input" value={guidedListener.name}
                        onChange={e => setGuidedListener(f => ({ ...f, name: e.target.value }))} />
                    </div>
                    <div>
                      <label className="dm-label">Protocol</label>
                      <select className="dm-select" value={guidedListener.protocol}
                        onChange={e => setGuidedListener(f => ({ ...f, protocol: e.target.value }))}>
                        <option value="http">http</option>
                        <option value="https">https</option>
                      </select>
                    </div>
                    <div>
                      <label className="dm-label">Host</label>
                      <input className="dm-input" value={guidedListener.host}
                        onChange={e => setGuidedListener(f => ({ ...f, host: e.target.value }))} />
                    </div>
                    <div>
                      <label className="dm-label">Port</label>
                      <input type="number" className="dm-input" value={guidedListener.port}
                        onChange={e => setGuidedListener(f => ({ ...f, port: e.target.value }))} />
                    </div>
                  </div>
                )}

                {guidedListener.mode === 'existing' && (
                  <select className="dm-select" value={guidedListener.listenerId}
                    onChange={e => setGuidedListener(f => ({ ...f, listenerId: e.target.value }))}>
                    <option value="">— select listener —</option>
                    {listeners.map(l => (
                      <option key={l.id} value={l.id}>
                        {l.name} ({l.type}://{l.bind_host}:{l.bind_port})
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <div className="flex gap-3 pt-1">
                <button
                  className="dm-btn"
                  style={{ flex: 1 }}
                  disabled={guidedListener.mode === 'existing' && !guidedListener.listenerId}
                  onClick={() => setStep(3)}
                >
                  Next → Payload
                </button>
                <button className="dm-action" style={{ padding: '0 1rem', fontSize: '0.72rem' }} onClick={() => setStep(1)}>
                  ← Back
                </button>
              </div>
            </div>
          )}

          {/* ── GUIDED: Step 3 — Payload ── */}
          {mode === 'guided' && step === 3 && (
            <div className="space-y-4">
              <div className="grid gap-3" style={{ gridTemplateColumns: '1fr 1fr' }}>
                <div>
                  <label className="dm-label">OS</label>
                  <select className="dm-select" value={guidedPayload.os}
                    onChange={e => setGuidedPayload(f => ({ ...f, os: e.target.value }))}>
                    <option value="windows">windows</option>
                    <option value="macos">macos</option>
                    <option value="linux">linux</option>
                  </select>
                </div>
                <div>
                  <label className="dm-label">Arch</label>
                  <select className="dm-select" value={guidedPayload.arch}
                    onChange={e => setGuidedPayload(f => ({ ...f, arch: e.target.value }))}>
                    <option value="amd64">amd64</option>
                    <option value="arm64">arm64</option>
                  </select>
                </div>
                <div>
                  <label className="dm-label">Sleep (seconds)</label>
                  <input type="number" className="dm-input" value={guidedPayload.sleep_seconds}
                    onChange={e => setGuidedPayload(f => ({ ...f, sleep_seconds: e.target.value }))} />
                </div>
                <div>
                  <label className="dm-label">Jitter %</label>
                  <input type="number" className="dm-input" min="0" max="50" value={guidedPayload.jitter_pct}
                    onChange={e => setGuidedPayload(f => ({ ...f, jitter_pct: e.target.value }))} />
                </div>
              </div>

              <div>
                <label className="dm-label">Features</label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.35rem' }}>
                  {FEATURES.map(feat => (
                    <label key={feat} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', cursor: 'pointer', fontSize: '0.74rem', color: 'var(--dm-text-mid)' }}>
                      <input
                        type="checkbox"
                        checked={guidedPayload.features.includes(feat)}
                        onChange={e => setGuidedPayload(f => ({
                          ...f,
                          features: e.target.checked
                            ? [...f.features, feat]
                            : f.features.filter(x => x !== feat),
                        }))}
                        style={{ accentColor: 'var(--dm-accent)' }}
                      />
                      {feat}
                    </label>
                  ))}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '1.5rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', cursor: 'pointer', fontSize: '0.74rem', color: 'var(--dm-text-mid)' }}>
                  <input
                    type="checkbox"
                    checked={guidedPayload.sign}
                    onChange={e => setGuidedPayload(f => ({ ...f, sign: e.target.checked }))}
                    style={{ accentColor: 'var(--dm-accent)' }}
                  />
                  Sign
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', cursor: 'pointer', fontSize: '0.74rem', color: 'var(--dm-text-mid)' }}>
                  <input
                    type="checkbox"
                    checked={guidedPayload.tls_skip_verify}
                    onChange={e => setGuidedPayload(f => ({ ...f, tls_skip_verify: e.target.checked }))}
                    style={{ accentColor: 'var(--dm-accent)' }}
                  />
                  TLS Skip Verify
                </label>
              </div>

              <div className="flex gap-3 pt-1">
                <button className="dm-btn" style={{ flex: 1 }} onClick={() => setStep(4)}>
                  Next → Review
                </button>
                <button className="dm-action" style={{ padding: '0 1rem', fontSize: '0.72rem' }} onClick={() => setStep(2)}>
                  ← Back
                </button>
              </div>
            </div>
          )}

          {/* ── GUIDED: Step 4 — Review ── */}
          {mode === 'guided' && step === 4 && (
            <div className="space-y-4">
              <div style={{ fontSize: '0.6rem', letterSpacing: '0.15em', textTransform: 'uppercase', color: 'var(--dm-text-lo)', marginBottom: '1rem' }}>
                Review & Launch
              </div>

              {[
                { label: 'Campaign',    value: `${guidedCampaign.name} / ${guidedCampaign.client_name}` },
                { label: 'Objective',   value: guidedCampaign.objective || '—' },
                { label: 'Scope CIDRs', value: guidedCampaign.scope_cidrs || '—' },
                { label: 'Scope Domains', value: guidedCampaign.scope_domains || '—' },
                { label: 'Listener',    value: guidedListener.mode === 'new'
                    ? `new · ${guidedListener.protocol}://${guidedListener.host}:${guidedListener.port}`
                    : listeners.find(l => l.id === guidedListener.listenerId)?.name ?? guidedListener.listenerId
                },
                { label: 'OS / Arch',  value: `${guidedPayload.os} / ${guidedPayload.arch}` },
                { label: 'Sleep / Jitter', value: `${guidedPayload.sleep_seconds}s / ${guidedPayload.jitter_pct}%` },
                { label: 'Features',   value: guidedPayload.features.length ? guidedPayload.features.join(', ') : 'none' },
                { label: 'Sign',       value: guidedPayload.sign ? 'yes' : 'no' },
                { label: 'TLS Skip Verify', value: guidedPayload.tls_skip_verify ? 'yes' : 'no' },
              ].map(row => (
                <div key={row.label} style={{ display: 'flex', gap: '1rem', borderBottom: '1px solid var(--dm-border)', paddingBottom: '0.4rem' }}>
                  <span style={{ width: '9rem', flexShrink: 0, fontSize: '0.62rem', letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--dm-text-lo)' }}>
                    {row.label}
                  </span>
                  <span style={{ fontSize: '0.78rem', color: 'var(--dm-text-hi)' }}>{row.value}</span>
                </div>
              ))}

              <div className="flex gap-3 pt-1">
                <button className="dm-btn" style={{ flex: 1 }} onClick={launchGuided}>
                  Launch →
                </button>
                <button className="dm-action" style={{ padding: '0 1rem', fontSize: '0.72rem' }} onClick={() => setStep(3)}>
                  ← Back
                </button>
              </div>
            </div>
          )}

          {/* ── Execution (Quick step 3 or Guided step 5) ── */}
          {((mode === 'quick' && step === 3) || (mode === 'guided' && step === 5)) && !doneData && (
            <div>
              <div style={{ marginBottom: '1.5rem' }}>
                {execSteps.map((s, i) => {
                  const ind = STEP_INDICATOR[s.status]
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', marginBottom: '0.75rem' }}>
                      <span
                        className={s.status === 'running' ? 'dm-alive' : undefined}
                        style={{ color: ind.color, fontSize: '1rem', lineHeight: 1, flexShrink: 0, marginTop: '0.05rem' }}
                      >
                        {ind.symbol}
                      </span>
                      <div>
                        <span style={{ color: s.status === 'done' ? 'var(--dm-text-hi)' : 'var(--dm-text-mid)', fontSize: '0.8rem' }}>
                          {s.label}
                        </span>
                        {s.status === 'error' && s.error && (
                          <div style={{ color: 'var(--dm-red)', fontSize: '0.72rem', marginTop: '0.2rem' }}>
                            {s.error}
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>

              {retryFrom !== null && (
                <button
                  className="dm-btn"
                  style={{ maxWidth: '12rem' }}
                  onClick={() => {
                    const from = retryFrom
                    setRetryFrom(null)
                    if (mode === 'quick' && profile) {
                      const listenerConfig = quickForm.listenerMode === 'auto'
                        ? { auto: true as const, name: 'qs-' + quickForm.campaignName, bind_host: window.location.hostname, bind_port: 4443, type: 'https' }
                        : { auto: false as const, id: quickForm.listenerId }
                      void runExecution(
                        { name: quickForm.campaignName, client_name: quickForm.clientName },
                        listenerConfig,
                        { ...profile.build, os: quickForm.os, arch: quickForm.arch },
                        selectedProfile!,
                        from,
                      )
                    } else {
                      const listenerConfig = guidedListener.mode === 'new'
                        ? { auto: true as const, name: guidedListener.name || 'qs-' + guidedCampaign.name, bind_host: guidedListener.host || window.location.hostname, bind_port: Number(guidedListener.port) || 4443, type: guidedListener.protocol || 'https' }
                        : { auto: false as const, id: guidedListener.listenerId }
                      void runExecution(
                        {
                          name:          guidedCampaign.name,
                          client_name:   guidedCampaign.client_name,
                          objective:     guidedCampaign.objective || undefined,
                          scope_cidrs:   guidedCampaign.scope_cidrs.split(',').map(s => s.trim()).filter(Boolean),
                          scope_domains: guidedCampaign.scope_domains.split(',').map(s => s.trim()).filter(Boolean),
                        },
                        listenerConfig,
                        {
                          os:              guidedPayload.os,
                          arch:            guidedPayload.arch,
                          sleep_seconds:   Number(guidedPayload.sleep_seconds),
                          jitter_pct:      Number(guidedPayload.jitter_pct),
                          features:        guidedPayload.features,
                          sign:            guidedPayload.sign,
                          tls_skip_verify: guidedPayload.tls_skip_verify,
                        },
                        'guided',
                        from,
                      )
                    }
                  }}
                >
                  Retry →
                </button>
              )}
            </div>
          )}

          {/* ── Done / Success screen ── */}
          {doneData && (
            <div>
              <div style={{ color: 'var(--dm-accent)', fontSize: '1rem', fontWeight: 700, letterSpacing: '0.08em', marginBottom: '0.5rem' }}>
                Engagement ready.
              </div>
              <div style={{ color: 'var(--dm-text-mid)', fontSize: '0.8rem', marginBottom: '1.5rem' }}>
                {doneData.campaignName}
              </div>

              <div className="flex gap-3" style={{ flexWrap: 'wrap' }}>
                <Link
                  to={`/campaigns/${doneData.campaignId}`}
                  className="dm-btn"
                  style={{ display: 'inline-block', textDecoration: 'none', maxWidth: '14rem', textAlign: 'center' }}
                  onClick={onClose}
                >
                  Go to Campaign →
                </Link>
                {doneData.profileId === 'stealth-external' && (
                  <Link
                    to="/lure-gen"
                    className="dm-btn"
                    style={{ display: 'inline-block', textDecoration: 'none', maxWidth: '10rem', textAlign: 'center', background: 'transparent', border: '1px solid var(--dm-accent-lo)', color: 'var(--dm-accent)' }}
                    onClick={onClose}
                  >
                    Lure Gen →
                  </Link>
                )}
              </div>

              {doneData.profileId === 'stealth-external' && (
                <p style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem', fontStyle: 'italic', marginTop: '1rem', lineHeight: 1.5 }}>
                  Download the payload from Builds once it compiles, then go to Lure Gen to generate the phishing package.
                </p>
              )}

              <div style={{ marginTop: '1rem' }}>
                {execSteps.map((s, i) => {
                  const ind = STEP_INDICATOR[s.status]
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
                      <span style={{ color: ind.color, fontSize: '0.9rem' }}>{ind.symbol}</span>
                      <span style={{ color: 'var(--dm-text-mid)', fontSize: '0.76rem' }}>{s.label}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  )
}
