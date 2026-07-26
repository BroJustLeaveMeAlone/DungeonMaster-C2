import { useState } from 'react'
import { api } from '../../api/client'
import { useTaskQueue } from '../../hooks/useTaskQueue'
import { type RichContent, detectOutputType } from './RichOutput'

interface Props {
  sessionId:           string
  sleepSeconds:        number
  jitterPct:           number
  onSleepUpdated?:     () => void
  onOpenTaskBuilder:   () => void
  onRichOutput?:       (content: RichContent) => void
}

export function SessionActions({
  sessionId,
  sleepSeconds,
  jitterPct,
  onSleepUpdated,
  onOpenTaskBuilder,
  onRichOutput,
}: Props) {
  const [busy, setBusy]           = useState<string | null>(null)
  const [sleepVal, setSleepVal]   = useState(String(sleepSeconds))
  const [jitterVal, setJitterVal] = useState(String(jitterPct))

  const { queueTask, pollOutput } = useTaskQueue(sessionId)

  async function updateSleep() {
    const s = parseInt(sleepVal)
    const j = parseInt(jitterVal)
    if (isNaN(s) || s < 1 || isNaN(j) || j < 0 || j > 100) {
      alert('Sleep: 1–86400 s, jitter: 0–100 %')
      return
    }
    setBusy('sleep')
    try {
      await api.patch(`/api/v1/sessions/${sessionId}/sleep`, { sleep_seconds: s, jitter_pct: j })
      onSleepUpdated?.()
    } catch (e: unknown) {
      alert(`Sleep update error: ${(e as Error).message}`)
    } finally {
      setBusy(null)
    }
  }

  async function killAgent() {
    if (!confirm('Send kill task? Agent will exit cleanly after completing pending tasks.')) return
    setBusy('kill')
    try {
      await queueTask('kill', {})
    } catch (e: unknown) {
      alert(`Kill error: ${(e as Error).message}`)
    } finally {
      setBusy(null)
    }
  }

  async function quickSummary() {
    setBusy('summary')
    try {
      const [tid1, tid2, tid3] = await Promise.all([
        queueTask('enum', { method: 'computer' }),
        queueTask('enum', { method: 'processes' }),
        queueTask('enum', { method: 'users' }),
      ])
      const [b1, b2, b3] = await Promise.all([
        pollOutput(tid1),
        pollOutput(tid2),
        pollOutput(tid3),
      ])
      const pairs: Array<[Uint8Array | null, string]> = [
        [b1, 'enum/computer'],
        [b2, 'enum/processes'],
        [b3, 'enum/users'],
      ]
      for (const [bytes, lbl] of pairs) {
        if (!bytes) continue
        const rich = detectOutputType(bytes, lbl)
        if (rich) onRichOutput?.(rich)
        else onRichOutput?.({ kind: 'json', text: new TextDecoder().decode(bytes), label: lbl })
      }
    } catch (e: unknown) {
      alert(`Summary error: ${(e as Error).message}`)
    } finally {
      setBusy(null)
    }
  }

  const sep = (
    <span style={{ color: 'var(--dm-border-hi)', userSelect: 'none', padding: '0 0.25rem' }}>│</span>
  )

  const inputNumCls: React.CSSProperties = {
    background: 'var(--dm-bg)',
    border: '1px solid var(--dm-border)',
    color: 'var(--dm-text-hi)',
    fontFamily: 'inherit',
    fontSize: '0.72rem',
    padding: '0.1rem 0.35rem',
    outline: 'none',
    textAlign: 'center',
    borderRadius: 0,
    width: '52px',
  }

  return (
    <div
      className="flex items-center gap-1.5 px-3 py-1.5 flex-wrap flex-shrink-0"
      style={{ borderBottom: '1px solid var(--dm-border)', minHeight: '34px' }}
    >
      <button
        className="dm-action dm-go"
        disabled={!!busy}
        onClick={onOpenTaskBuilder}
      >
        TASKS
      </button>

      <button
        className="dm-action dm-go"
        disabled={!!busy}
        onClick={quickSummary}
        title="Quick enum: computer info"
      >
        {busy === 'summary' ? 'SUM…' : 'SUMMARY'}
      </button>

      {sep}

      <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.68rem', letterSpacing: '0.08em' }}>SLEEP</span>
      <input
        type="number"
        value={sleepVal}
        min={1} max={86400}
        onChange={e => setSleepVal(e.target.value)}
        style={inputNumCls}
      />
      <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.68rem' }}>s ±</span>
      <input
        type="number"
        value={jitterVal}
        min={0} max={100}
        onChange={e => setJitterVal(e.target.value)}
        style={{ ...inputNumCls, width: '42px' }}
      />
      <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.68rem' }}>%</span>
      <button className="dm-action dm-go" disabled={!!busy} onClick={updateSleep}>
        {busy === 'sleep' ? 'SET…' : 'SET'}
      </button>

      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
        {sep}
        <button className="dm-action dm-danger" disabled={!!busy} onClick={killAgent}>
          {busy === 'kill' ? 'KILL…' : 'KILL'}
        </button>
      </div>
    </div>
  )
}
