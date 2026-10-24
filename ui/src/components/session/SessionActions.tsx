import { useState, useEffect } from 'react'
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
  const [inlineMsg, setInlineMsg] = useState<{
    text: string
    kind: 'error' | 'confirm'
    onConfirm?: () => void
  } | null>(null)

  const { queueTask, pollOutput } = useTaskQueue(sessionId)

  useEffect(() => {
    if (inlineMsg?.kind !== 'error') return
    const t = setTimeout(() => setInlineMsg(null), 4000)
    return () => clearTimeout(t)
  }, [inlineMsg])

  async function updateSleep() {
    const s = parseInt(sleepVal)
    const j = parseInt(jitterVal)
    if (isNaN(s) || s < 1 || isNaN(j) || j < 0 || j > 100) {
      setInlineMsg({ text: 'Sleep: 1–86400 s, jitter: 0–100 %', kind: 'error' })
      return
    }
    setBusy('sleep')
    try {
      await api.patch(`/api/v1/sessions/${sessionId}/sleep`, { sleep_seconds: s, jitter_pct: j })
      onSleepUpdated?.()
    } catch (e: unknown) {
      setInlineMsg({ text: `Sleep update error: ${(e as Error).message}`, kind: 'error' })
    } finally {
      setBusy(null)
    }
  }

  async function killAgent() {
    setInlineMsg({
      text: 'Send kill task? Agent exits cleanly after completing pending tasks.',
      kind: 'confirm',
      onConfirm: async () => {
        setBusy('kill')
        try {
          await queueTask('kill', {})
        } catch (e: unknown) {
          setInlineMsg({ text: `Kill error: ${(e as Error).message}`, kind: 'error' })
        } finally {
          setBusy(null)
        }
      },
    })
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
      setInlineMsg({ text: `Summary error: ${(e as Error).message}`, kind: 'error' })
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
    <div className="flex flex-col flex-shrink-0" style={{ borderBottom: '1px solid var(--dm-border)' }}>
      <div className="flex items-center gap-1.5 px-3 py-1.5 flex-wrap" style={{ minHeight: '34px' }}>
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

      {inlineMsg && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.2rem 0.75rem 0.35rem', borderTop: '1px solid var(--dm-border)' }}>
          <span style={{ color: inlineMsg.kind === 'error' ? 'var(--dm-red)' : 'var(--dm-amber)', fontSize: '0.72rem' }}>
            {inlineMsg.text}
          </span>
          {inlineMsg.kind === 'confirm' && (
            <>
              <button className="dm-action dm-danger" onClick={() => { inlineMsg.onConfirm?.(); setInlineMsg(null) }}>Confirm</button>
              <button className="dm-action" onClick={() => setInlineMsg(null)}>Cancel</button>
            </>
          )}
          {inlineMsg.kind === 'error' && (
            <button className="dm-action" onClick={() => setInlineMsg(null)}>✕</button>
          )}
        </div>
      )}
    </div>
  )
}
