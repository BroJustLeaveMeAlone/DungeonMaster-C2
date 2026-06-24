import { useRef, useState } from 'react'
import { api } from '../../api/client'

interface Props {
  sessionId:    string
  sleepSeconds: number
  jitterPct:    number
  onSleepUpdated?: () => void
}

export function SessionActions({ sessionId, sleepSeconds, jitterPct, onSleepUpdated }: Props) {
  const [busy, setBusy]             = useState<string | null>(null)
  const [screenshot, setScreenshot] = useState<string | null>(null)
  const [sleepVal, setSleepVal]     = useState(String(sleepSeconds))
  const [jitterVal, setJitterVal]   = useState(String(jitterPct))
  const fileInputRef                = useRef<HTMLInputElement>(null)

  async function queueTask(type: string, args: Record<string, unknown>) {
    const { data } = await api.post('/api/v1/tasks', {
      session_id: sessionId,
      type,
      args: btoa(JSON.stringify(args)),
    })
    return data.task_id as string
  }

  async function pollOutput(taskId: string): Promise<Uint8Array | null> {
    for (let i = 0; i < 60; i++) {
      await sleep(2000)
      try {
        const { data } = await api.get(`/api/v1/tasks/${taskId}`)
        if (data.status === 'complete' || data.status === 'failed') {
          if (!data.output || data.status === 'failed') return null
          return Uint8Array.from(atob(data.output), c => c.charCodeAt(0))
        }
      } catch {
        // swallow transient errors and keep polling
      }
    }
    return null
  }

  async function takeScreenshot() {
    setBusy('screenshot')
    try {
      const taskId = await queueTask('screenshot', {})
      const bytes  = await pollOutput(taskId)
      if (!bytes) { alert('Screenshot failed or timed out.'); return }
      const blob = new Blob([bytes.buffer as ArrayBuffer], { type: 'image/bmp' })
      setScreenshot(URL.createObjectURL(blob))
    } catch (e: unknown) {
      alert(`Screenshot error: ${(e as Error).message}`)
    } finally {
      setBusy(null)
    }
  }

  async function downloadFile() {
    const path = prompt('Remote file path to download:')
    if (!path) return
    setBusy('download')
    try {
      const taskId  = await queueTask('upload', { path })
      const bytes   = await pollOutput(taskId)
      if (!bytes) { alert('Download failed or timed out.'); return }
      const filename = path.split(/[\\/]/).pop() || 'file'
      const blob = new Blob([bytes.buffer as ArrayBuffer])
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url; a.download = filename; a.click()
      URL.revokeObjectURL(url)
    } catch (e: unknown) {
      alert(`Download error: ${(e as Error).message}`)
    } finally {
      setBusy(null)
    }
  }

  async function uploadFile(file: File) {
    const dest = prompt('Destination path on target:', `C:\\Users\\Public\\${file.name}`)
    if (!dest) return
    setBusy('upload')
    try {
      const reader = new FileReader()
      const data   = await new Promise<string>((res, rej) => {
        reader.onload = () => {
          const result = reader.result
          if (typeof result !== 'string') { rej(new Error('Unexpected FileReader result')); return }
          const b64 = result.split(',')[1]
          if (!b64) { rej(new Error('No base64 data')); return }
          res(b64)
        }
        reader.onerror = rej
        reader.readAsDataURL(file)
      })
      const taskId = await queueTask('download', { path: dest, data })
      await pollOutput(taskId)
      alert(`Uploaded to ${dest}`)
    } catch (e: unknown) {
      alert(`Upload error: ${(e as Error).message}`)
    } finally {
      setBusy(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

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
    <>
      <div
        className="flex items-center gap-1.5 px-3 py-1.5 flex-wrap flex-shrink-0"
        style={{ borderBottom: '1px solid var(--dm-border)', minHeight: '34px' }}
      >
        <button
          className="dm-action dm-go"
          disabled={!!busy}
          onClick={takeScreenshot}
        >
          {busy === 'screenshot' ? 'SCR…' : 'SCR'}
        </button>

        {sep}

        <button className="dm-action dm-go" disabled={!!busy} onClick={downloadFile}>
          {busy === 'download' ? '↓ DL…' : '↓ FILE'}
        </button>

        <button className="dm-action dm-go" disabled={!!busy} onClick={() => fileInputRef.current?.click()}>
          {busy === 'upload' ? '↑ UL…' : '↑ FILE'}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={e => { if (e.target.files?.[0]) uploadFile(e.target.files[0]) }}
        />

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

      {/* Screenshot modal */}
      {screenshot && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.88)' }}
          onClick={() => { URL.revokeObjectURL(screenshot); setScreenshot(null) }}
        >
          <div
            className="relative"
            style={{ maxWidth: '90vw', maxHeight: '90vh' }}
            onClick={e => e.stopPropagation()}
          >
            <img
              src={screenshot}
              alt="screenshot"
              style={{ maxWidth: '100%', maxHeight: '85vh', display: 'block', border: '1px solid var(--dm-border-hi)' }}
            />
            <div className="flex justify-between items-center mt-2" style={{ fontSize: '0.7rem', color: 'var(--dm-text-lo)' }}>
              <span>click outside to close</span>
              <a
                href={screenshot}
                download="screenshot.bmp"
                style={{ color: 'var(--dm-blue)', textDecoration: 'none' }}
                onClick={e => e.stopPropagation()}
              >
                ↓ save
              </a>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

function sleep(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
