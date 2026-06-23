import { useRef, useState } from 'react'
import { api } from '../../api/client'

interface Props {
  sessionId:   string
  sleepSeconds: number
  jitterPct:   number
  onSleepUpdated?: () => void
}

export function SessionActions({ sessionId, sleepSeconds, jitterPct, onSleepUpdated }: Props) {
  const [busy, setBusy]           = useState<string | null>(null)
  const [screenshot, setScreenshot] = useState<string | null>(null)
  const [sleepVal, setSleepVal]   = useState(String(sleepSeconds))
  const [jitterVal, setJitterVal] = useState(String(jitterPct))
  const fileInputRef              = useRef<HTMLInputElement>(null)
  const destPathRef               = useRef<string>('')

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
        // swallow transient network errors and keep polling
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
      const blob = new Blob([bytes], { type: 'image/bmp' })
      const url  = URL.createObjectURL(blob)
      setScreenshot(url)
    } catch (e: any) {
      alert(`Screenshot error: ${e.message}`)
    } finally {
      setBusy(null)
    }
  }

  async function downloadFile() {
    const path = prompt('Remote file path to download:')
    if (!path) return
    setBusy('download')
    try {
      const taskId = await queueTask('upload', { path })
      const bytes  = await pollOutput(taskId)
      if (!bytes) { alert('Download failed or timed out.'); return }
      const filename = path.split(/[\\/]/).pop() || 'file'
      const blob = new Blob([bytes])
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: any) {
      alert(`Download error: ${e.message}`)
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
        reader.onload  = () => {
          const result = reader.result
          if (typeof result !== 'string') { rej(new Error('FileReader returned unexpected type')); return }
          const b64 = result.split(',')[1]
          if (!b64) { rej(new Error('FileReader produced no base64 data')); return }
          res(b64)
        }
        reader.onerror = rej
        reader.readAsDataURL(file)
      })
      const taskId = await queueTask('download', { path: dest, data })
      await pollOutput(taskId)
      alert(`Uploaded to ${dest}`)
    } catch (e: any) {
      alert(`Upload error: ${e.message}`)
    } finally {
      setBusy(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  async function updateSleep() {
    const s = parseInt(sleepVal)
    const j = parseInt(jitterVal)
    if (isNaN(s) || s < 1 || isNaN(j) || j < 0 || j > 100) {
      alert('Sleep: 1–86400 seconds, jitter: 0–100 %')
      return
    }
    setBusy('sleep')
    try {
      await api.patch(`/api/v1/sessions/${sessionId}/sleep`, { sleep_seconds: s, jitter_pct: j })
      onSleepUpdated?.()
    } catch (e: any) {
      alert(`Sleep update error: ${e.message}`)
    } finally {
      setBusy(null)
    }
  }

  async function killAgent() {
    if (!confirm('Send kill task? Agent will exit cleanly after completing pending tasks.')) return
    setBusy('kill')
    try {
      await queueTask('kill', {})
    } catch (e: any) {
      alert(`Kill error: ${e.message}`)
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <div className="flex items-center gap-3 px-3 py-1.5 border-b border-gray-800 text-xs font-mono flex-wrap">

        {/* Screenshot */}
        <button
          onClick={takeScreenshot}
          disabled={!!busy}
          className="text-gray-400 hover:text-blue-400 disabled:opacity-40 transition-colors"
        >
          {busy === 'screenshot' ? '⏳ screenshot…' : '📷 screenshot'}
        </button>

        <span className="text-gray-700">|</span>

        {/* File download (from target) */}
        <button
          onClick={downloadFile}
          disabled={!!busy}
          className="text-gray-400 hover:text-green-400 disabled:opacity-40 transition-colors"
        >
          {busy === 'download' ? '⏳ downloading…' : '↓ download file'}
        </button>

        {/* File upload (to target) */}
        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={!!busy}
          className="text-gray-400 hover:text-green-400 disabled:opacity-40 transition-colors"
        >
          {busy === 'upload' ? '⏳ uploading…' : '↑ upload file'}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={e => { if (e.target.files?.[0]) uploadFile(e.target.files[0]) }}
        />

        <span className="text-gray-700">|</span>

        {/* Sleep */}
        <span className="text-gray-500">sleep</span>
        <input
          type="number"
          value={sleepVal}
          onChange={e => setSleepVal(e.target.value)}
          min={1} max={86400}
          className="w-16 bg-gray-900 border border-gray-700 rounded px-1 text-gray-300 text-xs font-mono text-center focus:outline-none focus:border-gray-500"
        />
        <span className="text-gray-500">s ±</span>
        <input
          type="number"
          value={jitterVal}
          onChange={e => setJitterVal(e.target.value)}
          min={0} max={100}
          className="w-12 bg-gray-900 border border-gray-700 rounded px-1 text-gray-300 text-xs font-mono text-center focus:outline-none focus:border-gray-500"
        />
        <span className="text-gray-500">%</span>
        <button
          onClick={updateSleep}
          disabled={!!busy}
          className="text-gray-400 hover:text-yellow-400 disabled:opacity-40 transition-colors"
        >
          {busy === 'sleep' ? '⏳' : 'apply'}
        </button>

        <span className="text-gray-700 ml-auto">|</span>

        {/* Kill */}
        <button
          onClick={killAgent}
          disabled={!!busy}
          className="text-gray-600 hover:text-red-400 disabled:opacity-40 transition-colors"
        >
          {busy === 'kill' ? '⏳ killing…' : '✕ kill'}
        </button>
      </div>

      {/* Screenshot modal */}
      {screenshot && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80"
          onClick={() => { URL.revokeObjectURL(screenshot); setScreenshot(null) }}
        >
          <div className="relative max-w-[90vw] max-h-[90vh]" onClick={e => e.stopPropagation()}>
            <img src={screenshot} alt="screenshot" className="max-w-full max-h-[85vh] rounded border border-gray-700 shadow-2xl" />
            <div className="flex justify-between items-center mt-2 text-xs font-mono text-gray-500">
              <span>click outside to close</span>
              <a
                href={screenshot}
                download="screenshot.bmp"
                className="text-blue-400 hover:text-blue-300"
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
