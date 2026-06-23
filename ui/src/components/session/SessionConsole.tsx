import { useEffect, useRef, useState } from 'react'
import { Terminal } from 'xterm'
import { FitAddon } from '@xterm/addon-fit'
import 'xterm/css/xterm.css'
import { api } from '../../api/client'

interface Props {
  sessionId:   string
  campaignId?: string
}

export function SessionConsole({ sessionId, campaignId: _campaignId }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)  // observed for size changes
  const termRef      = useRef<HTMLDivElement>(null)  // xterm mount point (absolute)
  const term         = useRef<Terminal>()
  const fitAddon     = useRef<FitAddon>()
  const [input, setInput] = useState('')
  const [busy, setBusy]   = useState(false)

  useEffect(() => {
    if (!termRef.current || !containerRef.current) return

    const t = new Terminal({
      theme: {
        background: '#0d1117',
        foreground: '#c9d1d9',
        cursor:     '#58a6ff',
        green:      '#3fb950',
        red:        '#f85149',
        yellow:     '#d29922',
      },
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      fontSize:   13,
      cursorBlink: true,
      convertEol:  true,
    })

    const fa = new FitAddon()
    t.loadAddon(fa)
    t.open(termRef.current)
    fa.fit()

    term.current    = t
    fitAddon.current = fa

    t.writeln('\x1b[32mDungeonMaster — Session Console\x1b[0m')
    t.writeln(`\x1b[90mSession: ${sessionId}\x1b[0m`)
    t.writeln('')

    // Observe the wrapper (not the xterm div) so canvas resizes don't retrigger
    const obs = new ResizeObserver(() => requestAnimationFrame(() => fa.fit()))
    obs.observe(containerRef.current)

    return () => {
      obs.disconnect()
      t.dispose()
    }
  }, [sessionId])

  async function sendCommand(cmd: string) {
    if (!cmd.trim() || busy) return
    setBusy(true)

    term.current?.writeln(`\x1b[33m» ${cmd}\x1b[0m`)

    try {
      const { data } = await api.post(`/api/v1/tasks`, {
        session_id: sessionId,
        type:       'shell',
        // Go's encoding/json decodes []byte fields from base64
        args:       btoa(JSON.stringify({ cmd })),
      })

      // Poll for output (Phase 1 — simple polling)
      await pollTaskOutput(data.task_id)
    } catch (err: any) {
      term.current?.writeln(`\x1b[31mError: ${err.message}\x1b[0m`)
    } finally {
      setBusy(false)
    }
  }

  async function pollTaskOutput(taskId: string) {
    for (let attempt = 0; attempt < 60; attempt++) {
      await sleep(2000)
      try {
        const { data } = await api.get(`/api/v1/tasks/${taskId}`)
        if (data.status === 'complete' || data.status === 'failed') {
          const output = data.output
            ? atob(data.output)
            : '(no output)'
          const color = data.status === 'complete' ? '' : '\x1b[31m'
          term.current?.writeln(`${color}${output}\x1b[0m`)
          return
        }
      } catch {
        // continue polling
      }
    }
    term.current?.writeln('\x1b[31mTimeout waiting for task output\x1b[0m')
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      sendCommand(input)
      setInput('')
    }
  }

  return (
    <div className="flex flex-col h-full bg-[#0d1117] rounded-lg overflow-hidden border border-gray-700">
      {/* Terminal output area — containerRef is observed; termRef is the absolute xterm mount */}
      <div ref={containerRef} className="flex-1 min-h-0 relative">
        <div ref={termRef} className="absolute inset-0 p-2" />
      </div>

      {/* Command input */}
      <div className="flex items-center border-t border-gray-700 px-3 py-2 gap-2">
        <span className="text-green-400 font-mono text-sm select-none">$</span>
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={busy}
          placeholder={busy ? 'waiting for output...' : 'enter command'}
          className="flex-1 bg-transparent text-gray-200 font-mono text-sm outline-none placeholder-gray-600"
          autoComplete="off"
          spellCheck={false}
        />
        {busy && (
          <span className="text-yellow-400 text-xs animate-pulse">running</span>
        )}
      </div>
    </div>
  )
}

function sleep(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}

