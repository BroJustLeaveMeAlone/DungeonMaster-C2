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
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef      = useRef<HTMLDivElement>(null)
  const term         = useRef<Terminal>()
  const fitAddon     = useRef<FitAddon>()
  const [input, setInput] = useState('')
  const [busy, setBusy]   = useState(false)

  useEffect(() => {
    if (!termRef.current || !containerRef.current) return

    const t = new Terminal({
      theme: {
        background:   '#060a10',
        foreground:   '#c4ddf0',
        cursor:       '#00d4b0',
        cursorAccent: '#060a10',
        selectionBackground: 'rgba(0,212,176,0.2)',
        black:   '#060a10',
        red:     '#ff3a4c',
        green:   '#00d4b0',
        yellow:  '#ffb730',
        blue:    '#4090ff',
        magenta: '#9966ff',
        cyan:    '#00b8a0',
        white:   '#c4ddf0',
        brightBlack:   '#2c4258',
        brightRed:     '#ff6070',
        brightGreen:   '#00e5c0',
        brightYellow:  '#ffd060',
        brightBlue:    '#60a8ff',
        brightMagenta: '#b880ff',
        brightCyan:    '#40d0b8',
        brightWhite:   '#e8f4ff',
      },
      fontFamily: '"Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace',
      fontSize:   13,
      lineHeight: 1.4,
      cursorBlink:  true,
      convertEol:   true,
      scrollback:   5000,
    })

    const fa = new FitAddon()
    t.loadAddon(fa)
    t.open(termRef.current)
    fa.fit()

    term.current     = t
    fitAddon.current = fa

    t.writeln('\x1b[36mDungeonMaster C2 — Interactive Shell\x1b[0m')
    t.writeln(`\x1b[90mSession: ${sessionId}\x1b[0m`)
    t.writeln('')

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
    term.current?.writeln(`\x1b[33m$ ${cmd}\x1b[0m`)
    try {
      const { data } = await api.post('/api/v1/tasks', {
        session_id: sessionId,
        type:       'shell',
        args:       btoa(JSON.stringify({ cmd })),
      })
      await pollTaskOutput(data.task_id)
    } catch (err: unknown) {
      term.current?.writeln(`\x1b[31mError: ${(err as Error).message}\x1b[0m`)
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
          const output = data.output ? atob(data.output) : '(no output)'
          const color  = data.status === 'complete' ? '\x1b[0m' : '\x1b[31m'
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
    <div
      className="flex flex-col h-full overflow-hidden"
      style={{ background: '#060a10', border: '1px solid var(--dm-border)' }}
    >
      <div ref={containerRef} className="flex-1 min-h-0 relative">
        <div ref={termRef} className="absolute inset-0 p-2" />
      </div>

      <div
        className="flex items-center gap-2 flex-shrink-0"
        style={{
          borderTop: '1px solid var(--dm-border)',
          padding: '0.4rem 0.75rem',
          background: '#060a10',
        }}
      >
        <span style={{ color: 'var(--dm-accent)', userSelect: 'none', fontSize: '0.82rem' }}>$</span>
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={busy}
          placeholder={busy ? 'waiting for output...' : 'enter command'}
          autoComplete="off"
          spellCheck={false}
          style={{
            flex: 1,
            background: 'transparent',
            border: 'none',
            outline: 'none',
            color: 'var(--dm-text-hi)',
            fontFamily: 'inherit',
            fontSize: '0.82rem',
          }}
        />
        {busy && (
          <span style={{ color: 'var(--dm-amber)', fontSize: '0.65rem', letterSpacing: '0.12em', animation: 'dm-pulse 1.2s ease-in-out infinite' }}>
            RUNNING
          </span>
        )}
      </div>
    </div>
  )
}

function sleep(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
