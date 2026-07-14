import { useState } from 'react'
import { ChevronDown, ChevronUp, Trash2 } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

export type PersistEntry = {
  id:       string
  method:   string
  args:     Record<string, unknown>
  queuedAt: Date
}

function label(e: PersistEntry): string {
  const s = (k: string) => String(e.args[k] ?? '')
  switch (e.method) {
    case 'reg':     return `Run key: ${s('val')} → ${s('key')}`
    case 'task':    return `Scheduled task: ${s('name')}`
    case 'svc':     return `Service: ${s('name')}`
    case 'startup': return `Startup folder: ${s('name')}`
    case 'com':     return `COM hijack: ${s('clsid')}`
    case 'wmi':     return `WMI subscription: ${s('name')}`
    default:        return `persist/${e.method}`
  }
}

function removeTask(e: PersistEntry): { type: string; args: Record<string, unknown> } | null {
  const s = (k: string) => String(e.args[k] ?? '')
  switch (e.method) {
    case 'reg':
      return { type: 'persist', args: { method: 'reg-rm', key: e.args.key, val: e.args.val } }
    case 'svc':
      return { type: 'persist', args: { method: 'svc-rm', name: e.args.name } }
    case 'task':
      return { type: 'shell', args: { cmd: `schtasks /delete /tn "${s('name')}" /f` } }
    case 'startup':
      return { type: 'shell', args: { cmd: `del /f "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\${s('name')}"` } }
    case 'com':
      return { type: 'shell', args: { cmd: `reg delete "HKCU\\Software\\Classes\\CLSID\\${s('clsid')}" /f` } }
    case 'wmi':
      return {
        type: 'shell',
        args: { cmd: `wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer where "Name='${s('name')}'" delete & wmic /namespace:\\\\root\\subscription path __EventFilter where "Name='${s('name')}'" delete` },
      }
    default:
      return null
  }
}

interface Props {
  entries:   PersistEntry[]
  onRemove:  (entry: PersistEntry, task: { type: string; args: Record<string, unknown> }) => void
  onDismiss: (id: string) => void
}

export function PersistenceTracker({ entries, onRemove, onDismiss }: Props) {
  const [expanded, setExpanded] = useState(true)

  if (entries.length === 0) return null

  return (
    <div style={{ borderBottom: '1px solid var(--dm-border)', flexShrink: 0 }}>
      <button
        onClick={() => setExpanded(e => !e)}
        style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          width: '100%', padding: '0.25rem 0.75rem',
          background: 'rgba(153,102,255,0.07)',
          border: 'none', cursor: 'pointer', textAlign: 'left',
        }}
      >
        <span style={{ color: 'var(--dm-purple)', fontSize: '0.6rem', letterSpacing: '0.12em', fontWeight: 700 }}>
          ◆ PERSISTENCE
        </span>
        <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.68rem' }}>
          {entries.length} active mechanism{entries.length !== 1 ? 's' : ''}
        </span>
        <span style={{ marginLeft: 'auto', color: 'var(--dm-text-lo)', display: 'flex', alignItems: 'center' }}>
          {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
        </span>
      </button>

      {expanded && (
        <div style={{ maxHeight: '150px', overflowY: 'auto' }}>
          {entries.map(entry => {
            const rt = removeTask(entry)
            return (
              <div
                key={entry.id}
                className="flex items-center gap-2 px-3"
                style={{
                  padding: '0.3rem 0.75rem',
                  borderTop: '1px solid rgba(255,255,255,0.04)',
                  fontSize: '0.72rem',
                }}
              >
                <span style={{
                  color: 'var(--dm-purple)',
                  fontFamily: 'Consolas, monospace',
                  fontSize: '0.68rem',
                  flexShrink: 0,
                  minWidth: '64px',
                }}>
                  {entry.method}
                </span>
                <span style={{
                  color: 'var(--dm-text-mid)',
                  flex: 1,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {label(entry)}
                </span>
                <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.62rem', flexShrink: 0 }}>
                  {formatDistanceToNow(entry.queuedAt, { addSuffix: true })}
                </span>
                {rt ? (
                  <button
                    onClick={() => onRemove(entry, rt)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '3px',
                      padding: '1px 7px',
                      background: 'none',
                      border: '1px solid rgba(255,58,76,0.3)',
                      color: 'var(--dm-red)',
                      fontSize: '0.62rem',
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                      flexShrink: 0,
                      letterSpacing: '0.04em',
                      transition: 'border-color 0.1s',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--dm-red)')}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = 'rgba(255,58,76,0.3)')}
                  >
                    <Trash2 size={9} /> Remove
                  </button>
                ) : (
                  <button
                    onClick={() => onDismiss(entry.id)}
                    style={{
                      padding: '1px 7px',
                      background: 'none',
                      border: '1px solid var(--dm-border)',
                      color: 'var(--dm-text-lo)',
                      fontSize: '0.62rem',
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                      flexShrink: 0,
                      transition: 'color 0.1s',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
                    onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-lo)')}
                  >
                    Dismiss
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
