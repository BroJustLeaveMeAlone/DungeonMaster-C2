import { useState } from 'react'
import { Download, X, ChevronDown, ChevronUp } from 'lucide-react'

export type RichContent =
  | { kind: 'image';    data: Uint8Array; label: string }
  | { kind: 'table';    rows: string[][];  headers: string[]; label: string }
  | { kind: 'json';     text: string;      label: string }
  | { kind: 'binary';   data: Uint8Array;  label: string }

export function detectOutputType(bytes: Uint8Array, label: string): RichContent | null {
  if (bytes.length === 0) return null

  // BMP magic
  if (bytes[0] === 0x42 && bytes[1] === 0x4d) {
    return { kind: 'image', data: bytes, label }
  }

  // PNG magic
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return { kind: 'image', data: bytes, label }
  }

  const text = tryDecodeUtf8(bytes)
  if (!text) {
    return { kind: 'binary', data: bytes, label }
  }

  // JSON
  const trimmed = text.trimStart()
  if (trimmed[0] === '{' || trimmed[0] === '[') {
    try {
      JSON.parse(text)
      return { kind: 'json', text, label }
    } catch { /* fall through */ }
  }

  // TSV: must have tabs AND consistent column count across ≥2 rows
  const lines = text.split('\n').filter(l => l.trim())
  if (lines.length >= 2 && lines[0].includes('\t')) {
    const cols = lines[0].split('\t').length
    const consistent = lines.slice(1).every(l => l.split('\t').length === cols)
    if (consistent) {
      const headers = lines[0].split('\t')
      const rows    = lines.slice(1).map(l => l.split('\t'))
      return { kind: 'table', headers, rows, label }
    }
  }

  return null
}

function tryDecodeUtf8(bytes: Uint8Array): string | null {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    return text
  } catch {
    return null
  }
}

// ── Renderers ─────────────────────────────────────────────────────────────────

function ImageViewer({ item }: { item: Extract<RichContent, { kind: 'image' }> }) {
  const mime = item.data[0] === 0x89 ? 'image/png' : 'image/bmp'
  const url  = URL.createObjectURL(new Blob([item.data.buffer as ArrayBuffer], { type: mime }))
  return (
    <img
      src={url}
      alt={item.label}
      style={{ maxWidth: '100%', maxHeight: '400px', objectFit: 'contain', display: 'block' }}
      onLoad={() => URL.revokeObjectURL(url)}
    />
  )
}

function TableViewer({ item }: { item: Extract<RichContent, { kind: 'table' }> }) {
  return (
    <div style={{ overflowX: 'auto', maxHeight: '340px', overflowY: 'auto' }}>
      <table style={{ borderCollapse: 'collapse', fontSize: '0.72rem', whiteSpace: 'nowrap', width: '100%' }}>
        <thead>
          <tr>
            {item.headers.map((h, i) => (
              <th key={i} style={{
                padding: '4px 10px',
                background: 'var(--dm-surface)',
                color: 'var(--dm-text-mid)',
                textAlign: 'left',
                fontWeight: 600,
                borderBottom: '1px solid var(--dm-border)',
                position: 'sticky',
                top: 0,
                letterSpacing: '0.04em',
                fontSize: '0.68rem',
              }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {item.rows.map((row, ri) => (
            <tr key={ri} style={{ background: ri % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)' }}>
              {row.map((cell, ci) => (
                <td key={ci} style={{
                  padding: '3px 10px',
                  color: 'var(--dm-text-lo)',
                  borderBottom: '1px solid rgba(255,255,255,0.04)',
                  fontFamily: 'Consolas, monospace',
                }}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function JsonViewer({ item }: { item: Extract<RichContent, { kind: 'json' }> }) {
  const pretty = (() => {
    try { return JSON.stringify(JSON.parse(item.text), null, 2) }
    catch { return item.text }
  })()
  return (
    <pre style={{
      margin: 0,
      padding: '0.5rem',
      fontSize: '0.72rem',
      color: 'var(--dm-text-lo)',
      fontFamily: 'Consolas, monospace',
      overflowX: 'auto',
      maxHeight: '340px',
      overflowY: 'auto',
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-word',
    }}>
      {pretty}
    </pre>
  )
}

function BinaryViewer({ item }: { item: Extract<RichContent, { kind: 'binary' }> }) {
  function download() {
    const url = URL.createObjectURL(new Blob([item.data.buffer as ArrayBuffer]))
    const a   = document.createElement('a')
    a.href     = url
    a.download = item.label || 'output.bin'
    a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <div className="flex flex-col gap-2 p-3">
      <span style={{ fontSize: '0.72rem', color: 'var(--dm-text-lo)' }}>
        Binary output — {item.data.length.toLocaleString()} bytes
      </span>
      <button className="dm-action dm-go" style={{ alignSelf: 'flex-start' }} onClick={download}>
        <Download size={12} style={{ display: 'inline', marginRight: 4 }} />
        Download
      </button>
    </div>
  )
}

// ── Panel ─────────────────────────────────────────────────────────────────────

interface RichOutputPanelProps {
  items:    RichContent[]
  onClose:  () => void
}

export function RichOutputPanel({ items, onClose }: RichOutputPanelProps) {
  const [activeIdx, setActiveIdx] = useState(items.length - 1)
  const [collapsed, setCollapsed] = useState(false)

  if (items.length === 0) return null

  const item = items[activeIdx] ?? items[items.length - 1]

  return (
    <div
      style={{
        width: '360px',
        minWidth: '280px',
        maxWidth: '480px',
        borderLeft: '1px solid var(--dm-border)',
        background: 'var(--dm-surface)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between flex-shrink-0 px-3 py-1"
        style={{ borderBottom: '1px solid var(--dm-border)', minHeight: '34px' }}
      >
        <div className="flex items-center gap-2">
          <span style={{ fontSize: '0.7rem', color: 'var(--dm-text-lo)', letterSpacing: '0.06em' }}>
            OUTPUT
          </span>
          {items.length > 1 && (
            <div className="flex gap-1">
              {items.map((_, i) => (
                <button
                  key={i}
                  onClick={() => setActiveIdx(i)}
                  style={{
                    width: 18, height: 18,
                    background: i === activeIdx ? 'var(--dm-accent)' : 'var(--dm-border)',
                    border: 'none',
                    cursor: 'pointer',
                    fontSize: '0.6rem',
                    color: i === activeIdx ? '#fff' : 'var(--dm-text-lo)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    borderRadius: 0,
                  }}
                >
                  {i + 1}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setCollapsed(c => !c)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--dm-text-lo)', padding: '2px' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-lo)')}
          >
            {collapsed ? <ChevronDown size={12} /> : <ChevronUp size={12} />}
          </button>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--dm-text-lo)', padding: '2px' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-lo)')}
          >
            <X size={12} />
          </button>
        </div>
      </div>

      {!collapsed && (
        <>
          {/* Label */}
          <div
            style={{
              padding: '4px 12px',
              borderBottom: '1px solid var(--dm-border)',
              fontSize: '0.68rem',
              color: 'var(--dm-text-lo)',
              fontFamily: 'Consolas, monospace',
              flexShrink: 0,
            }}
          >
            {item.label}
            <span
              style={{
                marginLeft: 8,
                padding: '1px 5px',
                background: 'var(--dm-border)',
                fontSize: '0.6rem',
                color: 'var(--dm-text-lo)',
                letterSpacing: '0.04em',
              }}
            >
              {item.kind.toUpperCase()}
            </span>
          </div>

          {/* Content */}
          <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
            {item.kind === 'image'  && <ImageViewer  item={item} />}
            {item.kind === 'table'  && <TableViewer  item={item} />}
            {item.kind === 'json'   && <JsonViewer   item={item} />}
            {item.kind === 'binary' && <BinaryViewer item={item} />}
          </div>
        </>
      )}
    </div>
  )
}
