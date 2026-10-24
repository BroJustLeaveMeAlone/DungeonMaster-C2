import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { api, campaignEventSource } from '../api/client'

interface Session {
  id:          string
  hostname:    string
  username:    string
  os:          string
  is_alive:    boolean
  is_elevated: boolean
  last_seen:   string
}

interface Campaign {
  id:            string
  name:          string
  client_name:   string
  objective:     string
  scope_cidrs:   string[]
  scope_domains: string[]
  is_active:     boolean
}

interface BusEvent {
  id:           string
  type:         string
  session_id?:  string
  operator_id?: string
  payload?:     unknown
  occurred_at:  string
}

const EVENT_COLORS: Record<string, string> = {
  SESSION_CHECKIN:  'var(--dm-accent)',
  SESSION_REVOKED:  'var(--dm-red)',
  TASK_QUEUED:      'var(--dm-blue)',
  TASK_OUTPUT:      'var(--dm-text-hi)',
  EVASION_DETECTED: 'var(--dm-amber)',
  BUILD_COMPLETE:   'var(--dm-purple)',
  OPERATOR_JOINED:  'var(--dm-text-mid)',
  OPERATOR_LEFT:    'var(--dm-text-mid)',
}

function relTime(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export function CampaignPage() {
  const { id: campaignId } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [events, setEvents] = useState<BusEvent[]>([])
  const [eventFilter, setEventFilter] = useState('')
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const [svgWidth, setSvgWidth] = useState(800)
  const [hoveredId, setHoveredId] = useState<string | null>(null)
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 })
  const bottomRef = useRef<HTMLDivElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const userScrolled = useRef(false)
  const graphRef = useRef<HTMLDivElement>(null)

  const { data: campaign } = useQuery<Campaign>({
    queryKey: ['campaign', campaignId],
    queryFn:  () => api.get(`/api/v1/campaigns/${campaignId}`).then(r => r.data),
    enabled:  !!campaignId,
  })

  const { data: sessions = [], refetch: refetchSessions } = useQuery<Session[]>({
    queryKey:        ['sessions', campaignId],
    queryFn:         () => api.get(`/api/v1/sessions?campaign_id=${campaignId}`).then(r => r.data),
    refetchInterval: 15_000,
    enabled:         !!campaignId,
  })

  useEffect(() => {
    if (!campaignId) return
    let closed = false
    let es: EventSource
    let retryTimer: ReturnType<typeof setTimeout>
    let retryDelay = 1000

    function connect() {
      if (closed) return
      es = campaignEventSource(campaignId!)
      es.onmessage = (e) => {
        retryDelay = 1000
        const ev: BusEvent = JSON.parse(e.data)
        setEvents(prev => [...prev.slice(-299), ev])
        if (ev.type === 'SESSION_CHECKIN') void refetchSessions()
      }
      es.onerror = () => {
        es.close()
        if (!closed) {
          retryTimer = setTimeout(connect, retryDelay)
          retryDelay = Math.min(retryDelay * 2, 30_000)
        }
      }
    }

    connect()
    return () => {
      closed = true
      clearTimeout(retryTimer)
      es?.close()
    }
  }, [campaignId])

  useEffect(() => {
    if (!userScrolled.current) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events])

  useEffect(() => {
    const el = graphRef.current
    if (!el) return
    const obs = new ResizeObserver(entries => {
      for (const entry of entries) {
        setSvgWidth(entry.contentRect.width)
      }
    })
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  const toggleExpanded = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  if (!campaign || !campaignId) return null

  const aliveSessions = sessions.filter(s => s.is_alive)
  const filteredEvents = eventFilter ? events.filter(ev => ev.type === eventFilter) : events
  const n = sessions.length
  const hoveredSession = hoveredId ? sessions.find(s => s.id === hoveredId) : null

  const c2x = svgWidth * 0.15
  const c2y = 110
  const hd = 14

  return (
    <div className="min-h-screen flex flex-col" style={{ background: 'var(--dm-bg)' }}>

      {/* Header */}
      <div
        className="flex items-center gap-4 px-6 py-2.5 flex-wrap"
        style={{ borderBottom: '1px solid var(--dm-border)', borderTop: '2px solid var(--dm-accent-lo)' }}
      >
        <Link
          to="/"
          style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem', textDecoration: 'none', flexShrink: 0, transition: 'color 0.1s' }}
          onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
          onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-lo)')}
        >
          ← dashboard
        </Link>
        <span style={{ color: 'var(--dm-text-lo)' }}>|</span>
        <span style={{ color: 'var(--dm-text-hi)', fontWeight: 700, fontSize: '0.88rem', letterSpacing: '0.04em' }}>
          {campaign.name}
        </span>
        <span style={{ color: 'var(--dm-text-mid)', fontSize: '0.78rem' }}>{campaign.client_name}</span>
        {campaign.objective && (
          <span
            className="hidden lg:block truncate ml-auto max-w-xs"
            style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem' }}
            title={campaign.objective}
          >
            {campaign.objective}
          </span>
        )}
      </div>

      {/* Scope bar */}
      {(campaign.scope_cidrs.length > 0 || campaign.scope_domains.length > 0) && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap',
          padding: '0.3rem 1.5rem',
          borderBottom: '1px solid var(--dm-border)',
          background: 'rgba(0,212,176,0.03)',
          fontSize: '0.68rem',
        }}>
          <span style={{ color: 'var(--dm-text-lo)', letterSpacing: '0.1em' }}>SCOPE</span>
          {campaign.scope_cidrs.map(cidr => (
            <span key={cidr} style={{ color: 'var(--dm-text-mid)' }}>{cidr}</span>
          ))}
          {campaign.scope_domains.map(domain => (
            <span key={domain} style={{ color: 'var(--dm-text-mid)' }}>[{domain}]</span>
          ))}
        </div>
      )}

      {/* Attack graph panel */}
      <div
        ref={graphRef}
        style={{
          background: 'var(--dm-surface)',
          borderBottom: '1px solid var(--dm-border)',
          overflow: 'hidden',
          height: '220px',
          position: 'relative',
        }}
      >
        {sessions.length === 0 ? (
          <svg width={svgWidth} height={220}>
            <text
              x={svgWidth / 2}
              y={115}
              textAnchor="middle"
              fill="var(--dm-text-lo)"
              fontSize="0.78rem"
            >
              No sessions yet
            </text>
          </svg>
        ) : (
          <svg width={svgWidth} height={220}>
            {sessions.map((s, i) => {
              const sx = svgWidth * 0.65
              const sy = n === 1 ? 110 : 20 + i * (180 / (n - 1))
              return (
                <line
                  key={`line-${s.id}`}
                  x1={c2x}
                  y1={c2y}
                  x2={sx}
                  y2={sy}
                  stroke={s.is_alive ? 'var(--dm-accent-lo)' : 'var(--dm-border)'}
                  strokeWidth={1}
                  strokeDasharray={s.is_alive ? undefined : '4 4'}
                />
              )
            })}

            <g>
              <polygon
                points={`${c2x},${c2y - hd} ${c2x + hd},${c2y} ${c2x},${c2y + hd} ${c2x - hd},${c2y}`}
                fill="var(--dm-accent)"
              />
              <text x={c2x} y={c2y + hd + 12} textAnchor="middle" fill="var(--dm-accent)" fontSize="0.6rem">
                C2
              </text>
            </g>

            {sessions.map((s, i) => {
              const sx = svgWidth * 0.65
              const sy = n === 1 ? 110 : 20 + i * (180 / (n - 1))
              return (
                <g
                  key={s.id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/campaigns/${campaignId}/sessions/${s.id}`)}
                  onMouseEnter={() => setHoveredId(s.id)}
                  onMouseMove={e => setTooltipPos({ x: e.clientX, y: e.clientY })}
                  onMouseLeave={() => setHoveredId(null)}
                >
                  {s.is_elevated && (
                    <circle
                      cx={sx}
                      cy={sy}
                      r={14}
                      fill="none"
                      stroke="var(--dm-red)"
                      strokeWidth={1.5}
                    />
                  )}
                  <circle
                    cx={sx}
                    cy={sy}
                    r={10}
                    fill={s.is_alive ? 'var(--dm-accent)' : '#2c4258'}
                  >
                    {s.is_alive && (
                      <animate attributeName="r" values="10;12;10" dur="2s" repeatCount="indefinite" />
                    )}
                  </circle>
                  <text x={sx} y={sy + 24} textAnchor="middle" fill="var(--dm-text-hi)" fontSize="0.65rem">
                    {s.hostname}
                  </text>
                  <text x={sx} y={sy + 35} textAnchor="middle" fill="var(--dm-text-lo)" fontSize="0.55rem">
                    {s.username}
                  </text>
                </g>
              )
            })}
          </svg>
        )}

        {hoveredSession && (
          <div style={{
            position: 'fixed',
            left: tooltipPos.x + 12,
            top: tooltipPos.y + 12,
            background: 'var(--dm-surface)',
            border: '1px solid var(--dm-border)',
            color: 'var(--dm-text-hi)',
            fontSize: '0.7rem',
            padding: '0.4rem 0.6rem',
            pointerEvents: 'none',
            zIndex: 100,
          }}>
            <div style={{ fontWeight: 600 }}>{hoveredSession.hostname}</div>
            <div style={{ color: 'var(--dm-text-mid)' }}>{hoveredSession.username}</div>
            <div style={{ color: 'var(--dm-text-lo)' }}>{hoveredSession.os}</div>
            <div style={{ color: 'var(--dm-text-lo)', marginTop: '0.2rem' }}>{relTime(hoveredSession.last_seen)}</div>
          </div>
        )}
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* Sessions list */}
        <div className="flex-1 overflow-y-auto p-6">
          <div className="dm-section mb-4">
            Sessions&nbsp;
            <span style={{ color: 'var(--dm-accent)', fontWeight: 600 }}>{aliveSessions.length} alive</span>
            &nbsp;/&nbsp;{sessions.length} total
          </div>

          {sessions.length === 0 ? (
            <p style={{ color: 'var(--dm-text-lo)', fontSize: '0.78rem' }}>
              No sessions yet. Deploy an agent with campaign_id&nbsp;
              <code style={{ color: 'var(--dm-text-mid)' }}>{campaignId}</code>.
            </p>
          ) : (
            <div className="space-y-1.5">
              {sessions.map(s => (
                <Link
                  key={s.id}
                  to={`/campaigns/${campaignId}/sessions/${s.id}`}
                  className="dm-card flex items-center gap-3"
                  style={{ padding: '0.65rem 1rem' }}
                >
                  <span
                    className={s.is_alive ? 'dm-alive' : undefined}
                    style={{
                      width: '6px', height: '6px',
                      borderRadius: '50%',
                      flexShrink: 0,
                      background: s.is_alive ? 'var(--dm-accent)' : 'var(--dm-text-lo)',
                    }}
                  />
                  <span style={{ color: 'var(--dm-text-hi)', fontWeight: 600, fontSize: '0.82rem', flexShrink: 0 }}>
                    {s.hostname}
                  </span>
                  <span style={{ color: 'var(--dm-text-mid)', fontSize: '0.78rem', flexShrink: 0 }}>
                    {s.username}
                  </span>
                  {s.is_elevated && (
                    <span className="dm-badge" style={{ color: 'var(--dm-red)', borderColor: 'rgba(255,58,76,0.3)' }}>
                      SYSTEM
                    </span>
                  )}
                  <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem', flexShrink: 0 }}>{s.os}</span>
                  <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.68rem', marginLeft: 'auto', flexShrink: 0 }}>
                    {new Date(s.last_seen).toLocaleTimeString()}
                  </span>
                  <span style={{ color: 'var(--dm-accent-lo)', fontSize: '0.72rem', flexShrink: 0 }}>→</span>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Event feed */}
        <div
          className="flex flex-col flex-shrink-0 overflow-hidden"
          style={{ width: '300px', borderLeft: '1px solid var(--dm-border)' }}
        >
          <div
            className="flex items-center px-4 py-2.5 gap-2"
            style={{ borderBottom: '1px solid var(--dm-border)', flexShrink: 0 }}
          >
            <span className="dm-section" style={{ flex: 1 }}>
              Events{' '}
              <span style={{ color: 'var(--dm-text-lo)', fontWeight: 400 }}>({events.length})</span>
            </span>
            <button
              className="dm-action dm-danger"
              style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem' }}
              onClick={() => setEvents([])}
            >
              CLR
            </button>
          </div>

          <div style={{ padding: '0.4rem 0.75rem', flexShrink: 0, borderBottom: '1px solid var(--dm-border)' }}>
            <select
              className="dm-input"
              style={{ width: '100%', fontSize: '0.68rem' }}
              value={eventFilter}
              onChange={e => setEventFilter(e.target.value)}
            >
              <option value="">All</option>
              <option value="SESSION_CHECKIN">SESSION_CHECKIN</option>
              <option value="TASK_QUEUED">TASK_QUEUED</option>
              <option value="TASK_OUTPUT">TASK_OUTPUT</option>
              <option value="SESSION_REVOKED">SESSION_REVOKED</option>
              <option value="EVASION_DETECTED">EVASION_DETECTED</option>
              <option value="BUILD_COMPLETE">BUILD_COMPLETE</option>
              <option value="OPERATOR_JOINED">OPERATOR_JOINED</option>
              <option value="OPERATOR_LEFT">OPERATOR_LEFT</option>
            </select>
          </div>

          <div
            ref={scrollRef}
            className="flex-1 overflow-y-auto p-3"
            style={{ minHeight: 0 }}
            onScroll={() => {
              const el = scrollRef.current
              if (!el) return
              userScrolled.current = el.scrollTop + el.clientHeight < el.scrollHeight - 50
            }}
          >
            {filteredEvents.length === 0 && (
              <p style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem', paddingTop: '0.5rem' }}>
                {events.length === 0 ? 'Waiting for events…' : 'No events match filter.'}
              </p>
            )}
            {filteredEvents.map(ev => (
              <div key={ev.id} style={{ fontSize: '0.72rem', lineHeight: '1.6', padding: '0.1rem 0' }}>
                <span style={{ color: 'var(--dm-text-lo)' }}>
                  {new Date(ev.occurred_at).toLocaleTimeString()}&nbsp;
                </span>
                <span style={{ color: EVENT_COLORS[ev.type] ?? 'var(--dm-text-mid)' }}>
                  {ev.type}
                </span>
                {ev.session_id && (
                  <span style={{ color: 'var(--dm-text-lo)' }}>&nbsp;{ev.session_id.slice(0, 8)}</span>
                )}
                {ev.type === 'TASK_OUTPUT' && ev.payload != null && (
                  <div style={{ paddingLeft: '0.5rem', marginTop: '0.1rem' }}>
                    <span
                      style={{ color: 'var(--dm-text-lo)', cursor: 'pointer', userSelect: 'none' }}
                      onClick={() => toggleExpanded(ev.id)}
                    >
                      {(() => {
                        const raw = JSON.stringify(ev.payload)
                        return expandedIds.has(ev.id)
                          ? raw
                          : `${raw.slice(0, 60)}${raw.length > 60 ? '…' : ''}`
                      })()}
                      {' '}
                      <span style={{ color: 'var(--dm-accent-lo)' }}>
                        {expandedIds.has(ev.id) ? '[-]' : '[+]'}
                      </span>
                    </span>
                  </div>
                )}
              </div>
            ))}
            <div ref={bottomRef} />
          </div>
        </div>
      </div>
    </div>
  )
}
