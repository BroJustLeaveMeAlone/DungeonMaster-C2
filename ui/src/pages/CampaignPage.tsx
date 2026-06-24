import { useParams, Link } from 'react-router-dom'
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

export function CampaignPage() {
  const { id: campaignId } = useParams<{ id: string }>()
  const [events, setEvents] = useState<BusEvent[]>([])
  const bottomRef = useRef<HTMLDivElement>(null)

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
    const es = campaignEventSource(campaignId)
    es.onmessage = (e) => {
      const ev: BusEvent = JSON.parse(e.data)
      setEvents(prev => [...prev.slice(-299), ev])
      if (ev.type === 'SESSION_CHECKIN') void refetchSessions()
    }
    es.onerror = () => es.close()
    return () => es.close()
  }, [campaignId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events])

  if (!campaign || !campaignId) return null

  const aliveSessions = sessions.filter(s => s.is_alive)

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
            className="flex items-center px-4 py-2.5"
            style={{ borderBottom: '1px solid var(--dm-border)', flexShrink: 0 }}
          >
            <span className="dm-section" style={{ flex: 1 }}>Event Feed</span>
          </div>

          <div className="flex-1 overflow-y-auto p-3" style={{ minHeight: 0 }}>
            {events.length === 0 && (
              <p style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem', paddingTop: '0.5rem' }}>
                Waiting for events…
              </p>
            )}
            {events.map(ev => (
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
              </div>
            ))}
            <div ref={bottomRef} />
          </div>
        </div>
      </div>
    </div>
  )
}
