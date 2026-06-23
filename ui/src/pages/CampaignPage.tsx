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
  id:          string
  type:        string
  session_id?: string
  operator_id?:string
  payload?:    unknown
  occurred_at: string
}

const EVENT_COLORS: Record<string, string> = {
  SESSION_CHECKIN:   '#3fb950',
  SESSION_REVOKED:   '#f85149',
  TASK_QUEUED:       '#58a6ff',
  TASK_OUTPUT:       '#c9d1d9',
  EVASION_DETECTED:  '#d29922',
  BUILD_COMPLETE:    '#bc8cff',
  OPERATOR_JOINED:   '#484f58',
  OPERATOR_LEFT:     '#484f58',
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
    queryKey:       ['sessions', campaignId],
    queryFn:        () => api.get(`/api/v1/sessions?campaign_id=${campaignId}`).then(r => r.data),
    refetchInterval: 15_000,
    enabled:        !!campaignId,
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
    <div className="min-h-screen flex flex-col" style={{ background: '#0d1117' }}>
      {/* Header */}
      <div className="border-b border-gray-800 px-6 py-3 flex items-center gap-4">
        <Link to="/" className="text-gray-600 hover:text-gray-300 text-xs font-mono transition-colors">
          ← dashboard
        </Link>
        <h1 className="font-mono font-bold text-white">{campaign.name}</h1>
        <span className="text-gray-500 text-sm">{campaign.client_name}</span>
        <span className="text-gray-700 text-xs ml-auto hidden lg:block truncate max-w-xs">
          {campaign.objective}
        </span>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* Session list */}
        <div className="flex-1 p-6 overflow-y-auto">
          <h2 className="text-xs text-gray-600 uppercase tracking-widest mb-3">
            Sessions{' '}
            <span style={{ color: '#3fb950' }}>{aliveSessions.length} alive</span>
            {' '}/ {sessions.length} total
          </h2>

          <div className="space-y-2">
            {sessions.map(s => (
              <Link
                key={s.id}
                to={`/campaigns/${campaignId}/sessions/${s.id}`}
                className="flex items-center gap-3 border border-gray-800 rounded-lg px-4 py-3 font-mono hover:border-green-900 transition-colors"
                style={{ background: '#161b22' }}
              >
                <span
                  className="h-2 w-2 rounded-full flex-shrink-0"
                  style={{ background: s.is_alive ? '#3fb950' : '#484f58' }}
                />
                <span className="text-white font-bold text-sm flex-shrink-0">{s.hostname}</span>
                <span className="text-gray-400 text-sm">{s.username}</span>
                {s.is_elevated && (
                  <span className="text-xs border border-red-900 rounded px-1 flex-shrink-0" style={{ color: '#f85149' }}>
                    ELEV
                  </span>
                )}
                <span className="text-gray-600 text-xs flex-shrink-0">{s.os}</span>
                <span className="text-gray-700 text-xs ml-auto flex-shrink-0">
                  {new Date(s.last_seen).toLocaleTimeString()}
                </span>
                <span className="text-xs ml-2 flex-shrink-0" style={{ color: '#3fb950' }}>→</span>
              </Link>
            ))}

            {sessions.length === 0 && (
              <p className="text-gray-700 text-sm py-4">
                No sessions yet. Deploy an agent with campaign_id{' '}
                <code className="text-gray-500 font-mono text-xs">{campaignId}</code>.
              </p>
            )}
          </div>
        </div>

        {/* Event feed */}
        <div
          className="w-80 border-l border-gray-800 flex flex-col flex-shrink-0"
          style={{ background: '#0d1117' }}
        >
          <div className="px-4 py-2 border-b border-gray-800 text-xs text-gray-600 uppercase tracking-widest">
            Event Feed
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-1">
            {events.length === 0 && (
              <p className="text-gray-700 text-xs py-2">Waiting for events…</p>
            )}
            {events.map(ev => (
              <div key={ev.id} className="font-mono text-xs leading-relaxed">
                <span className="text-gray-700">
                  {new Date(ev.occurred_at).toLocaleTimeString()}{' '}
                </span>
                <span style={{ color: EVENT_COLORS[ev.type] ?? '#8b949e' }}>
                  {ev.type}
                </span>
                {ev.session_id && (
                  <span className="text-gray-700"> {ev.session_id.slice(0, 8)}</span>
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
