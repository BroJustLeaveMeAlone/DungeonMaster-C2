import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { SessionConsole } from '../components/session/SessionConsole'
import { SessionActions } from '../components/session/SessionActions'

interface Session {
  id:             string
  hostname:       string
  username:       string
  domain:         string
  os:             string
  arch:           string
  os_version:     string
  is_elevated:    boolean
  is_alive:       boolean
  is_revoked:     boolean
  active_channel: string
  sleep_seconds:  number
  jitter_pct:     number
  edr_detected:   string[]
  av_detected:    string[]
  last_seen:      string
}

export function SessionPage() {
  const { id: campaignId, sessionId: rawSessionId } = useParams<{ id?: string; sessionId?: string }>()
  const sessionId = rawSessionId
  const qc = useQueryClient()

  const { data: session } = useQuery<Session>({
    queryKey:       ['session', sessionId],
    queryFn:        () => api.get(`/api/v1/sessions/${sessionId}`).then(r => r.data),
    refetchInterval: 15_000,
    enabled:        !!sessionId,
  })

  const revoke = useMutation({
    mutationFn: (reason: string) =>
      api.post(`/api/v1/sessions/${sessionId}/revoke`, { reason }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['session', sessionId] }),
  })

  if (!session || !sessionId) return null

  const detectionBar = session.edr_detected.length > 0 || session.av_detected.length > 0

  return (
    <div className="h-screen flex flex-col overflow-hidden" style={{ background: '#0d1117' }}>
      {/* Top bar */}
      <div className="border-b border-gray-800 px-4 py-2 flex items-center gap-3 font-mono text-sm flex-wrap">
        <Link
          to={campaignId ? `/campaigns/${campaignId}` : '/'}
          className="text-gray-600 hover:text-gray-300 text-xs transition-colors"
        >
          ← back
        </Link>

        <span
          className="h-2 w-2 rounded-full flex-shrink-0"
          style={{ background: session.is_alive ? '#3fb950' : '#484f58' }}
        />
        <span className="text-white font-bold">{session.hostname}</span>
        <span className="text-gray-400">
          {session.username}{session.domain ? '@' + session.domain : ''}
        </span>

        {session.is_elevated && (
          <span className="text-xs border border-red-900 rounded px-1" style={{ color: '#f85149' }}>
            ELEVATED
          </span>
        )}
        {session.is_revoked && (
          <span className="text-xs border border-orange-900 rounded px-1 text-orange-400">
            REVOKED
          </span>
        )}

        <span className="text-gray-600 text-xs">{session.os} {session.arch} {session.os_version}</span>
        <span className="text-gray-600 text-xs ml-auto">
          {session.active_channel} · sleep {session.sleep_seconds}s ±{session.jitter_pct}%
        </span>

        {!session.is_revoked && (
          <button
            onClick={() => {
              if (confirm('Revoke this session? The agent will self-destruct on next check-in.')) {
                revoke.mutate('operator-revoked')
              }
            }}
            className="text-xs text-gray-600 hover:text-red-400 transition-colors ml-2"
          >
            revoke
          </button>
        )}
      </div>

      {/* EDR / AV warning */}
      {detectionBar && (
        <div className="px-4 py-1 border-b border-yellow-900 text-xs font-mono flex gap-4"
             style={{ background: '#1a1200' }}>
          {session.edr_detected.length > 0 && (
            <span className="text-yellow-400">EDR: {session.edr_detected.join(', ')}</span>
          )}
          {session.av_detected.length > 0 && (
            <span className="text-yellow-400">AV: {session.av_detected.join(', ')}</span>
          )}
        </div>
      )}

      {/* Action bar */}
      <SessionActions
        sessionId={sessionId!}
        sleepSeconds={session.sleep_seconds}
        jitterPct={session.jitter_pct}
        onSleepUpdated={() => qc.invalidateQueries({ queryKey: ['session', sessionId] })}
      />

      {/* Terminal */}
      <div className="flex-1 p-3 min-h-0">
        <SessionConsole sessionId={sessionId!} campaignId={campaignId} />
      </div>
    </div>
  )
}
