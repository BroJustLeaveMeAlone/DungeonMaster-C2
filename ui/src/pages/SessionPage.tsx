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
    queryKey:        ['session', sessionId],
    queryFn:         () => api.get(`/api/v1/sessions/${sessionId}`).then(r => r.data),
    refetchInterval: 15_000,
    enabled:         !!sessionId,
  })

  const revoke = useMutation({
    mutationFn: (reason: string) =>
      api.post(`/api/v1/sessions/${sessionId}/revoke`, { reason }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['session', sessionId] }),
  })

  if (!session || !sessionId) return null

  const hasDetections = session.edr_detected.length > 0 || session.av_detected.length > 0

  return (
    <div className="h-screen flex flex-col overflow-hidden" style={{ background: 'var(--dm-bg)' }}>

      {/* Header bar */}
      <div
        className="flex items-center gap-3 px-4 py-2 flex-wrap flex-shrink-0"
        style={{
          borderBottom: '1px solid var(--dm-border)',
          borderTop: '2px solid var(--dm-accent-lo)',
          minHeight: '38px',
        }}
      >
        <Link
          to={campaignId ? `/campaigns/${campaignId}` : '/'}
          style={{ color: 'var(--dm-text-lo)', fontSize: '0.7rem', textDecoration: 'none', flexShrink: 0, transition: 'color 0.1s' }}
          onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
          onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-lo)')}
        >
          ←
        </Link>

        <span
          className={session.is_alive ? 'dm-alive' : undefined}
          style={{
            width: '7px', height: '7px',
            borderRadius: '50%',
            flexShrink: 0,
            background: session.is_alive ? 'var(--dm-accent)' : 'var(--dm-text-lo)',
          }}
        />

        <span style={{ color: 'var(--dm-text-hi)', fontWeight: 700, fontSize: '0.84rem', flexShrink: 0 }}>
          {session.hostname}
        </span>

        <span style={{ color: 'var(--dm-text-mid)', fontSize: '0.78rem', flexShrink: 0 }}>
          {session.username}{session.domain ? '@' + session.domain : ''}
        </span>

        {session.is_elevated && (
          <span className="dm-badge" style={{ color: 'var(--dm-red)', borderColor: 'rgba(255,58,76,0.35)' }}>
            SYSTEM
          </span>
        )}
        {session.is_revoked && (
          <span className="dm-badge" style={{ color: 'var(--dm-amber)', borderColor: 'rgba(255,183,48,0.35)' }}>
            REVOKED
          </span>
        )}

        <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.7rem', flexShrink: 0 }}>
          {session.os}&nbsp;{session.arch}&nbsp;{session.os_version}
        </span>

        <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.7rem', marginLeft: 'auto', flexShrink: 0 }}>
          {session.active_channel} · {session.sleep_seconds}s ±{session.jitter_pct}%
        </span>

        {!session.is_revoked && (
          <button
            className="dm-action dm-danger"
            style={{ fontSize: '0.68rem', letterSpacing: '0.06em' }}
            onClick={() => {
              if (confirm('Revoke this session? The agent will self-destruct on next check-in.')) {
                revoke.mutate('operator-revoked')
              }
            }}
          >
            Revoke
          </button>
        )}
      </div>

      {/* EDR / AV warning */}
      {hasDetections && (
        <div
          className="flex items-center gap-4 px-4 py-1.5 flex-shrink-0"
          style={{
            background: 'var(--dm-amber-bg)',
            borderBottom: '1px solid rgba(255,183,48,0.2)',
            fontSize: '0.72rem',
          }}
        >
          <span style={{ color: 'var(--dm-amber)', fontWeight: 600, letterSpacing: '0.08em', fontSize: '0.6rem' }}>
            ⚠ DETECTION
          </span>
          {session.edr_detected.length > 0 && (
            <span style={{ color: 'var(--dm-amber)' }}>
              EDR: {session.edr_detected.join(', ')}
            </span>
          )}
          {session.av_detected.length > 0 && (
            <span style={{ color: 'var(--dm-amber)' }}>
              AV: {session.av_detected.join(', ')}
            </span>
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
      <div className="flex-1 min-h-0 p-3">
        <SessionConsole sessionId={sessionId!} campaignId={campaignId} />
      </div>
    </div>
  )
}
