import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

export function LureGenPage() {
  const [serviceUp, setServiceUp] = useState<boolean | null>(null)

  useEffect(() => {
    fetch('/lure/', { method: 'HEAD', signal: AbortSignal.timeout(3000) })
      .then(() => setServiceUp(true))
      .catch(() => setServiceUp(false))
  }, [])

  return (
    <div className="min-h-screen flex flex-col" style={{ background: 'var(--dm-bg)' }}>

      {/* Nav */}
      <nav style={{ borderBottom: '1px solid var(--dm-border)', borderTop: '2px solid var(--dm-accent-lo)' }}>
        <div className="flex items-center justify-between px-6 py-2.5">
          <Link to="/" style={{ color: 'var(--dm-accent)', fontWeight: 700, fontSize: '0.82rem', letterSpacing: '0.3em', textDecoration: 'none' }}>
            DUNGEONMASTER
          </Link>
          <div className="flex items-center gap-5">
            <Link
              to="/builds"
              style={{ color: 'var(--dm-text-mid)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none', transition: 'color 0.1s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
            >
              Builds
            </Link>
            <Link
              to="/vault"
              style={{ color: 'var(--dm-text-mid)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none', transition: 'color 0.1s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
            >
              Vault
            </Link>
            <Link
              to="/manual"
              style={{ color: 'var(--dm-text-mid)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none', transition: 'color 0.1s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-mid)')}
            >
              Manual
            </Link>
            <Link
              to="/lure-gen"
              style={{ color: 'var(--dm-accent)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none' }}
            >
              Lure Gen
            </Link>
          </div>
        </div>
      </nav>

      <div className="flex-1 flex flex-col" style={{ minHeight: 0 }}>
        {serviceUp === false ? (
          <div
            className="flex-1 flex items-center justify-center"
            style={{ color: 'var(--dm-text-lo)', fontSize: '0.82rem', textAlign: 'center', padding: '3rem' }}
          >
            <div>
              <div style={{ color: 'var(--dm-text-mid)', marginBottom: '0.75rem', fontSize: '0.9rem' }}>
                Lure Gen service not reachable
              </div>
              <code style={{ color: 'var(--dm-text-hi)', fontSize: '0.75rem' }}>
                uvicorn main:app --host 0.0.0.0 --port 8000
              </code>
              <div style={{ marginTop: '1rem' }}>
                <button
                  className="dm-action dm-go"
                  onClick={() => {
                    setServiceUp(null)
                    fetch('/lure/', { method: 'HEAD', signal: AbortSignal.timeout(3000) })
                      .then(() => setServiceUp(true))
                      .catch(() => setServiceUp(false))
                  }}
                >
                  Retry
                </button>
              </div>
            </div>
          </div>
        ) : (
          <iframe
            src="/lure/"
            style={{
              flex: 1,
              width: '100%',
              border: 'none',
              minHeight: 'calc(100vh - 44px)',
            }}
            title="Lure Generator"
          />
        )}
      </div>
    </div>
  )
}
