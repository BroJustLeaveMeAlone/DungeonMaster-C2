import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Link } from 'react-router-dom'
import content from '../../../USER-MANUAL.md?raw'

export function ManualPage() {
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
              to="/manual"
              style={{ color: 'var(--dm-accent)', fontSize: '0.72rem', letterSpacing: '0.08em', textDecoration: 'none' }}
            >
              Manual
            </Link>
          </div>
        </div>
      </nav>

      <div className="flex-1 px-8 py-8 max-w-5xl mx-auto w-full">
        <div className="dm-manual-body">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {content}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  )
}
