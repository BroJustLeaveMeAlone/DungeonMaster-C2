import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Link } from 'react-router-dom'
import type { Components } from 'react-markdown'
import content from '../../../USER-MANUAL.md?raw'

function slugify(text: string): string {
  return String(text)
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/ /g, '-')
}

function heading(level: 1 | 2 | 3 | 4 | 5 | 6): Components['h1'] {
  const Tag = `h${level}` as 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6'
  return function H({ children }) {
    const text = typeof children === 'string' ? children
      : Array.isArray(children) ? children.map(c => (typeof c === 'string' ? c : '')).join('') : ''
    const id = slugify(text)
    return <Tag id={id} style={{ scrollMarginTop: '48px' }}>{children}</Tag>
  }
}

const MD_COMPONENTS: Components = {
  h1: heading(1), h2: heading(2), h3: heading(3),
  h4: heading(4), h5: heading(5), h6: heading(6),
}

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
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={MD_COMPONENTS}>
            {content}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  )
}
