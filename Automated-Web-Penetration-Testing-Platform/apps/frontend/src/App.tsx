import { useState, type ReactElement } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './components/Dashboard'
import Placeholder from './components/pages/Placeholder'
import type { PageId } from './types'
import './App.css'

const PAGES: Record<PageId, () => ReactElement> = {
  dashboard: () => <Dashboard />,
  scan: () => (
    <Placeholder
      title="Scan New Target"
      subtitle="Configure scope, auth, and probes for a one-off engagement."
      hint="Wizard for target scope, credentialed auth, and OWASP module toggles will live here."
    />
  ),
  history: () => (
    <Placeholder
      title="History"
      subtitle="All past scans with filters, status, and re-run controls."
      hint="Timeline + table of historical scans will populate from the engine API."
    />
  ),
  reports: () => (
    <Placeholder
      title="Report Archive"
      subtitle="PDF / JSON / SARIF exports of completed engagements."
      hint="Generated reports will appear here, downloadable per-finding or per-scan."
    />
  ),
  settings: () => (
    <Placeholder
      title="Settings"
      subtitle="Engine config, API keys, notification channels, scan profiles."
      hint="Module preferences, integrations, and user account controls."
    />
  ),
}

export default function App() {
  const [active, setActive] = useState<PageId>('dashboard')
  const Render = PAGES[active]

  return (
    <div className="app-shell">
      <Sidebar active={active} onNavigate={setActive} />
      <main className="main">
        <TopBar />
        <div className="main-scroll">
          <Render />
        </div>
      </main>
    </div>
  )
}

function TopBar() {
  return (
    <header className="topbar">
      <div className="crumbs">
        <span className="crumb-dim">Sentinel</span>
        <span className="crumb-sep">/</span>
        <span>Workspace</span>
      </div>
      <div className="topbar-right">
        <div className="search">
          <SearchIcon />
          <input placeholder="Search scans, targets, CVEs…" />
          <kbd>⌘K</kbd>
        </div>
        <button className="icon-btn" aria-label="Notifications">
          <BellIcon />
          <span className="dot" />
        </button>
        <div className="avatar">RT</div>
      </div>
    </header>
  )
}

function SearchIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="7" />
      <line x1="21" y1="21" x2="16.5" y2="16.5" />
    </svg>
  )
}

function BellIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 16v-5a6 6 0 1 0-12 0v5l-2 2h16z" />
      <path d="M10 21a2 2 0 0 0 4 0" />
    </svg>
  )
}
