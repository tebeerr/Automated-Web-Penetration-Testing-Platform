import { useState, type ComponentType } from 'react'
import type { PageId } from '../types'

interface NavEntry {
  id: PageId
  label: string
  icon: ComponentType
}

const NAV: NavEntry[] = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon },
  { id: 'scan', label: 'Scan New Target', icon: ScanIcon },
  { id: 'history', label: 'History', icon: HistoryIcon },
  { id: 'reports', label: 'Report Archive', icon: ReportIcon },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
]

interface SidebarProps {
  active: PageId
  onNavigate: (id: PageId) => void
}

export default function Sidebar({ active, onNavigate }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-head">
        <div className="brand">
          <div className="brand-mark">
            <span className="brand-dot" />
          </div>
          {!collapsed && (
            <div className="brand-text">
              <div className="brand-name">SENTINEL</div>
              <div className="brand-sub">PenTest Suite</div>
            </div>
          )}
        </div>
        <button
          className="collapse-btn"
          onClick={() => setCollapsed((c) => !c)}
          aria-label="Toggle sidebar"
        >
          <ChevronIcon flipped={collapsed} />
        </button>
      </div>

      <nav className="nav">
        {NAV.map(({ id, label, icon: Icon }) => {
          const isActive = active === id
          return (
            <button
              key={id}
              className={`nav-item ${isActive ? 'active' : ''}`}
              onClick={() => onNavigate(id)}
              title={collapsed ? label : undefined}
            >
              <span className="nav-icon">
                <Icon />
              </span>
              {!collapsed && <span className="nav-label">{label}</span>}
              {isActive && <span className="nav-indicator" />}
            </button>
          )
        })}
      </nav>

      <div className="sidebar-foot">
        <div className="status-pill">
          <span className="pulse" />
          {!collapsed && <span>Engine online</span>}
        </div>
      </div>
    </aside>
  )
}

function DashboardIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </svg>
  )
}

function ScanIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="7" />
      <line x1="21" y1="21" x2="16.5" y2="16.5" />
      <line x1="11" y1="8" x2="11" y2="14" />
      <line x1="8" y1="11" x2="14" y2="11" />
    </svg>
  )
}

function HistoryIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
      <path d="M3 3v5h5" />
      <path d="M12 7v5l3 2" />
    </svg>
  )
}

function ReportIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="8" y1="13" x2="16" y2="13" />
      <line x1="8" y1="17" x2="13" y2="17" />
    </svg>
  )
}

function SettingsIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </svg>
  )
}

function ChevronIcon({ flipped }: { flipped: boolean }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ transform: flipped ? 'rotate(180deg)' : 'none', transition: 'transform 0.25s' }}
    >
      <polyline points="15 18 9 12 15 6" />
    </svg>
  )
}
