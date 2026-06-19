import ScanPanel from './ScanPanel'

const STATS = [
  { label: 'Scans (30d)', value: '142', delta: '+12%', tone: 'good' },
  { label: 'Critical findings', value: '7', delta: '-3', tone: 'good' },
  { label: 'Avg scan time', value: '4m 38s', delta: '-22s', tone: 'good' },
  { label: 'Targets monitored', value: '38', delta: '+4', tone: 'good' },
]

export default function Dashboard() {
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p className="page-sub">Run a new scan or review live engine telemetry.</p>
        </div>
      </div>

      <div className="stats">
        {STATS.map((s) => (
          <div key={s.label} className="stat glass">
            <div className="stat-label">{s.label}</div>
            <div className="stat-value">{s.value}</div>
            <div className={`stat-delta ${s.tone}`}>{s.delta}</div>
          </div>
        ))}
      </div>

      <ScanPanel />
    </div>
  )
}
