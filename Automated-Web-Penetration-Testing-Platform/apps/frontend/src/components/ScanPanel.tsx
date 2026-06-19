import { useEffect, useRef, useState } from 'react'
import Radar from './Radar'
import type { Severity } from '../types'

interface LiveFinding {
  id: number
  code: string
  sev: Severity
  msg: string
}

const OWASP: { code: string; label: string }[] = [
  { code: 'A01', label: 'Broken Access Control' },
  { code: 'A02', label: 'Cryptographic Failures' },
  { code: 'A03', label: 'Injection' },
  { code: 'A04', label: 'Insecure Design' },
  { code: 'A05', label: 'Security Misconfiguration' },
  { code: 'A06', label: 'Vulnerable Components' },
  { code: 'A07', label: 'Auth & Identification Failures' },
  { code: 'A08', label: 'Software & Data Integrity Failures' },
  { code: 'A09', label: 'Logging & Monitoring Failures' },
  { code: 'A10', label: 'Server-Side Request Forgery' },
]

export default function ScanPanel() {
  const [target, setTarget] = useState('')
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [stage, setStage] = useState(0)
  const [findings, setFindings] = useState<LiveFinding[]>([])
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => () => {
    if (tickRef.current) clearInterval(tickRef.current)
  }, [])

  const startScan = () => {
    if (!target.trim() || scanning) return
    setScanning(true)
    setProgress(0)
    setStage(0)
    setFindings([])

    let p = 0
    let s = 0
    tickRef.current = setInterval(() => {
      p += Math.random() * 1.6 + 0.4
      const newStage = Math.min(OWASP.length - 1, Math.floor((p / 100) * OWASP.length))
      if (newStage !== s) {
        s = newStage
        setStage(s)
        if (Math.random() > 0.4) {
          setFindings((f) => [
            {
              id: Date.now() + Math.random(),
              code: OWASP[s].code,
              sev: pickSeverity(),
              msg: pickFinding(OWASP[s].code),
            },
            ...f,
          ].slice(0, 6))
        }
      }
      if (p >= 100) {
        p = 100
        if (tickRef.current) clearInterval(tickRef.current)
        setScanning(false)
      }
      setProgress(p)
    }, 180)
  }

  const stopScan = () => {
    if (tickRef.current) clearInterval(tickRef.current)
    setScanning(false)
  }

  const current = OWASP[stage]
  const status = scanning
    ? `Scanning ${current.code} — ${current.label}`
    : progress >= 100
      ? 'Scan complete'
      : 'Idle. Enter a target to begin.'

  return (
    <div className="scan-panel">
      <div className="scan-input-row">
        <div className="input-wrap">
          <span className="input-prefix">TARGET</span>
          <input
            className="target-input"
            placeholder="https://example.com  or  192.168.1.10"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={scanning}
            onKeyDown={(e) => e.key === 'Enter' && startScan()}
          />
          <span className={`input-status ${scanning ? 'live' : ''}`} />
        </div>
        {scanning ? (
          <button className="btn btn-danger" onClick={stopScan}>
            Stop Scan
          </button>
        ) : (
          <button className="btn btn-primary" onClick={startScan} disabled={!target.trim()}>
            <PlayIcon /> Run Scan
          </button>
        )}
      </div>

      <div className="scan-body">
        <div className="scan-left glass">
          <div className="scan-meta">
            <div>
              <div className="meta-label">Status</div>
              <div className="meta-value">{status}</div>
            </div>
            <div className="meta-right">
              <div className="meta-label">Progress</div>
              <div className="meta-value meta-mono">{progress.toFixed(1)}%</div>
            </div>
          </div>

          <div className="progress-track">
            <div
              className="progress-fill"
              style={{ width: `${progress}%` }}
            />
            <div className="progress-shine" />
          </div>

          <div className="owasp-list">
            {OWASP.map((o, i) => {
              const state =
                i < stage ? 'done' : i === stage && scanning ? 'active' : 'pending'
              return (
                <div key={o.code} className={`owasp-row ${state}`}>
                  <span className="owasp-code">{o.code}</span>
                  <span className="owasp-label">{o.label}</span>
                  <span className="owasp-dot" />
                </div>
              )
            })}
          </div>
        </div>

        <div className="scan-right glass">
          <Radar active={scanning} />
          <div className="radar-overlay">
            <div className="radar-stage">{current.code}</div>
            <div className="radar-stage-label">{current.label}</div>
          </div>
        </div>
      </div>

      <div className="findings glass">
        <div className="findings-head">
          <h3>Live findings</h3>
          <span className="findings-count">{findings.length}</span>
        </div>
        {findings.length === 0 ? (
          <div className="findings-empty">
            No findings yet. {scanning ? 'Probing…' : 'Run a scan to populate.'}
          </div>
        ) : (
          <ul className="findings-list">
            {findings.map((f) => (
              <li key={f.id} className={`finding sev-${f.sev}`}>
                <span className="finding-sev">{f.sev}</span>
                <span className="finding-code">{f.code}</span>
                <span className="finding-msg">{f.msg}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function PlayIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <polygon points="6 4 20 12 6 20 6 4" />
    </svg>
  )
}

function pickSeverity(): Severity {
  const r = Math.random()
  if (r < 0.08) return 'critical'
  if (r < 0.3) return 'high'
  if (r < 0.6) return 'medium'
  return 'low'
}

function pickFinding(code: string): string {
  const map: Record<string, string[]> = {
    A01: ['IDOR on /api/user/{id}', 'Missing role check on /admin', 'JWT verifies without audience'],
    A02: ['TLS 1.0 enabled', 'Weak cipher suite negotiated', 'Plaintext password storage suspected'],
    A03: ['Reflected XSS on ?q=', 'SQLi candidate on /search', 'Command injection in /ping'],
    A04: ['Missing rate limit on login', 'No CSRF token on state change'],
    A05: ['Server header reveals version', 'Default credentials accepted', 'Verbose error stack leaked'],
    A06: ['jQuery 1.7 (CVE-2020-11023)', 'Outdated OpenSSL banner'],
    A07: ['Username enumeration on /login', 'Session fixation possible'],
    A08: ['Unsigned update endpoint', 'CI artifact path traversal'],
    A09: ['No audit log on auth events', 'Logs ship over HTTP'],
    A10: ['SSRF in /fetch?url=', 'Open redirect on /go'],
  }
  const opts = map[code] || ['Anomaly observed']
  return opts[Math.floor(Math.random() * opts.length)]
}
