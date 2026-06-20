import { create } from 'zustand'
import { api } from '../services/api'
import type { Scan, ScanStatus, Vulnerability } from '../types'

const TERMINAL: ScanStatus[] = ['completed', 'failed', 'cancelled']
const POLL_INTERVAL_MS = 2000

interface ScanState {
  activeScan: Scan | null
  scanHistory: Scan[]
  vulnerabilities: Vulnerability[]
  pollTimer: ReturnType<typeof setInterval> | null

  startScan: (targetUrl: string, profile?: string) => Promise<void>
  fetchScan: (scanId: string) => Promise<void>
  fetchHistory: () => Promise<void>
  fetchVulnerabilities: (scanId: string) => Promise<void>
  startPolling: (scanId: string) => void
  stopPolling: () => void
  cancelScan: (scanId: string) => Promise<void>
}

export const useScanStore = create<ScanState>((set, get) => ({
  activeScan: null,
  scanHistory: [],
  vulnerabilities: [],
  pollTimer: null,

  startScan: async (targetUrl, profile = 'owasp_top10') => {
    const res = await api.post<Scan>('/scans/', {
      target_url: targetUrl,
      scan_profile: profile,
    })
    set({ activeScan: res.data, vulnerabilities: [] })
    get().startPolling(res.data.id)
  },

  fetchScan: async (scanId) => {
    const res = await api.get<Scan>(`/scans/${scanId}`)
    set({ activeScan: res.data })
    if (TERMINAL.includes(res.data.status)) {
      get().stopPolling()
      await get().fetchVulnerabilities(scanId)
    }
  },

  fetchHistory: async () => {
    const res = await api.get<Scan[]>('/scans/')
    set({ scanHistory: res.data })
  },

  fetchVulnerabilities: async (scanId) => {
    const res = await api.get<Vulnerability[]>(`/scans/${scanId}/vulnerabilities`)
    set({ vulnerabilities: res.data })
  },

  startPolling: (scanId) => {
    get().stopPolling()
    const timer = setInterval(() => {
      get().fetchScan(scanId).catch(() => {
        /* network glitch — next tick will retry */
      })
    }, POLL_INTERVAL_MS)
    set({ pollTimer: timer })
  },

  stopPolling: () => {
    const t = get().pollTimer
    if (t) clearInterval(t)
    set({ pollTimer: null })
  },

  cancelScan: async (scanId) => {
    await api.post<Scan>(`/scans/${scanId}/cancel`)
    await get().fetchScan(scanId)
  },
}))
