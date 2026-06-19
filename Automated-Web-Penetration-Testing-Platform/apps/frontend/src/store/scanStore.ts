import { create } from 'zustand'
import { api, WS_BASE } from '../services/api'
import type { Scan, Vulnerability } from '../types'

interface ScanState {
  activeScan: Scan | null
  scanHistory: Scan[]
  vulnerabilities: Vulnerability[]
  wsConnection: WebSocket | null

  startScan: (targetUrl: string, profile?: string) => Promise<void>
  connectWebSocket: (scanId: string) => void
  disconnectWebSocket: () => void
  fetchHistory: () => Promise<void>
  fetchVulnerabilities: (scanId: string) => Promise<void>
}

export const useScanStore = create<ScanState>((set, get) => ({
  activeScan: null,
  scanHistory: [],
  vulnerabilities: [],
  wsConnection: null,

  startScan: async (targetUrl, profile = 'owasp_top10') => {
    const res = await api.post<Scan>('/scans/', {
      target_url: targetUrl,
      scan_profile: profile,
    })
    set({ activeScan: res.data })
    get().connectWebSocket(res.data.id)
  },

  connectWebSocket: (scanId) => {
    get().disconnectWebSocket()
    const ws = new WebSocket(`${WS_BASE}/ws/scan/${scanId}`)
    ws.onmessage = (event) => {
      try {
        const update = JSON.parse(event.data) as Partial<Scan>
        set((state) => ({
          activeScan: state.activeScan ? { ...state.activeScan, ...update } : null,
        }))
      } catch {
        /* ignore malformed frames */
      }
    }
    ws.onclose = () => set({ wsConnection: null })
    set({ wsConnection: ws })
  },

  disconnectWebSocket: () => {
    const ws = get().wsConnection
    if (ws) ws.close()
    set({ wsConnection: null })
  },

  fetchHistory: async () => {
    const res = await api.get<Scan[]>('/scans/')
    set({ scanHistory: res.data })
  },

  fetchVulnerabilities: async (scanId) => {
    const res = await api.get<Vulnerability[]>(`/scans/${scanId}/vulnerabilities`)
    set({ vulnerabilities: res.data })
  },
}))
